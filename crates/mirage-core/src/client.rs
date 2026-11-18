//! High level client: connection pooling, header ordering, cookies, redirects, decoding.

use crate::body::Body;
use crate::conn::MaybeTls;
use crate::error::{Error, Result};
use crate::h1::{H1Body, H1Conn};
use crate::h2::H2Conn;
use crate::net::{IpFamily, NetOptions};
use crate::profile::Profile;
use crate::proxy::{self, Proxy};
use crate::tls::{TlsConnector, TlsOptions};
use crate::ResponseHead;
use bytes::Bytes;
use cookie_store::{CookieStore, RawCookie};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;
use url::Url;

/// Redirect bodies smaller than this are drained so the connection can be reused.
const MAX_DRAIN: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct ClientOptions {
    pub profile: Profile,
    pub proxy: Option<String>,
    pub insecure: bool,
    pub ca_pem: Option<Vec<u8>>,
    /// Whole request timeout (including redirects).
    pub timeout: Option<Duration>,
    pub connect_timeout: Option<Duration>,
    pub follow_redirects: bool,
    pub max_redirects: u32,
    pub cookies: bool,
    /// Only offer http/1.1 in ALPN.
    pub http1_only: bool,
    /// Send the profile's default browser headers.
    pub default_headers: bool,
    /// Headers added to every request (override profile defaults).
    pub headers: Vec<(String, String)>,
    /// Source address to bind outgoing connections to.
    pub local_address: Option<IpAddr>,
    /// Address family used to reach the target (or the proxy).
    pub ip_family: IpFamily,
    /// Allow TLS session resumption (when the profile does).
    pub tls_resumption: bool,
    /// Allow ECH GREASE (when the profile does). Turning it off changes the fingerprint.
    pub ech_grease: bool,
}

impl ClientOptions {
    pub fn new(profile: Profile) -> Self {
        ClientOptions {
            profile,
            proxy: None,
            insecure: false,
            ca_pem: None,
            timeout: Some(Duration::from_secs(30)),
            connect_timeout: Some(Duration::from_secs(10)),
            follow_redirects: true,
            max_redirects: 20,
            cookies: true,
            http1_only: false,
            default_headers: true,
            headers: Vec::new(),
            local_address: None,
            ip_family: IpFamily::Auto,
            tls_resumption: true,
            ech_grease: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Request {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub timeout: Option<Duration>,
    pub follow_redirects: Option<bool>,
    pub default_headers: Option<bool>,
}

impl Request {
    pub fn get(url: impl Into<String>) -> Self {
        Request { method: "GET".into(), url: url.into(), ..Default::default() }
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub status_text: String,
    pub version: String,
    pub url: String,
    pub redirected: bool,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// A response whose body has not been read yet. The body is decoded
/// (Content-Encoding) while streaming and is subject to the request timeout.
pub struct StreamResponse {
    pub status: u16,
    pub status_text: String,
    pub version: String,
    pub url: String,
    pub redirected: bool,
    pub headers: Vec<(String, String)>,
    pub body: Body,
}

impl StreamResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Read the whole body.
    pub async fn into_response(self) -> Result<Response> {
        let body = self.body.bytes().await?;
        Ok(Response {
            status: self.status,
            status_text: self.status_text,
            version: self.version,
            url: self.url,
            redirected: self.redirected,
            headers: self.headers,
            body,
        })
    }
}

#[derive(Default)]
struct Pool {
    h2: HashMap<String, H2Conn>,
    h1: HashMap<String, Vec<H1Conn<MaybeTls>>>,
    h1_origins: HashSet<String>,
    connect_locks: HashMap<String, Arc<tokio::sync::Mutex<()>>>,
}

struct Inner {
    opts: ClientOptions,
    profile: Arc<Profile>,
    tls: TlsConnector,
    proxy: Option<Proxy>,
    net: NetOptions,
    pool: Mutex<Pool>,
    cookies: Mutex<CookieStore>,
    order: HashMap<String, usize>,
    h1_case: HashMap<String, String>,
}

#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

enum Conn {
    H2(H2Conn),
    H1(H1Conn<MaybeTls>, bool /* reused */),
}

impl Client {
    pub fn new(opts: ClientOptions) -> Result<Client> {
        let profile = Arc::new(opts.profile.clone());
        let tls_opts = TlsOptions {
            insecure: opts.insecure,
            ca_pem: opts.ca_pem.clone(),
            alpn: opts.http1_only.then(|| vec!["http/1.1".to_string()]),
            resumption: opts.tls_resumption,
            ech_grease: opts.ech_grease,
        };
        let tls = TlsConnector::new(profile.clone(), &tls_opts)?;
        let proxy = opts.proxy.as_deref().map(Proxy::parse).transpose()?;
        let net = NetOptions { local_address: opts.local_address, family: opts.ip_family };
        let order = profile
            .header_order()
            .into_iter()
            .enumerate()
            .map(|(i, k)| (k, i))
            .collect();
        let h1_case = profile
            .headers
            .h1_case
            .iter()
            .map(|k| (k.to_ascii_lowercase(), k.clone()))
            .collect();
        Ok(Client {
            inner: Arc::new(Inner {
                opts,
                profile,
                tls,
                proxy,
                net,
                pool: Mutex::new(Pool::default()),
                cookies: Mutex::new(CookieStore::default()),
                order,
                h1_case,
            }),
        })
    }

    pub fn profile(&self) -> &Profile {
        &self.inner.profile
    }

    /// Send a request and buffer the whole (decoded) body.
    pub async fn request(&self, req: Request) -> Result<Response> {
        self.request_stream(req).await?.into_response().await
    }

    /// Send a request; resolves once the final response head arrives. The timeout covers
    /// the whole exchange, body included.
    pub async fn request_stream(&self, req: Request) -> Result<StreamResponse> {
        let deadline = req.timeout.or(self.inner.opts.timeout).map(|t| Instant::now() + t);
        let fut = self.inner.clone().execute(req, deadline);
        match deadline {
            Some(d) => tokio::time::timeout_at(d, fut).await.map_err(|_| Error::Timeout)?,
            None => fut.await,
        }
    }

    pub async fn get(&self, url: &str) -> Result<Response> {
        self.request(Request::get(url)).await
    }

    /// Cookies that would be sent to `url`.
    pub fn cookies(&self, url: &str) -> Result<Vec<(String, String)>> {
        let url = parse_url(url)?;
        let jar = self.inner.cookies.lock().unwrap();
        Ok(jar
            .get_request_values(&url)
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect())
    }

    /// Store a cookie as if `url` had sent `Set-Cookie: <cookie>`.
    pub fn set_cookie(&self, url: &str, cookie: &str) -> Result<()> {
        let url = parse_url(url)?;
        let raw = RawCookie::parse(cookie.to_string())
            .map_err(|e| Error::Http(format!("invalid cookie: {e}")))?;
        self.inner
            .cookies
            .lock()
            .unwrap()
            .store_response_cookies(std::iter::once(raw), &url);
        Ok(())
    }

    pub fn clear_cookies(&self) {
        self.inner.cookies.lock().unwrap().clear();
    }

    /// Drop every pooled connection.
    pub fn close(&self) {
        let mut pool = self.inner.pool.lock().unwrap();
        pool.h2.clear();
        pool.h1.clear();
    }
}

fn parse_url(s: &str) -> Result<Url> {
    let url = Url::parse(s).map_err(|e| Error::Url(format!("{s}: {e}")))?;
    match url.scheme() {
        "http" | "https" => Ok(url),
        other => Err(Error::Url(format!("unsupported scheme '{other}'"))),
    }
}

/// Read (and discard) a small redirect body so a keep-alive connection goes back to the
/// pool; larger ones are dropped, which closes / cancels the stream.
async fn drain(mut body: Body) {
    let mut n = 0;
    while let Ok(Some(c)) = body.chunk().await {
        n += c.len();
        if n > MAX_DRAIN {
            break;
        }
    }
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme() && a.host_str() == b.host_str() && a.port_or_known_default() == b.port_or_known_default()
}

impl Inner {
    async fn execute(self: Arc<Self>, req: Request, deadline: Option<Instant>) -> Result<StreamResponse> {
        let mut url = parse_url(&req.url)?;
        let mut method = req.method.to_ascii_uppercase();
        if method.is_empty() {
            method = "GET".into();
        }
        let mut body = req.body.unwrap_or_default();
        let mut headers = req.headers;
        let follow = req.follow_redirects.unwrap_or(self.opts.follow_redirects);
        let defaults = req.default_headers.unwrap_or(self.opts.default_headers);
        let mut redirected = false;

        for _ in 0..=self.opts.max_redirects {
            let logical = self.logical_headers(&url, &method, &headers, &body, defaults);
            let (head, raw_body) = self.send(&method, &url, logical, Bytes::from(body.clone())).await?;

            if self.opts.cookies {
                let set: Vec<RawCookie<'static>> = head
                    .headers
                    .iter()
                    .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
                    .filter_map(|(_, v)| RawCookie::parse(v.clone()).ok())
                    .collect();
                if !set.is_empty() {
                    self.cookies.lock().unwrap().store_response_cookies(set.into_iter(), &url);
                }
            }

            let location = head
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                .map(|(_, v)| v.clone());
            if follow && is_redirect(head.status) {
                if let Some(loc) = location {
                    drain(raw_body).await;
                    let next = url
                        .join(&loc)
                        .map_err(|e| Error::Url(format!("bad redirect location '{loc}': {e}")))?;
                    if !matches!(next.scheme(), "http" | "https") {
                        return Err(Error::Url(format!("redirect to unsupported scheme: {next}")));
                    }
                    if head.status == 303 && method != "HEAD"
                        || matches!(head.status, 301 | 302) && method == "POST"
                    {
                        method = "GET".into();
                        body.clear();
                        headers.retain(|(k, _)| {
                            !matches!(
                                k.to_ascii_lowercase().as_str(),
                                "content-type" | "content-length" | "content-encoding" | "content-language" | "content-location"
                            )
                        });
                    }
                    if !same_origin(&url, &next) {
                        headers.retain(|(k, _)| {
                            !matches!(k.to_ascii_lowercase().as_str(), "authorization" | "cookie" | "proxy-authorization")
                        });
                    }
                    url = next;
                    redirected = true;
                    continue;
                }
            }

            let encoding = head
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
                .map(|(_, v)| v.clone());
            let mut body = raw_body.with_deadline(deadline);
            if let Some(enc) = encoding.filter(|_| method != "HEAD") {
                body = body.decode(&enc);
            }
            return Ok(StreamResponse {
                status: head.status,
                status_text: head.reason,
                version: head.version,
                url: url.to_string(),
                redirected,
                headers: head.headers,
                body,
            });
        }
        Err(Error::TooManyRedirects)
    }

    /// Profile defaults + session headers + request headers + cookies + content-length.
    fn logical_headers(
        &self,
        url: &Url,
        method: &str,
        user: &[(String, String)],
        body: &[u8],
        defaults: bool,
    ) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = if defaults {
            self.profile.headers.default.clone()
        } else {
            Vec::new()
        };
        let set = |k: &str, v: &str, out: &mut Vec<(String, String)>| {
            if let Some(slot) = out.iter_mut().find(|(n, _)| n.eq_ignore_ascii_case(k)) {
                slot.1 = v.to_string();
            } else {
                out.push((k.to_string(), v.to_string()));
            }
        };
        for (k, v) in self.opts.headers.iter().chain(user.iter()) {
            if k.eq_ignore_ascii_case("cookie") {
                continue;
            }
            set(k, v, &mut out);
        }

        let mut cookie_parts: Vec<String> = Vec::new();
        if self.opts.cookies {
            let jar = self.cookies.lock().unwrap();
            cookie_parts.extend(jar.get_request_values(url).map(|(k, v)| format!("{k}={v}")));
        }
        for (k, v) in self.opts.headers.iter().chain(user.iter()) {
            if k.eq_ignore_ascii_case("cookie") && !v.is_empty() {
                cookie_parts.push(v.clone());
            }
        }
        if !cookie_parts.is_empty() {
            set("cookie", &cookie_parts.join("; "), &mut out);
        }

        out.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length"));
        if !body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH") {
            out.push(("content-length".into(), body.len().to_string()));
        }
        out
    }

    fn order_headers(&self, mut headers: Vec<(String, String)>) -> Vec<(String, String)> {
        let n = self.order.len();
        let mut keyed: Vec<(usize, (String, String))> = headers
            .drain(..)
            .enumerate()
            .map(|(i, h)| {
                let rank = self.order.get(&h.0.to_ascii_lowercase()).copied().unwrap_or(n + i);
                (rank, h)
            })
            .collect();
        keyed.sort_by_key(|(r, _)| *r);
        keyed.into_iter().map(|(_, h)| h).collect()
    }

    fn h1_name(&self, name: &str) -> String {
        let lower = name.to_ascii_lowercase();
        if let Some(c) = self.h1_case.get(&lower) {
            return c.clone();
        }
        match lower.as_str() {
            "host" => "Host".into(),
            "connection" => "Connection".into(),
            "content-length" => "Content-Length".into(),
            "cookie" => "Cookie".into(),
            _ => name.to_string(),
        }
    }

    async fn send(
        self: &Arc<Self>,
        method: &str,
        url: &Url,
        headers: Vec<(String, String)>,
        body: Bytes,
    ) -> Result<(ResponseHead, Body)> {
        let https = url.scheme() == "https";
        let host = url
            .host_str()
            .ok_or_else(|| Error::Url("url has no host".into()))?
            .trim_matches(|c| c == '[' || c == ']')
            .to_string();
        let port = url.port_or_known_default().unwrap_or(if https { 443 } else { 80 });
        let key = format!("{}://{}:{}", url.scheme(), host, port);
        let authority = match url.port() {
            Some(p) if host.contains(':') => format!("[{host}]:{p}"),
            Some(p) => format!("{host}:{p}"),
            None if host.contains(':') => format!("[{host}]"),
            None => host.clone(),
        };
        let path = match url.query() {
            Some(q) => format!("{}?{}", url.path(), q),
            None => url.path().to_string(),
        };

        for attempt in 0..2 {
            let can_retry = attempt == 0;
            let conn = self.checkout(&key, &host, port, https).await?;
            match conn {
                Conn::H2(c) => {
                    let ordered = self.order_headers(headers.clone());
                    match c
                        .request(method, url.scheme(), &authority, &path, &ordered, body.clone())
                        .await
                    {
                        Ok((head, b)) => return Ok((head, Body::h2(b))),
                        // REFUSED_STREAM / GOAWAY: the server did not process it.
                        Err(Error::Refused(_)) if can_retry => continue,
                        Err(e) => return Err(e),
                    }
                }
                Conn::H1(mut c, reused) => {
                    let mut h = headers.clone();
                    if !h.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
                        h.push(("host".into(), authority.clone()));
                    }
                    if !h.iter().any(|(k, _)| k.eq_ignore_ascii_case("connection")) {
                        h.push(("connection".into(), "keep-alive".into()));
                    }
                    // HTTP/2-only headers are not sent by browsers on HTTP/1.1.
                    h.retain(|(k, _)| !k.eq_ignore_ascii_case("te") || self.profile.meta.family == "firefox");
                    let ordered: Vec<(String, String)> = self
                        .order_headers(h)
                        .into_iter()
                        .map(|(k, v)| (self.h1_name(&k), v))
                        .collect();
                    match c.send(method, &path, &ordered, &body).await {
                        Ok((head, framing, keep)) => {
                            // Back to the pool once the body has been fully read.
                            let inner = Arc::downgrade(self);
                            let pool_key = key.clone();
                            let on_done = Box::new(move |c: H1Conn<MaybeTls>| {
                                if let Some(inner) = inner.upgrade() {
                                    inner.pool.lock().unwrap().h1.entry(pool_key).or_default().push(c);
                                }
                            });
                            return Ok((head, Body::h1(H1Body::new(c, framing, keep, on_done))));
                        }
                        // A pooled keep-alive connection may have been closed by the server.
                        Err(_) if reused && can_retry => continue,
                        Err(e) => return Err(e),
                    }
                }
            }
        }
        Err(Error::Http("request failed".into()))
    }

    async fn checkout(&self, key: &str, host: &str, port: u16, https: bool) -> Result<Conn> {
        let lock = {
            let mut pool = self.pool.lock().unwrap();
            if let Some(c) = pool.h2.get(key) {
                if !c.is_closed() {
                    return Ok(Conn::H2(c.clone()));
                }
                pool.h2.remove(key);
            }
            if let Some(c) = pool.h1.get_mut(key).and_then(|v| v.pop()) {
                return Ok(Conn::H1(c, true));
            }
            if pool.h1_origins.contains(key) {
                None
            } else {
                Some(pool.connect_locks.entry(key.to_string()).or_default().clone())
            }
        };
        // Serialize the first connection to an origin so concurrent requests share one h2 conn.
        let _guard = match &lock {
            Some(l) => Some(l.lock().await),
            None => None,
        };
        if lock.is_some() {
            let pool = self.pool.lock().unwrap();
            if let Some(c) = pool.h2.get(key) {
                if !c.is_closed() {
                    return Ok(Conn::H2(c.clone()));
                }
            }
        }

        let connect = self.connect(host, port, https);
        let stream = match self.opts.connect_timeout {
            Some(t) => tokio::time::timeout(t, connect).await.map_err(|_| Error::Timeout)??,
            None => connect.await?,
        };
        if stream.alpn().as_deref() == Some(b"h2") {
            let c = H2Conn::handshake(stream, &self.profile.http2).await?;
            self.pool.lock().unwrap().h2.insert(key.to_string(), c.clone());
            Ok(Conn::H2(c))
        } else {
            self.pool.lock().unwrap().h1_origins.insert(key.to_string());
            Ok(Conn::H1(H1Conn::new(stream), false))
        }
    }

    async fn connect(&self, host: &str, port: u16, https: bool) -> Result<MaybeTls> {
        let ua = self
            .profile
            .headers
            .default
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
            .map(|(_, v)| v.as_str());
        let tcp = proxy::connect(self.proxy.as_ref(), host, port, ua, &self.net).await?;
        if !https {
            return Ok(MaybeTls::Plain(tcp));
        }
        let tls = self.tls.connect(host, port, tcp).await?;
        Ok(MaybeTls::Tls(Box::new(tls)))
    }
}
