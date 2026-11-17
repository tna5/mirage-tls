//! Node-API bindings (Node.js and Bun) for mirage-core.

use mirage_core::{Client, ClientOptions, Profile, Request};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::time::Duration;

fn err(e: mirage_core::Error) -> napi::Error {
    let code = match &e {
        mirage_core::Error::Timeout => "ETIMEDOUT",
        mirage_core::Error::Tls(_) => "ETLS",
        mirage_core::Error::Proxy(_) => "EPROXY",
        mirage_core::Error::Profile(_) => "EPROFILE",
        mirage_core::Error::Url(_) => "EURL",
        mirage_core::Error::TooManyRedirects => "EREDIRECT",
        _ => "EREQUEST",
    };
    napi::Error::new(Status::GenericFailure, format!("[{code}] {e}"))
}

fn pairs(v: Option<Vec<Vec<String>>>) -> Vec<(String, String)> {
    v.unwrap_or_default()
        .into_iter()
        .filter_map(|mut p| {
            if p.len() >= 2 {
                let val = p.swap_remove(1);
                Some((p.swap_remove(0), val))
            } else {
                None
            }
        })
        .collect()
}

fn ms(v: Option<u32>, default: Option<Duration>) -> Option<Duration> {
    match v {
        Some(0) => None,
        Some(n) => Some(Duration::from_millis(n as u64)),
        None => default,
    }
}

#[napi(object)]
pub struct SessionOptions {
    /// Built-in profile name, e.g. "chrome_157", "firefox_windows", "safari_ios_26".
    pub browser: Option<String>,
    /// Custom profile as JSON (may contain "extends": "<builtin>").
    pub profile: Option<String>,
    /// http://user:pass@host:port, socks5://..., socks5h://...
    pub proxy: Option<String>,
    pub insecure: Option<bool>,
    /// Extra PEM CA bundle.
    pub ca: Option<String>,
    /// Request timeout in ms (0 = none). Default 30000.
    pub timeout: Option<u32>,
    /// Connect timeout in ms (0 = none). Default 10000.
    pub connect_timeout: Option<u32>,
    /// "follow" (default) | "manual"
    pub redirect: Option<String>,
    pub max_redirects: Option<u32>,
    /// Keep a cookie jar (default true).
    pub cookies: Option<bool>,
    pub http1_only: Option<bool>,
    /// Send the browser's default headers (default true).
    pub default_headers: Option<bool>,
    /// Headers added to every request: [[name, value], ...]
    pub headers: Option<Vec<Vec<String>>>,
}

#[napi(object)]
pub struct NativeRequest {
    pub url: String,
    pub method: Option<String>,
    pub headers: Option<Vec<Vec<String>>>,
    pub body: Option<Buffer>,
    pub timeout: Option<u32>,
    pub redirect: Option<String>,
    pub default_headers: Option<bool>,
}

#[napi(object)]
pub struct NativeResponse {
    pub status: u32,
    pub status_text: String,
    pub version: String,
    pub url: String,
    pub redirected: bool,
    pub headers: Vec<Vec<String>>,
    pub body: Buffer,
}

#[napi]
pub struct NativeSession {
    client: Client,
}

#[napi]
impl NativeSession {
    #[napi(constructor)]
    pub fn new(options: Option<SessionOptions>) -> Result<Self> {
        let o = options.unwrap_or(SessionOptions {
            browser: None,
            profile: None,
            proxy: None,
            insecure: None,
            ca: None,
            timeout: None,
            connect_timeout: None,
            redirect: None,
            max_redirects: None,
            cookies: None,
            http1_only: None,
            default_headers: None,
            headers: None,
        });
        let profile = match (&o.profile, &o.browser) {
            (Some(json), _) => Profile::from_json(json).map_err(err)?,
            (None, Some(name)) => Profile::get(name).map_err(err)?,
            (None, None) => Profile::get("chrome").map_err(err)?,
        };
        let mut opts = ClientOptions::new(profile);
        opts.proxy = o.proxy.filter(|p| !p.is_empty());
        opts.insecure = o.insecure.unwrap_or(false);
        opts.ca_pem = o.ca.map(String::into_bytes);
        opts.timeout = ms(o.timeout, opts.timeout);
        opts.connect_timeout = ms(o.connect_timeout, opts.connect_timeout);
        opts.follow_redirects = o.redirect.as_deref() != Some("manual");
        if let Some(m) = o.max_redirects {
            opts.max_redirects = m;
        }
        opts.cookies = o.cookies.unwrap_or(true);
        opts.http1_only = o.http1_only.unwrap_or(false);
        opts.default_headers = o.default_headers.unwrap_or(true);
        opts.headers = pairs(o.headers);
        Ok(NativeSession { client: Client::new(opts).map_err(err)? })
    }

    #[napi]
    pub async fn request(&self, req: NativeRequest) -> Result<NativeResponse> {
        let client = self.client.clone();
        let request = Request {
            method: req.method.unwrap_or_else(|| "GET".into()),
            url: req.url,
            headers: pairs(req.headers),
            body: req.body.map(|b| b.to_vec()),
            timeout: req.timeout.map(|t| Duration::from_millis(t as u64)),
            follow_redirects: req.redirect.map(|r| r != "manual"),
            default_headers: req.default_headers,
        };
        let res = client.request(request).await.map_err(err)?;
        Ok(NativeResponse {
            status: res.status as u32,
            status_text: res.status_text,
            version: res.version,
            url: res.url,
            redirected: res.redirected,
            headers: res.headers.into_iter().map(|(k, v)| vec![k, v]).collect(),
            body: res.body.into(),
        })
    }

    /// Cookies that would be sent to `url`: [[name, value], ...]
    #[napi]
    pub fn get_cookies(&self, url: String) -> Result<Vec<Vec<String>>> {
        Ok(self
            .client
            .cookies(&url)
            .map_err(err)?
            .into_iter()
            .map(|(k, v)| vec![k, v])
            .collect())
    }

    /// Store a cookie (Set-Cookie syntax) for `url`.
    #[napi]
    pub fn set_cookie(&self, url: String, cookie: String) -> Result<()> {
        self.client.set_cookie(&url, &cookie).map_err(err)
    }

    #[napi]
    pub fn clear_cookies(&self) {
        self.client.clear_cookies();
    }

    /// Resolved profile as JSON.
    #[napi(getter)]
    pub fn profile(&self) -> Result<String> {
        serde_json::to_string(self.client.profile()).map_err(|e| napi::Error::from_reason(e.to_string()))
    }

    /// Close pooled connections.
    #[napi]
    pub fn close(&self) {
        self.client.close();
    }
}

/// Built-in browser families as JSON.
#[napi]
pub fn list_profiles() -> Result<String> {
    serde_json::to_string(&Profile::families()).map_err(|e| napi::Error::from_reason(e.to_string()))
}

/// Resolve a built-in profile name to its full JSON definition.
#[napi]
pub fn resolve_profile(name: String) -> Result<String> {
    let p = Profile::get(&name).map_err(err)?;
    serde_json::to_string_pretty(&p).map_err(|e| napi::Error::from_reason(e.to_string()))
}
