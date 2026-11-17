//! TCP connection establishment, directly or through an HTTP (CONNECT) / SOCKS5 proxy.

use crate::error::{Error, Result};
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone, PartialEq)]
pub enum ProxyKind {
    Http,
    /// `remote_dns`: socks5h:// lets the proxy resolve the host name.
    Socks5 { remote_dns: bool },
}

#[derive(Debug, Clone)]
pub struct Proxy {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub auth: Option<(String, String)>,
}

impl Proxy {
    pub fn parse(s: &str) -> Result<Proxy> {
        let url = url::Url::parse(s).map_err(|e| Error::Proxy(format!("invalid proxy url: {e}")))?;
        let kind = match url.scheme() {
            "http" => ProxyKind::Http,
            "socks5" => ProxyKind::Socks5 { remote_dns: false },
            "socks5h" | "socks" => ProxyKind::Socks5 { remote_dns: true },
            other => return Err(Error::Proxy(format!("unsupported proxy scheme '{other}'"))),
        };
        let host = url
            .host_str()
            .ok_or_else(|| Error::Proxy("proxy url has no host".into()))?
            .trim_matches(|c| c == '[' || c == ']')
            .to_string();
        let port = url.port().unwrap_or(match kind {
            ProxyKind::Http => 8080,
            _ => 1080,
        });
        let auth = if url.username().is_empty() {
            None
        } else {
            let dec = |s: &str| {
                percent_decode(s)
            };
            Some((dec(url.username()), dec(url.password().unwrap_or(""))))
        };
        Ok(Proxy { kind, host, port, auth })
    }
}

fn percent_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("x={s}").as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| s.to_string())
}

/// Open a TCP stream to `host:port`, tunnelled through `proxy` if set.
pub async fn connect(proxy: Option<&Proxy>, host: &str, port: u16, user_agent: Option<&str>) -> Result<TcpStream> {
    let Some(p) = proxy else {
        let s = TcpStream::connect((host, port)).await?;
        s.set_nodelay(true)?;
        return Ok(s);
    };
    let mut s = TcpStream::connect((p.host.as_str(), p.port))
        .await
        .map_err(|e| Error::Proxy(format!("cannot reach proxy {}:{}: {e}", p.host, p.port)))?;
    s.set_nodelay(true)?;
    match p.kind {
        ProxyKind::Http => http_connect(&mut s, p, host, port, user_agent).await?,
        ProxyKind::Socks5 { remote_dns } => socks5(&mut s, p, host, port, remote_dns).await?,
    }
    Ok(s)
}

fn authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

async fn http_connect(s: &mut TcpStream, p: &Proxy, host: &str, port: u16, ua: Option<&str>) -> Result<()> {
    let target = authority(host, port);
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: keep-alive\r\n");
    if let Some(ua) = ua {
        req.push_str(&format!("User-Agent: {ua}\r\n"));
    }
    if let Some((u, pw)) = &p.auth {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{pw}"));
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;

    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            return Err(Error::Proxy("proxy closed the connection during CONNECT".into()));
        }
        buf.extend_from_slice(&tmp[..n]);
        if crate::h1::find(&buf, b"\r\n\r\n").is_some() {
            break;
        }
        if buf.len() > 64 * 1024 {
            return Err(Error::Proxy("proxy response too large".into()));
        }
    }
    let line = String::from_utf8_lossy(&buf);
    let status = line.split_whitespace().nth(1).unwrap_or("");
    if status != "200" {
        let first = line.lines().next().unwrap_or("").to_string();
        return Err(Error::Proxy(format!("CONNECT refused: {first}")));
    }
    Ok(())
}

async fn socks5(s: &mut TcpStream, p: &Proxy, host: &str, port: u16, remote_dns: bool) -> Result<()> {
    let methods: &[u8] = if p.auth.is_some() { &[0x00, 0x02] } else { &[0x00] };
    let mut hello = vec![0x05, methods.len() as u8];
    hello.extend_from_slice(methods);
    s.write_all(&hello).await?;
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await?;
    if resp[0] != 0x05 {
        return Err(Error::Proxy("not a SOCKS5 proxy".into()));
    }
    match resp[1] {
        0x00 => {}
        0x02 => {
            let (u, pw) = p.auth.as_ref().ok_or_else(|| Error::Proxy("SOCKS5 proxy requires auth".into()))?;
            let mut a = vec![0x01, u.len() as u8];
            a.extend_from_slice(u.as_bytes());
            a.push(pw.len() as u8);
            a.extend_from_slice(pw.as_bytes());
            s.write_all(&a).await?;
            let mut r = [0u8; 2];
            s.read_exact(&mut r).await?;
            if r[1] != 0x00 {
                return Err(Error::Proxy("SOCKS5 authentication failed".into()));
            }
        }
        _ => return Err(Error::Proxy("SOCKS5 proxy: no acceptable auth method".into())),
    }

    let mut req = vec![0x05, 0x01, 0x00];
    let ip = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => Some(ip),
        Err(_) if !remote_dns => tokio::net::lookup_host((host, port))
            .await?
            .next()
            .map(|a| a.ip()),
        Err(_) => None,
    };
    match ip {
        Some(std::net::IpAddr::V4(v4)) => {
            req.push(0x01);
            req.extend_from_slice(&v4.octets());
        }
        Some(std::net::IpAddr::V6(v6)) => {
            req.push(0x04);
            req.extend_from_slice(&v6.octets());
        }
        None => {
            req.push(0x03);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;

    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        let why = match head[1] {
            0x01 => "general failure",
            0x02 => "not allowed by ruleset",
            0x03 => "network unreachable",
            0x04 => "host unreachable",
            0x05 => "connection refused",
            0x06 => "TTL expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "unknown error",
        };
        return Err(Error::Proxy(format!("SOCKS5 connect failed: {why}")));
    }
    let skip = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize
        }
        _ => return Err(Error::Proxy("SOCKS5: bad reply".into())),
    };
    let mut rest = vec![0u8; skip + 2];
    s.read_exact(&mut rest).await?;
    Ok(())
}
