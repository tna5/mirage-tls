//! HTTP/1.1 client: headers are written exactly in the given order and casing.
//! Response bodies are read incrementally (content-length, chunked or until close).

use crate::conn::MaybeTls;
use crate::error::{Error, Result};
use crate::ResponseHead;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_HEAD: usize = 256 * 1024;
const READ_CHUNK: usize = 64 * 1024;

pub struct H1Conn<S> {
    io: S,
    buf: BytesMut,
}

/// How the response body is delimited.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Framing {
    None,
    Length(u64),
    Chunked { remaining: u64, crlf: bool, done: bool },
    Close,
}

impl<S: AsyncRead + AsyncWrite + Unpin> H1Conn<S> {
    pub fn new(io: S) -> Self {
        H1Conn { io, buf: BytesMut::new() }
    }

    /// Send one request and read the response head. Returns the head, the body framing and
    /// whether the connection can be reused once the body has been read.
    pub async fn send(
        &mut self,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(ResponseHead, Framing, bool)> {
        let mut out = Vec::with_capacity(512 + body.len());
        out.extend_from_slice(method.as_bytes());
        out.push(b' ');
        out.extend_from_slice(target.as_bytes());
        out.extend_from_slice(b" HTTP/1.1\r\n");
        for (k, v) in headers {
            out.extend_from_slice(k.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(v.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(body);
        self.io.write_all(&out).await?;
        self.io.flush().await?;

        loop {
            let head = self.read_head().await?;
            let status = head.status;
            if (100..200).contains(&status) && status != 101 {
                continue;
            }
            let header = |name: &str| {
                head.headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v.as_str())
            };
            let conn_hdr = header("connection").map(|v| v.to_ascii_lowercase());
            let mut keep_alive = match head.version.as_str() {
                "HTTP/1.0" => conn_hdr.as_deref().map(|v| v.contains("keep-alive")).unwrap_or(false),
                _ => !conn_hdr.as_deref().map(|v| v.contains("close")).unwrap_or(false),
            };
            let no_body = method == "HEAD" || status == 204 || status == 304;
            let chunked = header("transfer-encoding")
                .map(|v| v.to_ascii_lowercase().contains("chunked"))
                .unwrap_or(false);
            let framing = if no_body {
                Framing::None
            } else if chunked {
                Framing::Chunked { remaining: 0, crlf: false, done: false }
            } else if let Some(len) = header("content-length") {
                let len: u64 = len
                    .trim()
                    .parse()
                    .map_err(|_| Error::Http("invalid content-length".into()))?;
                Framing::Length(len)
            } else {
                keep_alive = false;
                Framing::Close
            };
            return Ok((head, framing, keep_alive));
        }
    }

    /// Send a request and buffer the whole response body.
    pub async fn request(
        &mut self,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(ResponseHead, Vec<u8>, bool)> {
        let (head, mut framing, keep) = self.send(method, target, headers, body).await?;
        let mut out = Vec::new();
        while let Some(c) = self.read_body(&mut framing).await? {
            out.extend_from_slice(&c);
        }
        Ok((head, out, keep))
    }

    /// Next piece of the body, `None` once it is complete.
    pub async fn read_body(&mut self, framing: &mut Framing) -> Result<Option<Bytes>> {
        match framing {
            Framing::None => Ok(None),
            Framing::Length(0) => Ok(None),
            Framing::Length(rem) => {
                if self.buf.is_empty() && self.fill().await? == 0 {
                    return Err(Error::Http("connection closed mid-body".into()));
                }
                let n = (*rem).min(self.buf.len() as u64) as usize;
                *rem -= n as u64;
                Ok(Some(self.buf.split_to(n).freeze()))
            }
            Framing::Chunked { remaining, crlf, done } => {
                if *done {
                    return Ok(None);
                }
                if *remaining == 0 {
                    if *crlf {
                        if !self.read_line().await?.is_empty() {
                            return Err(Error::Http("invalid chunk terminator".into()));
                        }
                        *crlf = false;
                    }
                    let line = self.read_line().await?;
                    let size = line.split(';').next().unwrap_or("").trim();
                    let size = u64::from_str_radix(size, 16)
                        .map_err(|_| Error::Http(format!("invalid chunk size '{size}'")))?;
                    if size == 0 {
                        while !self.read_line().await?.is_empty() {} // trailers
                        *done = true;
                        return Ok(None);
                    }
                    *remaining = size;
                    *crlf = true;
                }
                if self.buf.is_empty() && self.fill().await? == 0 {
                    return Err(Error::Http("connection closed in chunked body".into()));
                }
                let n = (*remaining).min(self.buf.len() as u64) as usize;
                *remaining -= n as u64;
                Ok(Some(self.buf.split_to(n).freeze()))
            }
            Framing::Close => {
                if !self.buf.is_empty() {
                    return Ok(Some(self.buf.split().freeze()));
                }
                match self.fill().await {
                    Ok(0) => {
                        *framing = Framing::None;
                        Ok(None)
                    }
                    Ok(_) => Ok(Some(self.buf.split().freeze())),
                    // Many servers close TLS without close_notify.
                    Err(_) => {
                        *framing = Framing::None;
                        Ok(None)
                    }
                }
            }
        }
    }

    async fn fill(&mut self) -> Result<usize> {
        self.buf.reserve(READ_CHUNK);
        Ok(self.io.read_buf(&mut self.buf).await?)
    }

    async fn read_head(&mut self) -> Result<ResponseHead> {
        loop {
            if let Some(pos) = find(&self.buf, b"\r\n\r\n") {
                let head_len = pos + 4;
                let head = {
                    let mut hdrs = [httparse::EMPTY_HEADER; 128];
                    let mut resp = httparse::Response::new(&mut hdrs);
                    match resp.parse(&self.buf[..head_len]) {
                        Ok(httparse::Status::Complete(_)) => {}
                        Ok(httparse::Status::Partial) => return Err(Error::Http("truncated response head".into())),
                        Err(e) => return Err(Error::Http(format!("invalid response: {e}"))),
                    }
                    ResponseHead {
                        status: resp.code.unwrap_or(0),
                        reason: resp.reason.unwrap_or("").to_string(),
                        version: if resp.version == Some(0) { "HTTP/1.0" } else { "HTTP/1.1" }.to_string(),
                        headers: resp
                            .headers
                            .iter()
                            .map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).into_owned()))
                            .collect(),
                    }
                };
                let _ = self.buf.split_to(head_len);
                return Ok(head);
            }
            if self.buf.len() > MAX_HEAD {
                return Err(Error::Http("response head too large".into()));
            }
            if self.fill().await? == 0 {
                return Err(Error::Http("connection closed before response".into()));
            }
        }
    }

    async fn read_line(&mut self) -> Result<String> {
        loop {
            if let Some(pos) = find(&self.buf, b"\r\n") {
                let line = String::from_utf8_lossy(&self.buf[..pos]).into_owned();
                let _ = self.buf.split_to(pos + 2);
                return Ok(line);
            }
            if self.buf.len() > MAX_HEAD {
                return Err(Error::Http("chunk header too large".into()));
            }
            if self.fill().await? == 0 {
                return Err(Error::Http("connection closed in chunked body".into()));
            }
        }
    }
}

type ReturnFn = Box<dyn FnOnce(H1Conn<MaybeTls>) + Send + Sync>;

/// Streaming HTTP/1.1 body. Once fully read, a keep-alive connection is handed to
/// `on_done` (the pool); dropping it earlier closes the connection.
pub struct H1Body {
    conn: Option<H1Conn<MaybeTls>>,
    framing: Framing,
    keep_alive: bool,
    on_done: Option<ReturnFn>,
}

impl H1Body {
    pub(crate) fn new(conn: H1Conn<MaybeTls>, framing: Framing, keep_alive: bool, on_done: ReturnFn) -> H1Body {
        H1Body { conn: Some(conn), framing, keep_alive, on_done: Some(on_done) }
    }

    pub async fn chunk(&mut self) -> Result<Option<Bytes>> {
        let Some(conn) = self.conn.as_mut() else { return Ok(None) };
        loop {
            match conn.read_body(&mut self.framing).await {
                Ok(Some(b)) if b.is_empty() => continue,
                Ok(Some(b)) => return Ok(Some(b)),
                Ok(None) => {
                    let conn = self.conn.take();
                    if let (true, Some(c), Some(f)) = (self.keep_alive, conn, self.on_done.take()) {
                        f(c);
                    }
                    return Ok(None);
                }
                Err(e) => {
                    self.conn = None;
                    return Err(e);
                }
            }
        }
    }
}

pub(crate) fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    async fn roundtrip(response: &'static [u8], method: &str) -> (ResponseHead, Vec<u8>, bool) {
        let (client, mut server) = duplex(1 << 16);
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let _ = server.read(&mut buf).await;
            // Write in small pieces to exercise incremental parsing.
            for c in response.chunks(3) {
                server.write_all(c).await.unwrap();
            }
        });
        let mut c = H1Conn::new(client);
        c.request(method, "/", &[("Host".into(), "x".into())], b"").await.unwrap()
    }

    #[tokio::test]
    async fn framings() {
        let (h, b, keep) =
            roundtrip(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", "GET").await;
        assert_eq!((h.status, b.as_slice(), keep), (200, &b"hello"[..], true));

        let (_, b, keep) = roundtrip(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;x=1\r\nhello\r\n6\r\n world\r\n0\r\nX-T: 1\r\n\r\n",
            "GET",
        )
        .await;
        assert_eq!((b.as_slice(), keep), (&b"hello world"[..], true));

        let (_, b, keep) = roundtrip(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nuntil close", "GET").await;
        assert_eq!((b.as_slice(), keep), (&b"until close"[..], false));

        let (_, b, _) = roundtrip(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", "HEAD").await;
        assert!(b.is_empty());
    }
}
