//! HTTP/1.1 client: headers are written exactly in the given order and casing.

use crate::error::{Error, Result};
use crate::RawResponse;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_HEAD: usize = 256 * 1024;

pub struct H1Conn<S> {
    io: S,
    buf: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> H1Conn<S> {
    pub fn new(io: S) -> Self {
        H1Conn { io, buf: Vec::new() }
    }

    /// Send one request; returns the response and whether the connection can be reused.
    pub async fn request(
        &mut self,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(RawResponse, bool)> {
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
            let (status, reason, version, resp_headers, head_len) = self.read_head().await?;
            self.buf.drain(..head_len);
            if (100..200).contains(&status) && status != 101 {
                continue;
            }
            let header = |name: &str| {
                resp_headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v.as_str())
            };
            let conn_hdr = header("connection").map(|v| v.to_ascii_lowercase());
            let mut keep_alive = match version.as_str() {
                "HTTP/1.0" => conn_hdr.as_deref().map(|v| v.contains("keep-alive")).unwrap_or(false),
                _ => !conn_hdr.as_deref().map(|v| v.contains("close")).unwrap_or(false),
            };
            let no_body = method == "HEAD" || status == 204 || status == 304;
            let chunked = header("transfer-encoding")
                .map(|v| v.to_ascii_lowercase().contains("chunked"))
                .unwrap_or(false);
            let body = if no_body {
                Vec::new()
            } else if chunked {
                self.read_chunked().await?
            } else if let Some(len) = header("content-length") {
                let len: usize = len
                    .trim()
                    .parse()
                    .map_err(|_| Error::Http("invalid content-length".into()))?;
                self.read_exact_body(len).await?
            } else {
                keep_alive = false;
                self.read_to_end().await?
            };
            return Ok((
                RawResponse { status, reason, version, headers: resp_headers, body },
                keep_alive,
            ));
        }
    }

    async fn fill(&mut self) -> Result<usize> {
        let mut tmp = [0u8; 16 * 1024];
        let n = self.io.read(&mut tmp).await?;
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(n)
    }

    async fn read_head(&mut self) -> Result<(u16, String, String, Vec<(String, String)>, usize)> {
        loop {
            if let Some(pos) = find(&self.buf, b"\r\n\r\n") {
                let mut hdrs = [httparse::EMPTY_HEADER; 128];
                let mut resp = httparse::Response::new(&mut hdrs);
                let head_len = pos + 4;
                match resp.parse(&self.buf[..head_len]) {
                    Ok(httparse::Status::Complete(_)) => {}
                    Ok(httparse::Status::Partial) => return Err(Error::Http("truncated response head".into())),
                    Err(e) => return Err(Error::Http(format!("invalid response: {e}"))),
                }
                let status = resp.code.unwrap_or(0);
                let reason = resp.reason.unwrap_or("").to_string();
                let version = if resp.version == Some(0) { "HTTP/1.0" } else { "HTTP/1.1" }.to_string();
                let headers = resp
                    .headers
                    .iter()
                    .map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).into_owned()))
                    .collect();
                return Ok((status, reason, version, headers, head_len));
            }
            if self.buf.len() > MAX_HEAD {
                return Err(Error::Http("response head too large".into()));
            }
            if self.fill().await? == 0 {
                return Err(Error::Http("connection closed before response".into()));
            }
        }
    }

    async fn read_exact_body(&mut self, len: usize) -> Result<Vec<u8>> {
        while self.buf.len() < len {
            if self.fill().await? == 0 {
                return Err(Error::Http("connection closed mid-body".into()));
            }
        }
        Ok(self.buf.drain(..len).collect())
    }

    async fn read_line(&mut self) -> Result<String> {
        loop {
            if let Some(pos) = find(&self.buf, b"\r\n") {
                let line = String::from_utf8_lossy(&self.buf[..pos]).into_owned();
                self.buf.drain(..pos + 2);
                return Ok(line);
            }
            if self.fill().await? == 0 {
                return Err(Error::Http("connection closed in chunked body".into()));
            }
        }
    }

    async fn read_chunked(&mut self) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        loop {
            let line = self.read_line().await?;
            let size = line.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size, 16)
                .map_err(|_| Error::Http(format!("invalid chunk size '{size}'")))?;
            if size == 0 {
                // trailers
                loop {
                    if self.read_line().await?.is_empty() {
                        return Ok(body);
                    }
                }
            }
            body.extend(self.read_exact_body(size).await?);
            self.read_exact_body(2).await?;
        }
    }

    async fn read_to_end(&mut self) -> Result<Vec<u8>> {
        loop {
            match self.fill().await {
                Ok(0) => break,
                Ok(_) => {}
                // Many servers close TLS without close_notify.
                Err(_) if !self.buf.is_empty() => break,
                Err(e) => return Err(e),
            }
        }
        Ok(std::mem::take(&mut self.buf))
    }
}

pub(crate) fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
