//! Response bodies: a pull-based stream of chunks with optional streaming
//! Content-Encoding decoding (gzip, deflate, br, zstd).

use crate::error::{Error, Result};
use crate::h1::H1Body;
use crate::h2::H2Body;
use bytes::Bytes;
use std::io::Write;
use tokio::time::Instant;

/// A response body. Reading happens on demand: for HTTP/2 the stream window is only
/// re-opened (WINDOW_UPDATE) as chunks are consumed, so a slow reader applies backpressure.
/// Dropping an unfinished body cancels the request (RST_STREAM CANCEL on HTTP/2, the
/// connection is closed on HTTP/1.1).
pub struct Body {
    src: Source,
    decoder: Option<StreamDecoder>,
    deadline: Option<Instant>,
    done: bool,
}

enum Source {
    Empty,
    Full(Bytes),
    H1(H1Body),
    H2(H2Body),
}

impl Body {
    pub fn empty() -> Body {
        Body { src: Source::Empty, decoder: None, deadline: None, done: true }
    }

    pub fn from_bytes(b: impl Into<Bytes>) -> Body {
        Body { src: Source::Full(b.into()), decoder: None, deadline: None, done: false }
    }

    pub(crate) fn h1(b: H1Body) -> Body {
        Body { src: Source::H1(b), decoder: None, deadline: None, done: false }
    }

    pub(crate) fn h2(b: H2Body) -> Body {
        Body { src: Source::H2(b), decoder: None, deadline: None, done: false }
    }

    /// Decode the given Content-Encoding while streaming (unknown encodings pass through).
    pub(crate) fn decode(mut self, encoding: &str) -> Body {
        self.decoder = StreamDecoder::new(encoding);
        self
    }

    pub(crate) fn with_deadline(mut self, deadline: Option<Instant>) -> Body {
        self.deadline = deadline;
        self
    }

    pub fn is_end(&self) -> bool {
        self.done
    }

    /// Next chunk of (decoded) body, `None` at the end.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>> {
        loop {
            if self.done {
                return Ok(None);
            }
            let raw = match self.deadline {
                Some(d) => match tokio::time::timeout_at(d, self.raw_chunk()).await {
                    Ok(r) => r,
                    Err(_) => Err(Error::Timeout),
                },
                None => self.raw_chunk().await,
            };
            let raw = match raw {
                Ok(r) => r,
                Err(e) => {
                    self.done = true;
                    self.src = Source::Empty;
                    return Err(e);
                }
            };
            match raw {
                Some(b) => match &mut self.decoder {
                    Some(d) => {
                        let out = d.feed(&b)?;
                        if !out.is_empty() {
                            return Ok(Some(out.into()));
                        }
                    }
                    None => return Ok(Some(b)),
                },
                None => {
                    self.done = true;
                    if let Some(d) = &mut self.decoder {
                        let out = d.finish()?;
                        if !out.is_empty() {
                            return Ok(Some(out.into()));
                        }
                    }
                    return Ok(None);
                }
            }
        }
    }

    /// Read the whole body.
    pub async fn bytes(mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(c) = self.chunk().await? {
            out.extend_from_slice(&c);
        }
        Ok(out)
    }

    async fn raw_chunk(&mut self) -> Result<Option<Bytes>> {
        match &mut self.src {
            Source::Empty => Ok(None),
            Source::Full(b) => {
                let b = std::mem::take(b);
                self.src = Source::Empty;
                Ok(if b.is_empty() { None } else { Some(b) })
            }
            Source::H1(b) => b.chunk().await,
            Source::H2(b) => b.chunk().await,
        }
    }
}

/// Decode a whole buffered body.
pub fn decode(encoding: &str, body: Vec<u8>) -> Result<Vec<u8>> {
    if body.is_empty() {
        return Ok(body);
    }
    match StreamDecoder::new(encoding) {
        Some(mut d) => {
            let mut out = d.feed(&body)?;
            out.extend(d.finish()?);
            Ok(out)
        }
        None => Ok(body),
    }
}

enum Stage {
    Gzip(flate2::write::MultiGzDecoder<Vec<u8>>),
    Zlib(flate2::write::ZlibDecoder<Vec<u8>>),
    Deflate(flate2::write::DeflateDecoder<Vec<u8>>),
    /// "deflate" is zlib-wrapped per RFC, but some servers send raw deflate: sniff it.
    DeflateSniff(Vec<u8>),
    Brotli(Box<brotli::DecompressorWriter<Vec<u8>>>),
    Zstd(Box<zstd::stream::write::Decoder<'static, Vec<u8>>>),
}

fn derr(e: impl std::fmt::Display) -> Error {
    Error::Decode(e.to_string())
}

impl Stage {
    fn feed(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if let Stage::DeflateSniff(buf) = self {
            buf.extend_from_slice(data);
            if buf.len() < 2 {
                return Ok(Vec::new());
            }
            let pending = std::mem::take(buf);
            let zlib = pending[0] & 0x0f == 8 && (u16::from(pending[0]) << 8 | u16::from(pending[1])) % 31 == 0;
            *self = if zlib {
                Stage::Zlib(flate2::write::ZlibDecoder::new(Vec::new()))
            } else {
                Stage::Deflate(flate2::write::DeflateDecoder::new(Vec::new()))
            };
            return self.feed(&pending);
        }
        macro_rules! run {
            ($w:expr) => {{
                $w.write_all(data).map_err(derr)?;
                $w.flush().map_err(derr)?;
                Ok(std::mem::take($w.get_mut()))
            }};
        }
        match self {
            Stage::Gzip(w) => run!(w),
            Stage::Zlib(w) => run!(w),
            Stage::Deflate(w) => run!(w),
            Stage::Brotli(w) => run!(w),
            Stage::Zstd(w) => run!(w),
            Stage::DeflateSniff(_) => unreachable!(),
        }
    }

    fn finish(&mut self) -> Result<Vec<u8>> {
        match self {
            Stage::Gzip(w) => {
                w.try_finish().map_err(derr)?;
                Ok(std::mem::take(w.get_mut()))
            }
            Stage::Zlib(w) => {
                w.try_finish().map_err(derr)?;
                Ok(std::mem::take(w.get_mut()))
            }
            Stage::Deflate(w) => {
                w.try_finish().map_err(derr)?;
                Ok(std::mem::take(w.get_mut()))
            }
            Stage::Brotli(w) => {
                w.close().map_err(derr)?;
                Ok(std::mem::take(w.get_mut()))
            }
            Stage::Zstd(w) => {
                w.flush().map_err(derr)?;
                Ok(std::mem::take(w.get_mut()))
            }
            Stage::DeflateSniff(buf) => {
                if buf.is_empty() {
                    return Ok(Vec::new());
                }
                let pending = std::mem::take(buf);
                *self = Stage::Deflate(flate2::write::DeflateDecoder::new(Vec::new()));
                let mut out = self.feed(&pending)?;
                out.extend(self.finish()?);
                Ok(out)
            }
        }
    }
}

/// Push-based decoder for a (possibly stacked) Content-Encoding.
pub struct StreamDecoder {
    /// In decoding order (reverse of the header order).
    stages: Vec<Stage>,
    fed: bool,
}

impl StreamDecoder {
    /// `None` when there is nothing to decode, or an encoding is unknown (the body is then
    /// handed back as-is, like before).
    pub fn new(encoding: &str) -> Option<StreamDecoder> {
        let mut stages = Vec::new();
        for enc in encoding.split(',').map(|e| e.trim().to_ascii_lowercase()).rev() {
            stages.push(match enc.as_str() {
                "" | "identity" => continue,
                "gzip" | "x-gzip" => Stage::Gzip(flate2::write::MultiGzDecoder::new(Vec::new())),
                "deflate" => Stage::DeflateSniff(Vec::new()),
                "br" => Stage::Brotli(Box::new(brotli::DecompressorWriter::new(Vec::new(), 64 * 1024))),
                "zstd" => Stage::Zstd(Box::new(zstd::stream::write::Decoder::new(Vec::new()).ok()?)),
                _ => return None,
            });
        }
        if stages.is_empty() {
            None
        } else {
            Some(StreamDecoder { stages, fed: false })
        }
    }

    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        self.fed = true;
        let mut buf = data.to_vec();
        for s in &mut self.stages {
            buf = s.feed(&buf)?;
            if buf.is_empty() {
                break;
            }
        }
        Ok(buf)
    }

    pub fn finish(&mut self) -> Result<Vec<u8>> {
        if !self.fed {
            return Ok(Vec::new());
        }
        let mut carry: Vec<u8> = Vec::new();
        for s in &mut self.stages {
            let mut out = if carry.is_empty() { Vec::new() } else { s.feed(&carry)? };
            out.extend(s.finish()?);
            carry = out;
        }
        Ok(carry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn chunked_decode(enc: &str, data: &[u8], step: usize) -> Vec<u8> {
        let mut d = StreamDecoder::new(enc).unwrap();
        let mut out = Vec::new();
        for c in data.chunks(step) {
            out.extend(d.feed(c).unwrap());
        }
        out.extend(d.finish().unwrap());
        out
    }

    #[test]
    fn streaming_codecs() {
        let text: Vec<u8> = (0..200_000u32).flat_map(|i| (i % 251).to_le_bytes()).collect();
        let gz = gzip(&text);
        assert_eq!(chunked_decode("gzip", &gz, 7), text);

        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        z.write_all(&text).unwrap();
        let z = z.finish().unwrap();
        assert_eq!(chunked_decode("deflate", &z, 1), text);

        let mut raw = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        raw.write_all(&text).unwrap();
        let raw = raw.finish().unwrap();
        assert_eq!(chunked_decode("deflate", &raw, 1000), text);

        let mut br = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut br, 4096, 5, 22);
            w.write_all(&text).unwrap();
        }
        assert_eq!(chunked_decode("br", &br, 333), text);

        let zs = zstd::stream::encode_all(&text[..], 3).unwrap();
        assert_eq!(chunked_decode("zstd", &zs, 4096), text);

        // Stacked: gzip applied first, then br.
        let mut stacked = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut stacked, 4096, 5, 22);
            w.write_all(&gz).unwrap();
        }
        assert_eq!(chunked_decode("gzip, br", &stacked, 100), text);
        assert_eq!(decode("gzip", gz).unwrap(), text);
    }

    #[test]
    fn passthrough_and_errors() {
        assert!(StreamDecoder::new("identity").is_none());
        assert!(StreamDecoder::new("gzip, foo").is_none());
        assert_eq!(decode("gzip", Vec::new()).unwrap(), Vec::<u8>::new());
        let mut d = StreamDecoder::new("gzip").unwrap();
        assert!(d.feed(b"definitely not gzip data").is_err() || d.finish().is_err());
    }
}
