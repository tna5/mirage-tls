//! Content-Encoding decoding (gzip, deflate, br, zstd).

use crate::error::{Error, Result};
use std::io::Read;

pub fn decode(encoding: &str, body: Vec<u8>) -> Result<Vec<u8>> {
    let mut data = body;
    // Encodings are listed in the order they were applied.
    for enc in encoding.split(',').map(|e| e.trim().to_ascii_lowercase()).rev() {
        if data.is_empty() {
            break;
        }
        data = match enc.as_str() {
            "" | "identity" => data,
            "gzip" | "x-gzip" => read_all(flate2::read::MultiGzDecoder::new(&data[..]))?,
            "deflate" => read_all(flate2::read::ZlibDecoder::new(&data[..]))
                .or_else(|_| read_all(flate2::read::DeflateDecoder::new(&data[..])))?,
            "br" => read_all(brotli::Decompressor::new(&data[..], 64 * 1024))?,
            "zstd" => zstd::stream::decode_all(&data[..]).map_err(|e| Error::Decode(e.to_string()))?,
            _ => return Ok(data), // unknown: hand back as-is
        };
    }
    Ok(data)
}

fn read_all<R: Read>(mut r: R) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    r.read_to_end(&mut out).map_err(|e| Error::Decode(e.to_string()))?;
    Ok(out)
}
