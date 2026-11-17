//! mirage-core: an HTTP client that reproduces real browser fingerprints
//! (TLS ClientHello, HTTP/2 SETTINGS / priorities / pseudo-header order, header order).

pub mod body;
pub mod client;
pub mod conn;
pub mod error;
pub mod h1;
pub mod h2;
pub mod profile;
pub mod proxy;
pub mod tls;

pub use client::{Client, ClientOptions, Request, Response};
pub use error::{Error, Result};
pub use profile::Profile;

/// A response as read off the wire (body still content-encoded).
#[derive(Debug, Clone)]
pub struct RawResponse {
    pub status: u16,
    pub reason: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
