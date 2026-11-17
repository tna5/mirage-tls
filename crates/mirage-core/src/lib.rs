//! mirage-core: an HTTP client that reproduces real browser fingerprints
//! (TLS ClientHello, HTTP/2 SETTINGS / priorities / pseudo-header order, header order).

pub mod body;
pub mod client;
pub mod conn;
pub mod error;
pub mod fetch;
pub mod h1;
pub mod h2;
pub mod hpack;
pub mod net;
pub mod profile;
pub mod proxy;
pub mod tls;

pub use body::Body;
pub use client::{Client, ClientOptions, Request, Response, StreamResponse};
pub use error::{Error, Result};
pub use net::IpFamily;
pub use profile::Profile;

/// Status line + headers of a response as read off the wire.
#[derive(Debug, Clone)]
pub struct ResponseHead {
    pub status: u16,
    pub reason: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
}
