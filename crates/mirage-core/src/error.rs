use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("profile error: {0}")]
    Profile(String),
    #[error("invalid url: {0}")]
    Url(String),
    #[error("tls error: {0}")]
    Tls(String),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("proxy error: {0}")]
    Proxy(String),
    #[error("http error: {0}")]
    Http(String),
    #[error("http2 error: {0}")]
    H2(String),
    /// The server did not process the request (HTTP/2 REFUSED_STREAM, or GOAWAY for a
    /// stream above last_stream_id): it is safe to retry, and the client does so itself.
    #[error("request refused by server: {0}")]
    Refused(String),
    #[error("request cancelled")]
    Cancelled,
    #[error("request timed out")]
    Timeout,
    #[error("too many redirects")]
    TooManyRedirects,
    #[error("decompression error: {0}")]
    Decode(String),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<boring2::error::ErrorStack> for Error {
    fn from(e: boring2::error::ErrorStack) -> Self {
        Error::Tls(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
