use crate::network;
use std::io;
use std::string::FromUtf8Error;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("HTTP client error: {0}")]
    HttpClientError(#[from] hyper_util::client::legacy::Error),

    #[error("HTTP URI error: {0}")]
    HttpUriError(#[from] http::uri::InvalidUri),

    #[error("hyper error: {0}")]
    HyperError(#[from] hyper::Error),

    #[error("UTF8 error: {0}")]
    Utf8Error(#[from] FromUtf8Error),

    #[error("I/O error: {0}")]
    IOError(#[from] io::Error),

    #[error("TOML error: {0}")]
    TomlError(#[from] toml::de::Error),

    #[error("HTTP error: {0}")]
    HttpError(#[from] hyper::http::Error),

    #[error("URL parsing error: {0}")]
    UrlError(#[from] url::ParseError),

    #[error("Network error: {0}")]
    NetworkError(#[from] network::ConfigError),
}
