use std::io;
use thiserror::Error;

/// Errors that can occur during REST API authentication operations
#[derive(Debug, Error)]
pub enum Error {
    /// Token is missing from the request
    #[error("Authentication token missing")]
    AuthTokenMissing,

    /// Token is invalid or wrong
    #[error("Authentication token invalid")]
    AuthTokenWrong,

    /// Token file could not be read
    #[error("Failed to read token file: {0}")]
    AuthTokenReadFailed(#[from] io::Error),

    /// Token file does not exist
    #[error("Token file does not exist")]
    AuthTokenFileNotFound,

    /// Token generation failed
    #[error("Failed to generate token: {reason}")]
    TokenGenerationFailed { reason: String },
}
