use std::io;
use thiserror::Error;

/// Errors that can occur during REST API authentication operations
#[derive(Debug, Error)]
pub enum Error {
    /// Token is missing from the authentication request headers
    #[error("Authentication token missing")]
    AuthTokenMissing,

    /// Token provided in the request is invalid or has incorrect format
    #[error("Authentication token invalid or has incorrect format")]
    AuthTokenWrong,

    /// Token file could not be read due to file system errors
    #[error("Failed to read token file: {0}")]
    AuthTokenReadFailed(io::Error),

    /// Token file does not exist at the specified location
    #[error("Token file does not exist")]
    AuthTokenFileNotFound,

    /// Token generation failed due to internal error
    #[error("Failed to generate authentication token: {reason}")]
    TokenGenerationFailed { reason: String },

    /// API status request failed to retrieve node status information
    #[error("Failed to get node status: {reason}")]
    StatusRequestFailed { reason: String },

    /// Failed to bind the REST API server to the specified address/port
    #[error("Failed to bind REST API server: {0}")]
    Bind(io::Error),

    /// Failed to serve the REST API due to server error
    #[error("Failed to serve REST API: {0}")]
    Serve(io::Error),

    /// Invalid configuration URL provided
    #[error("Invalid configuration URL: {reason}")]
    InvalidConfigUrl { reason: String },

    /// Network configuration fetch failed
    #[error("Failed to fetch network configuration: {reason}")]
    NetworkConfigFetchFailed { reason: String },

    /// Network already exists
    #[error("Network already exists: {config_url}")]
    NetworkAlreadyExists { config_url: String },

    /// Network not found
    #[error("Network not found: {config_url}")]
    NetworkNotFound { config_url: String },
}
