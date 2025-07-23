use crate::util::HexError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Generated session keys are identical")]
    SessionKeysIdentical,

    #[error("A Libsodium cryptographic error occurred")]
    LibsodiumError,

    #[error("An AEGIS cryptographic error occurred")]
    DecryptFailed,

    #[error("An AEGIS conversion error occurred")]
    AEGISConversionError,

    /// Invalid hex string format when parsing keys.
    #[error("Invalid hex string: {0}")]
    HexError(#[from] HexError),
}
