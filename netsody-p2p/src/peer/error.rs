//! Error types for peer operations.
//!
//! This module defines error types that can occur during peer management
//! operations such as cryptographic key agreement and super peer resolution.

// External crate imports
use crate::crypto;
use thiserror::Error;

/// Error type for peer operations.
///
/// This enum represents all possible errors that can occur during peer
/// management, including cryptographic operations and network resolution.
#[derive(Debug, Error)]
pub enum Error {
    /// Cryptographic operation failed.
    #[error("Crypto error: {0}")]
    Crypto(#[from] crypto::Error),

    /// Agreement public key is not present when required.
    #[error("Agreement pk not present")]
    AgreementPkNotPresent,

    /// Agreement secret key is not present when required.
    #[error("Agreement sk not present")]
    AgreementSkNotPresent,

    /// Failed to look up super peer address.
    #[error("Failed to look up super peer address {0}: {1}")]
    SuperPeerLookupFailed(String, String),

    /// Timeout exceeded while resolving super peer hostname.
    #[error("Timeout of {1} ms exceeded while attempting to resolve super peer host {0}")]
    SuperPeerResolveTimeout(String, u64),

    /// Empty result returned from super peer hostname resolution.
    #[error("Empty result on super peer host resolve")]
    SuperPeerResolveEmpty,
}
