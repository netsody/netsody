//! Error types for identity operations.
//!
//! This module defines error types that can occur during identity operations
//! such as generation, loading, saving, and validation of cryptographic identities.

// Standard library imports
use std::io;

// External crate imports
use crate::crypto;
use thiserror::Error;
// Crate-internal imports
use crate::util::HexError;

/// Error type for operations on [`crate::identity::Identity`].
///
/// This enum represents all possible errors that can occur during identity operations,
/// including generation, loading, saving, and validation.
///
/// # Variants
///
/// * [`PowNotFound`](Error::PowNotFound) - Could not find a valid proof of work
/// * [`GenerationFailed`](Error::GenerationFailed) - Failed to generate cryptographic keys
/// * [`IoError`](Error::IoError) - Failed to read/write identity file
/// * [`HexError`](Error::HexError) - Invalid hex string format
/// * [`InvalidKeyLength`](Error::InvalidKeyLength) - Key length does not match expected size
#[derive(Debug, Error)]
pub enum Error {
    /// Could not find a valid proof of work that meets the minimum difficulty requirement.
    #[error("Proof of Work could not be found")]
    PowNotFound,

    /// Failed to generate cryptographic keys during identity creation.
    #[error("Identity generation failed: {0}")]
    GenerationFailed(#[from] crypto::Error),

    /// Failed to read from or write to the identity file.
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    /// Invalid hex string format when parsing keys.
    #[error("Invalid hex string: {0}")]
    HexError(#[from] HexError),

    /// Key length does not match the expected size for Ed25519 keys.
    #[error("Invalid key length")]
    InvalidKeyLength,
}
