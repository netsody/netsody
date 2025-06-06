//! Proof of Work status tracking for peers.
//!
//! This module provides the PowStatus enum for tracking the validation
//! state of proof of work values for network peers.

// Standard library imports
use std::fmt;

/// Status of proof of work validation for a peer.
///
/// This enum tracks whether a peer's proof of work has been validated,
/// is known to be invalid, or is still unknown/pending validation.
#[derive(Debug, Default)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PowStatus {
    /// Proof of work status is unknown or pending validation.
    #[default]
    Unknw = 0,
    /// Proof of work has been validated and is correct.
    Ok = 1,
    /// Proof of work has been validated and is incorrect.
    Nok = 2,
}

impl TryFrom<u8> for PowStatus {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PowStatus::Unknw),
            1 => Ok(PowStatus::Ok),
            2 => Ok(PowStatus::Nok),
            _ => Err(()),
        }
    }
}

impl fmt::Display for PowStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Ok => "ok",
                Self::Nok => "nok",
                Self::Unknw => "",
            }
        )
    }
}

impl From<PowStatus> for u8 {
    fn from(status: PowStatus) -> Self {
        status as u8
    }
}
