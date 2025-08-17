//! Proof of Work implementation for the drasyl protocol.
//!
//! This module provides functionality for generating and validating proof of work
//! values used to prevent Sybil attacks in the drasyl network.

// Crate-internal imports
use crate::crypto::sha256;
use crate::identity::PubKey;
use crate::identity::error::Error;
use std::fmt;
use std::fmt::{Display, Formatter};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// A 4-byte proof of work value used to prevent Sybil attacks in the network.
///
/// The proof of work is a cryptographic puzzle that must be solved to create a valid identity.
/// It helps protect the network from Sybil attacks by making it computationally expensive
/// to create multiple identities. This ensures that the cost of creating fake identities
/// is high enough to deter attackers from controlling a significant portion of the network.
///
/// # Structure
///
/// The proof of work is stored as a 4-byte array, which is interpreted as a big-endian
/// signed 32-bit integer. This integer is used in combination with the node's public key
/// to generate a hash that must meet a minimum difficulty requirement.
///
/// # Validation
///
/// A proof of work is considered valid if the SHA-256 hash of the concatenated public key
/// and proof of work value has at least `min_pow_difficulty` leading zero bits. The higher
/// the difficulty, the more computational work is required to create a new identity.
///
/// # Example
///
/// ```rust
/// use std::str::FromStr;
/// use drasyl_p2p::identity::{Pow, PubKey};
///
/// // A valid proof of work for a given public key and difficulty
/// let pk = PubKey::from_str("9331341e09d313baa4027a2fccea4fd471b9637f2305de714009c46b9192e006").expect("Invalid public key");
/// let pow = (-2130520098i32).to_be_bytes().into();
/// let difficulty = 24;
///
/// assert!(Pow::validate(&pk, &pow, difficulty));
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable)]
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "i32", from = "i32"))]
pub struct Pow(pub(crate) [u8; 4]);

impl Pow {
    /// Generate a proof of work for the given public key and minimum difficulty.
    ///
    /// This function iterates through possible proof of work values until it finds
    /// one that meets the minimum difficulty requirement. The process can be
    /// computationally intensive depending on the difficulty level.
    ///
    /// # Arguments
    /// * `pk` - The public key to generate proof of work for
    /// * `min_pow_difficulty` - Minimum number of leading zero bits required
    ///
    /// # Returns
    /// A valid proof of work value or an error if none could be found
    ///
    /// # Errors
    /// Returns [`Error::PowNotFound`] if no valid proof of work could be found
    /// within the search space.
    pub fn generate(pk: &PubKey, min_pow_difficulty: u8) -> Result<Pow, Error> {
        for candidate in i32::MIN..i32::MAX {
            let candidate_bytes = candidate.to_be_bytes().into();
            if Self::validate(pk, &candidate_bytes, min_pow_difficulty) {
                return Ok(candidate_bytes);
            }
        }
        Err(Error::PowNotFound)
    }

    /// Validate a proof of work for the given public key and minimum difficulty.
    ///
    /// This function checks whether the provided proof of work meets the minimum
    /// difficulty requirement by calculating the SHA-256 hash of the concatenated
    /// public key and proof of work value, then counting the leading zero bits.
    ///
    /// # Arguments
    /// * `pk` - The public key to validate against
    /// * `pow` - The proof of work value to validate
    /// * `min_pow_difficulty` - Minimum number of leading zero bits required
    ///
    /// # Returns
    /// `true` if the proof of work is valid, `false` otherwise
    #[doc(hidden)]
    pub fn validate(pk: &PubKey, pow: &Pow, min_pow_difficulty: u8) -> bool {
        // calculate proof of work difficulty
        let input = format!("{pk}{pow}");
        let hash = sha256(input.as_bytes()).unwrap();

        // count leading zero bits
        let mut leading_zeros: u8 = 0;
        for &byte in &hash {
            if byte == 0 {
                leading_zeros += 8;
            } else {
                leading_zeros += byte.leading_zeros() as u8;
                break;
            }
        }

        leading_zeros >= min_pow_difficulty
    }
}

impl From<[u8; 4]> for Pow {
    fn from(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }
}

impl From<i32> for Pow {
    fn from(int: i32) -> Self {
        Self(int.to_be_bytes())
    }
}

impl Display for Pow {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", i32::from_be_bytes(self.0))
    }
}

impl fmt::Debug for Pow {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl From<Pow> for i32 {
    fn from(pow: Pow) -> Self {
        i32::from_be_bytes(pow.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_pow_validate_valid() {
        let pk =
            PubKey::from_str("9331341e09d313baa4027a2fccea4fd471b9637f2305de714009c46b9192e006")
                .unwrap();
        let pow = (-2130520098i32).into();
        let difficulty = 24;

        assert!(Pow::validate(&pk, &pow, difficulty));
    }

    #[test]
    fn test_pow_validate_invalid() {
        let pk =
            PubKey::from_str("38fddd8d068165f227199b521bf91c09577231f05cae822d78c04be7595fb81d")
                .unwrap();
        let pow = (-2110011455i32).into();
        let difficulty = 24;

        assert!(!Pow::validate(&pk, &pow, difficulty));
    }
}
