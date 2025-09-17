//! Secret key implementation for the Netsody protocol.
//!
//! This module provides the SecKey type which wraps Ed25519 secret keys
//! used for signing messages and deriving public keys.

// Standard library imports
use std::borrow::Borrow;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

// Crate-internal imports
use crate::crypto::{ED25519_PUBLICKEYBYTES, ED25519_SECRETKEYBYTES, SigningSecKey};
use crate::identity::{Error, PubKey};
use crate::util::{bytes_to_hex, hex_to_bytes};

/// A wrapper for an Ed25519 secret key.
///
/// This structure encapsulates a 32-byte Ed25519 secret key used for:
/// * Signing messages to prove authenticity
/// * Deriving the corresponding public key
/// * Generating cryptographic material for secure communication
///
/// # Security
///
/// The secret key is the most sensitive piece of cryptographic material in the system.
/// It should never be exposed or transmitted over the network.
///
/// # Example
///
/// ```rust
/// use netsody_p2p::identity::SecKey;
///
/// // Secret keys are typically generated as part of an Identity
/// // and should not be created directly
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SecKey([u8; ED25519_SECRETKEYBYTES]);

impl SecKey {
    /// Extract the public key from a secret key.
    ///
    /// This function extracts the public key portion from an Ed25519 secret key.
    /// In Ed25519, the secret key contains both the private and public key material.
    ///
    /// # Returns
    /// The corresponding public key
    pub fn extract_pk(&self) -> PubKey {
        // Extract the last 32 bytes (public key portion) from the 64-byte secret key
        let pk_start = ED25519_SECRETKEYBYTES - ED25519_PUBLICKEYBYTES;
        let pk_bytes: [u8; ED25519_PUBLICKEYBYTES] = self.0[pk_start..].try_into().unwrap();
        pk_bytes.into()
    }
}

impl Borrow<[u8; ED25519_SECRETKEYBYTES]> for SecKey {
    fn borrow(&self) -> &[u8; ED25519_SECRETKEYBYTES] {
        &self.0
    }
}

impl From<[u8; ED25519_SECRETKEYBYTES]> for SecKey {
    fn from(bytes: [u8; ED25519_SECRETKEYBYTES]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<&[u8]> for SecKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        <[u8; ED25519_SECRETKEYBYTES]>::try_from(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidKeyLength)
    }
}

impl FromStr for SecKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex_to_bytes(s).map(Self).map_err(Error::HexError)
    }
}

impl From<SecKey> for SigningSecKey {
    fn from(sk: SecKey) -> SigningSecKey {
        sk.0
    }
}

impl Display for SecKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", bytes_to_hex(&self.0))
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SecKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::from_str(&s).map_err(serde::de::Error::custom)
        } else {
            let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
            let array: [u8; ED25519_SECRETKEYBYTES] = bytes
                .try_into()
                .map_err(|_| serde::de::Error::custom("invalid length"))?;
            Ok(Self(array))
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SecKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            self.0.to_vec().serialize(serializer)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_public_key() {
        let sk = SecKey::from_str(
            "3e6499116ba86b4884345891f3421a5a16c902247326928ce41c10ad8a66bd1f668178a3be9ad22f4f6e94c835ac824cf365db86bb486ab4a42c021dec09c0e4",
        ).unwrap();
        let expected_pk =
            PubKey::from_str("668178a3be9ad22f4f6e94c835ac824cf365db86bb486ab4a42c021dec09c0e4")
                .unwrap();

        assert_eq!(sk.extract_pk(), expected_pk);
    }
}
