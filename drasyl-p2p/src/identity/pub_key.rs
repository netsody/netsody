//! Public key implementation for the drasyl protocol.
//!
//! This module provides the PubKey type which wraps Ed25519 public keys
//! and provides functionality for node identification and UDP port derivation.

// Standard library imports
use std::borrow::Borrow;
use std::fmt::{self, Display, Formatter};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::str::FromStr;

// External crate imports
use zerocopy::{FromBytes, Immutable, IntoBytes};

// Crate-internal imports
use crate::crypto::{ED25519_PUBLICKEYBYTES, SigningPubKey};
use crate::identity::MIN_DERIVED_PORT;
use crate::identity::error::Error;
use crate::util::{bytes_to_hex, hex_to_bytes};

/// A wrapper for an Ed25519 public key.
///
/// This structure encapsulates a 32-byte Ed25519 public key used for:
/// * Verifying message signatures
/// * Identifying nodes in the network
/// * Deriving a unique UDP port for the node
///
/// # Features
///
/// * Implements `Ord` and `PartialOrd` for consistent ordering
/// * Can be serialized/deserialized with serde (when feature enabled)
/// * Provides hex string conversion via `Display` and `FromStr`
///
/// # Example
///
/// ```rust
/// use std::str::FromStr;
/// use drasyl_p2p::identity::PubKey;
///
/// // Parse a public key from a hex string
/// let pk = PubKey::from_str("668178a3be9ad22f4f6e94c835ac824cf365db86bb486ab4a42c021dec09c0e4").expect("Invalid public key");
///
/// // Get the derived UDP port for this public key
/// let port = pk.udp_port();
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable)]
#[repr(transparent)]
pub struct PubKey([u8; ED25519_PUBLICKEYBYTES]);

impl PubKey {
    /// Derive a unique UDP port for this public key.
    ///
    /// This method derives a port in the range between MIN_DERIVED_PORT and MAX_PORT_NUMBER
    /// from the public key's identity. This is done because we also expose this port via
    /// UPnP-IGD/NAT-PMP/PCP and some NAT devices behave unexpectedly when multiple nodes
    /// in the local network try to expose the same local port.
    ///
    /// A completely random port would have the disadvantage that every time the node is
    /// started it would use a new port and this would make discovery more difficult.
    ///
    /// # Returns
    /// A deterministic UDP port derived from the public key
    pub fn udp_port(&self) -> u16 {
        // derive a port in the range between MIN_DERIVED_PORT and {MAX_PORT_NUMBER from its
        // own identity. this is done because we plan to expose this port via
        // UPnP-IGD/NAT-PMP/PCP and some NAT devices behave unexpectedly when multiple nodes
        // in the local network try to expose the same local port.
        // a completely random port would have the disadvantage that every time the node is
        // started it would use a new port and this would make discovery more difficult
        let mut hasher = DefaultHasher::new();
        self.0.hash(&mut hasher);
        let identity_hash = hasher.finish();

        let port_range = u16::MAX as u64 - MIN_DERIVED_PORT as u64;
        MIN_DERIVED_PORT + (identity_hash % port_range) as u16
    }
}

impl Borrow<[u8; ED25519_PUBLICKEYBYTES]> for PubKey {
    fn borrow(&self) -> &[u8; ED25519_PUBLICKEYBYTES] {
        &self.0
    }
}

impl From<[u8; ED25519_PUBLICKEYBYTES]> for PubKey {
    fn from(bytes: [u8; ED25519_PUBLICKEYBYTES]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<&[u8]> for PubKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        <[u8; ED25519_PUBLICKEYBYTES]>::try_from(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidKeyLength)
    }
}

impl FromStr for PubKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex_to_bytes(s).map(Self).map_err(Error::HexError)
    }
}

impl From<PubKey> for SigningPubKey {
    fn from(pk: PubKey) -> SigningPubKey {
        pk.0
    }
}

impl Display for PubKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", bytes_to_hex(&self.0))
    }
}

impl fmt::Debug for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl PartialOrd for PubKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PubKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PubKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::from_str(&s).map_err(serde::de::Error::custom)
        } else {
            let data: [u8; ED25519_PUBLICKEYBYTES] = serde::Deserialize::deserialize(deserializer)?;
            Self::try_from(data.as_ref()).map_err(serde::de::Error::custom)
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for PubKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            self.0.serialize(serializer)
        }
    }
}
