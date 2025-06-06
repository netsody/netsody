//! Short header implementation for the drasyl protocol.
//!
//! Short headers provide compact message routing using short IDs instead of
//! full public keys. They are used for efficient communication between
//! established peers.

// Standard library imports
use std::borrow::Borrow;
use std::fmt::{Display, Formatter};

// External crate imports
use crate::crypto::SessionKey;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
// Crate-internal imports
use crate::message::arming;
use crate::message::arming::ARM_HEADER_LEN;
use crate::message::error::Error;
use crate::message::long_header::MagicNumber;
use crate::util::bytes_to_hex;

/// Size of short header ID field in bytes.
pub(crate) const SHORT_HEADER_ID_LEN: usize = 4;
/// Special short ID value indicating no short ID is assigned.
pub const SHORT_ID_NONE: ShortId = ShortId([0u8; SHORT_HEADER_ID_LEN]);
/// Total size of the complete short header in bytes.
pub const SHORT_HEADER_LEN: usize = SHORT_HEADER_ID_LEN;

/// Short ID for efficient message routing between established peers.
///
/// Short IDs are compact identifiers used instead of full public keys
/// for routing messages between peers that have already established
/// a connection and exchanged their full identities.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ShortId([u8; SHORT_HEADER_ID_LEN]);

impl ShortId {
    /// Convert the short ID to raw bytes.
    ///
    /// # Returns
    /// Array containing the short ID bytes
    pub(crate) fn to_bytes(self) -> [u8; SHORT_HEADER_ID_LEN] {
        self.0
    }
}

impl Borrow<[u8; SHORT_HEADER_ID_LEN]> for ShortId {
    fn borrow(&self) -> &[u8; SHORT_HEADER_ID_LEN] {
        &self.0
    }
}

impl From<[u8; SHORT_HEADER_ID_LEN]> for ShortId {
    fn from(bytes: [u8; SHORT_HEADER_ID_LEN]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<&[u8]> for ShortId {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        <[u8; SHORT_HEADER_ID_LEN]>::try_from(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidShortId)
    }
}

impl Display for ShortId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", bytes_to_hex(&self.0))
    }
}

/// Short header for efficient message routing between established peers.
///
/// Short headers use compact short IDs instead of full public keys for
/// routing, making them more efficient for communication between peers
/// that have already established a connection.
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct ShortHeader {
    /// Magic number identifying drasyl protocol messages
    pub magic_number: MagicNumber,
    /// The message payload
    pub payload: [u8],
}

impl ShortHeader {
    /// Parse a short header message from a buffer.
    ///
    /// # Arguments
    /// * `buf` - Buffer containing the message
    /// * `rx_key` - Optional session key for decryption
    ///
    /// # Returns
    /// Reference to the message payload or an error
    pub(crate) fn parse<'a>(
        buf: &'a mut [u8],
        rx_key: Option<&SessionKey>,
    ) -> Result<&'a [u8], Error> {
        if let Some(rx_key) = rx_key {
            let (ad, buf) = buf.split_at_mut(SHORT_HEADER_ID_LEN);
            arming::disarm_message_body(buf, ad, rx_key)?;
            Ok(&buf[ARM_HEADER_LEN..])
        } else {
            Ok(&buf[SHORT_HEADER_ID_LEN..])
        }
    }

    /// Build a short header message.
    ///
    /// # Arguments
    /// * `short_id` - Short ID for message routing
    /// * `tx_key` - Optional session key for encryption
    /// * `payload` - The message payload
    ///
    /// # Returns
    /// Vector containing the complete message or an error
    pub fn build(
        short_id: ShortId,
        tx_key: Option<&SessionKey>,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // buffer
        let buf_len =
            SHORT_HEADER_ID_LEN + payload.len() + tx_key.is_some() as usize * ARM_HEADER_LEN;
        let mut buf = Vec::with_capacity(buf_len);
        unsafe { buf.set_len(buf.capacity()) };

        buf[..SHORT_HEADER_ID_LEN].copy_from_slice(&short_id.to_bytes());
        if tx_key.is_some() {
            buf[SHORT_HEADER_ID_LEN + ARM_HEADER_LEN..].copy_from_slice(payload);
        } else {
            buf[SHORT_HEADER_ID_LEN..].copy_from_slice(payload);
        }

        if let Some(tx_key) = tx_key {
            let (ad, buf2) = buf.split_at_mut(SHORT_HEADER_ID_LEN);
            arming::arm_message_body(buf2, ad, tx_key)?;
        }

        Ok(buf)
    }
}
