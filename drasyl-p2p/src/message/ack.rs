//! ACK message implementation for the drasyl protocol.
//!
//! ACK messages are sent in response to HELLO messages to confirm receipt
//! and establish bidirectional communication between peers.

// Standard library imports
use std::fmt;

// External crate imports
use crate::crypto::SessionKey;
use tracing::{instrument, trace};
use zerocopy::big_endian::U64;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
// Crate-internal imports
use crate::identity::{Pow, PubKey};
use crate::message::arming::ARM_HEADER_LEN;
use crate::message::error::Error;
use crate::message::long_header::{LongHeader, NetworkId};
use crate::message::{
    LONG_HEADER_HOP_COUNT_LEN, LONG_HEADER_LEN, LONG_HEADER_MAGIC_NUMBER_LEN, MessageType, arming,
};

const ACK_TIME_LEN: usize = 8;
const ACK_LEN: usize = ACK_TIME_LEN;

/// ACK message sent in response to HELLO messages.
///
/// ACK messages confirm receipt of HELLO messages and help establish
/// bidirectional communication between peers. They contain timing
/// information used for latency calculation.
#[repr(C, packed)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct AckMessage {
    /// Timestamp when the original HELLO message was sent (in microseconds)
    pub time: U64,
}

impl AckMessage {
    /// Parse an ACK message from a buffer.
    ///
    /// # Arguments
    /// * `buf` - Buffer containing the ACK message
    /// * `long_header` - The long header of the message
    /// * `rx_key` - Optional session key for decryption
    ///
    /// # Returns
    /// Reference to the parsed ACK message or an error
    pub(crate) fn parse<'a>(
        buf: &'a mut [u8],
        long_header: &'a LongHeader,
        rx_key: Option<&SessionKey>,
    ) -> Result<&'a Self, Error> {
        let buf = if long_header.is_armed() && rx_key.is_some() {
            // disarm body
            if let Some(rx_key) = rx_key {
                arming::disarm_message_body(
                    buf,
                    &long_header.as_bytes()
                        [LONG_HEADER_MAGIC_NUMBER_LEN + LONG_HEADER_HOP_COUNT_LEN..],
                    rx_key,
                )?;
                &buf[ARM_HEADER_LEN..]
            } else {
                return Err(Error::RxKeyNotPresent);
            }
        } else {
            buf
        };

        match Self::ref_from_prefix(buf) {
            Ok((ack, _)) => Ok(ack),
            Err(e) => Err(Error::AckMessageConversionFailed(e.to_string())),
        }
    }

    /// Build an ACK message into a buffer.
    ///
    /// # Arguments
    /// * `buf` - Buffer to write the ACK message to
    /// * `network_id` - Network identifier
    /// * `my_pk` - Sender's public key
    /// * `my_pow` - Sender's proof of work
    /// * `tx_key` - Optional session key for encryption
    /// * `recipient` - Recipient's public key
    /// * `time` - Timestamp to include in the ACK
    ///
    /// # Returns
    /// Number of bytes written or an error
    #[instrument(name = "AckMessage::build", skip_all)]
    pub fn build(
        buf: &mut [u8],
        network_id: &NetworkId,
        my_pk: &PubKey,
        my_pow: &Pow,
        tx_key: Option<&SessionKey>,
        recipient: &PubKey,
        time: u64,
    ) -> Result<usize, Error> {
        // buffer
        let buf_len = LONG_HEADER_LEN + ACK_LEN + tx_key.is_some() as usize * ARM_HEADER_LEN;
        let buf = &mut buf[..buf_len];

        // long header
        let long_header = LongHeader::new(
            tx_key.is_some(),
            network_id,
            my_pk,
            my_pow,
            recipient,
            MessageType::ACK,
        );
        long_header
            .write_to_prefix(buf)
            .map_err(|e| Error::WriteLongHeaderFailed(e.to_string()))?;
        let body_slice = &mut buf[LONG_HEADER_LEN..];

        // body
        let ack = Self::mut_from_bytes(if tx_key.is_some() {
            &mut body_slice[ARM_HEADER_LEN..]
        } else {
            body_slice
        })
        .map_err(|e| Error::BuildAckMessageFailed(e.to_string()))?;
        ack.time = time.into();
        log_ack_message(&long_header, ack);

        if tx_key.is_some() {
            // arm body
            if let Some(tx_key) = tx_key {
                arming::arm_message_body(
                    body_slice,
                    &long_header.as_bytes()
                        [LONG_HEADER_MAGIC_NUMBER_LEN + LONG_HEADER_HOP_COUNT_LEN..],
                    tx_key,
                )?;
            } else {
                return Err(Error::TxKeyNotPresent);
            }
        }

        Ok(buf_len)
    }
}

impl fmt::Display for AckMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ACK:")?;
        write!(f, "└─ Time : {} ms", self.time / 1000)
    }
}

/// Log an ACK message for debugging purposes.
///
/// # Arguments
/// * `hdr` - The long header of the message
/// * `ack` - The ACK message to log
#[inline]
pub fn log_ack_message(hdr: &LongHeader, ack: &AckMessage) {
    trace!(
        r#type = %hdr.message_type,
        recipient = %hdr.recipient,
        sender = %hdr.sender,
        time = %ack.time,
    );
}
