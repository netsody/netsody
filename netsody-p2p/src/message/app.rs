//! Application message implementation for the Netsody protocol.
//!
//! APP messages carry user data between peers in the Netsody network.
//! They represent the actual payload that applications want to transmit.

// Standard library imports
use std::fmt;

// External crate imports
use crate::crypto::SessionKey;
use tracing::trace;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref};
// Crate-internal imports
use crate::identity::{Pow, PubKey};
use crate::message::ARM_HEADER_LEN;
use crate::message::error::Error;
use crate::message::long_header::{LongHeader, NetworkId};
use crate::message::{
    LONG_HEADER_HOP_COUNT_LEN, LONG_HEADER_LEN, LONG_HEADER_MAGIC_NUMBER_LEN, MessageType,
    arm_message_body, disarm_message_body,
};

/// Application message containing user data.
///
/// APP messages are the primary way to send user data between peers.
/// The payload can contain any application-specific data and will be
/// encrypted if the node is configured with message encryption.
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct AppMessage {
    /// The application payload data
    pub payload: [u8],
}

impl AppMessage {
    /// Parse an APP message from a buffer.
    ///
    /// # Arguments
    /// * `buf` - Buffer containing the APP message
    /// * `long_header` - The long header of the message
    /// * `rx_key` - Optional session key for decryption
    ///
    /// # Returns
    /// Reference to the parsed APP message or an error
    pub(crate) fn parse<'a>(
        buf: &'a mut [u8],
        long_header: &'a LongHeader,
        rx_key: Option<&SessionKey>,
    ) -> Result<Ref<&'a [u8], Self>, Error> {
        let buf = if long_header.is_armed() && rx_key.is_some() {
            // disarm body
            if let Some(rx_key) = rx_key {
                disarm_message_body(
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

        let app: Ref<&'a [u8], Self> =
            Ref::from_bytes(buf).map_err(|e| Error::AppMessageInvalid(e.to_string()))?;

        Ok(app)
    }

    /// Build an APP message.
    ///
    /// # Arguments
    /// * `network_id` - Network identifier
    /// * `my_pk` - Sender's public key
    /// * `my_pow` - Sender's proof of work
    /// * `tx_key` - Optional session key for encryption
    /// * `recipient` - Recipient's public key
    /// * `payload` - The application data to send
    ///
    /// # Returns
    /// Vector containing the complete APP message or an error
    #[allow(clippy::uninit_vec)]
    pub fn build(
        network_id: &NetworkId,
        my_pk: &PubKey,
        my_pow: &Pow,
        tx_key: Option<&SessionKey>,
        recipient: &PubKey,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // buffer
        let buf_len = LONG_HEADER_LEN + payload.len() + tx_key.is_some() as usize * ARM_HEADER_LEN;
        let mut buf = Vec::with_capacity(buf_len);
        unsafe { buf.set_len(buf.capacity()) };

        // long header
        let long_header = LongHeader::new(
            tx_key.is_some(),
            network_id,
            my_pk,
            my_pow,
            recipient,
            MessageType::APP,
        );
        long_header
            .write_to_prefix(&mut buf)
            .map_err(|e| Error::WriteLongHeaderFailed(e.to_string()))?;
        let body_slice = &mut buf[LONG_HEADER_LEN..];

        // body
        let app = Self::mut_from_bytes(if tx_key.is_some() {
            &mut body_slice[ARM_HEADER_LEN..]
        } else {
            body_slice
        })
        .map_err(|e| Error::WriteAppMessageFailed(e.to_string()))?;
        app.payload[..payload.len()].copy_from_slice(payload);
        log_app_message(&long_header, app);

        if tx_key.is_some() {
            // arm body
            if let Some(tx_key) = tx_key {
                arm_message_body(
                    body_slice,
                    &long_header.as_bytes()
                        [LONG_HEADER_MAGIC_NUMBER_LEN + LONG_HEADER_HOP_COUNT_LEN..],
                    tx_key,
                )?;
            } else {
                return Err(Error::TxKeyNotPresent);
            }
        }

        Ok(buf)
    }
}

impl fmt::Display for AppMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "APP:")?;
        write!(f, "└─ Payload length: {} bytes", self.payload.len())
    }
}

/// Log an APP message for debugging purposes.
///
/// # Arguments
/// * `hdr` - The long header of the message
/// * `app` - The APP message to log
#[inline]
pub fn log_app_message(hdr: &LongHeader, app: &AppMessage) {
    trace!(
        r#type = %hdr.message_type,
        recipient = %hdr.recipient,
        sender = %hdr.sender,
        payload_len = %app.payload.len(),
    );
}
