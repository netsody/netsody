//! UNITE message implementation for the drasyl protocol.
//!
//! UNITE messages are used for NAT traversal and direct connection establishment
//! between peers. They contain endpoint information to help peers connect directly.

// Standard library imports
use std::collections::HashSet;
use std::fmt;

// External crate imports
use crate::crypto::SessionKey;
use tracing::{instrument, trace};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
// Crate-internal imports
use crate::identity::{Pow, PubKey};
use crate::message::arming::ARM_HEADER_LEN;
use crate::message::endpoints::{Endpoint, EndpointsList};
use crate::message::error::Error;
use crate::message::hello::HELLO_MAX_ENDPOINTS;
use crate::message::long_header::{LongHeader, NetworkId};
use crate::message::{
    LONG_HEADER_HOP_COUNT_LEN, LONG_HEADER_LEN, LONG_HEADER_MAGIC_NUMBER_LEN, MessageType, arming,
};
use crate::util::IPV6_LENGTH;

// Constants
const UNITE_ADDRESS_LEN: usize = 32;
const UNITE_ENDPOINT_LEN: usize = 2 + IPV6_LENGTH;
const UNITE_MIN_LEN: usize = UNITE_ADDRESS_LEN + UNITE_ENDPOINT_LEN;
pub(crate) const UNITE_MAX_ENDPOINTS: usize = HELLO_MAX_ENDPOINTS + 1;

/// UNITE message for NAT traversal and direct connection establishment.
///
/// UNITE messages are sent by super peers to help two peers establish
/// a direct connection by providing each peer with the other's endpoint
/// information. This enables NAT traversal and direct peer-to-peer communication.
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct UniteMessage {
    /// Public key of the peer to connect to
    pub address: PubKey,
    /// List of endpoints where the target peer can be reached
    pub endpoints: [u8],
}

impl UniteMessage {
    /// Parse a UNITE message from a buffer.
    ///
    /// # Arguments
    /// * `buf` - Buffer containing the UNITE message
    /// * `long_header` - The long header of the message
    /// * `rx_key` - Optional session key for decryption
    ///
    /// # Returns
    /// Reference to the parsed UNITE message or an error
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

        // rust implementation has a limit for endpoints. To not break compatibility with Java
        // implementation, we just take the first N endpoints instead of discarding the UNITE
        let buf = if buf.len() > UNITE_MIN_LEN + UNITE_ENDPOINT_LEN * (UNITE_MAX_ENDPOINTS - 1) {
            &buf[..UNITE_MIN_LEN + UNITE_ENDPOINT_LEN * (UNITE_MAX_ENDPOINTS - 1)]
        } else {
            buf
        };

        let unite: &Self =
            Self::ref_from_bytes(buf).map_err(|e| Error::UniteMessageInvalid(e.to_string()))?;

        Ok(unite)
    }

    /// Build a UNITE message.
    ///
    /// # Arguments
    /// * `network_id` - Network identifier
    /// * `my_pk` - Sender's public key
    /// * `my_pow` - Sender's proof of work
    /// * `tx_key` - Optional session key for encryption
    /// * `recipient` - Recipient's public key
    /// * `address` - Public key of the peer to connect to
    /// * `endpoints` - List of endpoints for the target peer
    ///
    /// # Returns
    /// Vector containing the complete UNITE message or an error
    #[instrument(name = "UniteMessage::build", skip_all)]
    pub fn build(
        network_id: &NetworkId,
        my_pk: &PubKey,
        my_pow: &Pow,
        tx_key: Option<&SessionKey>,
        recipient: &PubKey,
        address: &PubKey,
        endpoints: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // buffer
        let buf_len = LONG_HEADER_LEN + UNITE_MIN_LEN + endpoints.len() - UNITE_ENDPOINT_LEN
            + tx_key.is_some() as usize * ARM_HEADER_LEN;
        let mut buf = Vec::with_capacity(buf_len);
        unsafe { buf.set_len(buf.capacity()) };

        // long header
        let (long_header, body_slice) = LongHeader::write_bytes(
            &mut buf,
            tx_key.is_some(),
            network_id,
            my_pk,
            my_pow,
            recipient,
            MessageType::UNITE,
        )?;

        // body
        let unite = Self::mut_from_bytes(if tx_key.is_some() {
            &mut body_slice[ARM_HEADER_LEN..]
        } else {
            body_slice
        })
        .map_err(|e| Error::BuildUniteMessageFailed(e.to_string()))?;
        unite.address = *address;
        unite.endpoints.copy_from_slice(endpoints);
        log_unite_message(long_header, unite);

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

        Ok(buf)
    }
}

impl fmt::Display for UniteMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "UNITE:")?;
        writeln!(f, "├─ Address   : {}", self.address)?;
        writeln!(f, "└─ Endpoints :")?;
        let endpoints: EndpointsList = self.endpoints.into();
        let endpoints: HashSet<Endpoint> = endpoints.0;
        let len = endpoints.len();
        for (i, endpoint) in endpoints.iter().enumerate() {
            if i == len - 1 {
                writeln!(f, "   └─ {endpoint}")?;
            } else {
                writeln!(f, "   ├─ {endpoint}")?;
            }
        }
        Ok(())
    }
}

/// Log a UNITE message for debugging purposes.
///
/// # Arguments
/// * `hdr` - The long header of the message
/// * `unite` - The UNITE message to log
#[inline]
pub fn log_unite_message(hdr: &LongHeader, unite: &UniteMessage) {
    trace!(
        r#type = %hdr.message_type,
        recipient = %hdr.recipient,
        sender = %hdr.sender,
        address = %unite.address,
        endpoints = %EndpointsList::from(&unite.endpoints),
    );
}
