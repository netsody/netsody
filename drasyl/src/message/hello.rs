//! HELLO message implementations for the drasyl protocol.
//!
//! HELLO messages are used for peer discovery and connection establishment.
//! There are two types: HelloSuperPeerMessage for communication with super peers,
//! and HelloNodePeerMessage for direct peer-to-peer communication.

// Standard library imports
use std::collections::HashSet;
use std::fmt;

// External crate imports
use crate::crypto::SessionKey;
use tracing::{instrument, trace};
use zerocopy::big_endian::U64;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
// Crate-internal imports
use crate::identity::{Pow, PubKey};
use crate::message::arming::ARM_HEADER_LEN;
use crate::message::endpoints::{Endpoint, EndpointsList};
use crate::message::error::Error;
use crate::message::long_header::{LongHeader, NetworkId};
use crate::message::short_header::ShortId;
use crate::message::{
    LONG_HEADER_HOP_COUNT_LEN, LONG_HEADER_LEN, LONG_HEADER_MAGIC_NUMBER_LEN, MessageType, arming,
};
use crate::util::IPV6_LENGTH;

// HELLO body
/// Size of timestamp field in HELLO messages in bytes.
const HELLO_TIME_LEN: usize = 8;
/// Size of child time field in HELLO_SUPER_PEER messages in bytes.
const HELLO_CHILD_TIME_LEN: usize = 8;
/// Size of short ID field in HELLO_NODE_PEER messages in bytes.
const HELLO_SHORT_ID_LEN: usize = 4;
/// Size of a single endpoint entry in HELLO message (port + IPv6 address) in bytes.
pub const HELLO_ENDPOINT_LEN: usize = 2 + IPV6_LENGTH;
/// Size of a HELLO_NODE_PEER message body (time + short ID) in bytes.
const HELLO_NODE_PEER_LEN: usize = HELLO_TIME_LEN + HELLO_SHORT_ID_LEN;
/// Minimum size of a HELLO_SUPER_PEER message body (time + child time) in bytes.
const HELLO_SUPER_PEER_MIN_LEN: usize = HELLO_TIME_LEN + HELLO_CHILD_TIME_LEN;
/// Fixed child time value for HELLO_SUPER_PEER messages (always 1).
const HELLO_CHILD_TIME_SUPER_PEER: u64 = 1u64;
// actual time not used; any non-zero value is accepted by super peers
/// Maximum number of endpoints allowed in a HELLO_SUPER_PEER message.
pub(crate) const HELLO_MAX_ENDPOINTS: usize = 15;

/// HELLO message sent to super peers for registration and discovery.
///
/// Super peer HELLO messages contain timing information and a list of
/// endpoints where the sending peer can be reached. Super peers use
/// this information for peer discovery and message relaying.
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct HelloSuperPeerMessage {
    /// Timestamp when the message was sent (in microseconds)
    pub time: U64,
    /// Child time for super peer protocol (always set to 1)
    pub child_time: U64,
    /// List of endpoints where the sender can be reached
    pub endpoints: [u8], // TODO: replace with `EndpointsList`?
}

impl fmt::Display for HelloSuperPeerMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "HELLO_SUPER_PEER:")?;
        writeln!(f, "├─ Time       : {} ms", self.time / 1000)?;
        writeln!(f, "├─ Child time : {} ms", self.child_time / 1000)?;
        writeln!(f, "└─ Endpoints  :")?;
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

impl HelloSuperPeerMessage {
    /// Parse a HELLO_SUPER_PEER message from a buffer.
    ///
    /// # Arguments
    /// * `buf` - Buffer containing the HELLO message
    /// * `long_header` - The long header of the message
    /// * `rx_key` - Optional session key for decryption
    ///
    /// # Returns
    /// Reference to the parsed HELLO message or an error
    pub fn parse<'a>(
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
        // implementation, we just take the first N endpoints instead of discarding the HELLO
        let buf = if buf.len() > HELLO_SUPER_PEER_MIN_LEN + HELLO_ENDPOINT_LEN * HELLO_MAX_ENDPOINTS
        {
            &buf[..HELLO_SUPER_PEER_MIN_LEN + HELLO_ENDPOINT_LEN * HELLO_MAX_ENDPOINTS]
        } else {
            buf
        };

        let hello: &Self =
            Self::ref_from_bytes(buf).map_err(|e| Error::HelloMessageInvalid(e.to_string()))?;

        if hello.child_time == 0 {
            return Err(Error::HelloMessageInvalidChildTime);
        }

        if (hello.endpoints.len() % HELLO_ENDPOINT_LEN) != 0 {
            return Err(Error::HelloMessageInvalidEndpoints);
        }

        Ok(hello)
    }

    /// Build a HELLO_SUPER_PEER message.
    ///
    /// # Arguments
    /// * `network_id` - Network identifier
    /// * `my_pk` - Sender's public key
    /// * `my_pow` - Sender's proof of work
    /// * `tx_key` - Optional session key for encryption
    /// * `recipient` - Recipient's public key (super peer)
    /// * `time` - Timestamp for the message
    /// * `endpoints` - List of endpoints where sender can be reached
    ///
    /// # Returns
    /// Vector containing the complete HELLO message or an error
    #[allow(clippy::uninit_vec)]
    #[instrument(name = "HelloSuperPeerMessage::build", skip_all)]
    pub fn build(
        network_id: &NetworkId,
        my_pk: &PubKey,
        my_pow: &Pow,
        tx_key: Option<&SessionKey>,
        recipient: &PubKey,
        time: u64,
        endpoints: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // buffer
        let buf_len = LONG_HEADER_LEN
            + HELLO_SUPER_PEER_MIN_LEN
            + endpoints.len()
            + tx_key.is_some() as usize * ARM_HEADER_LEN;
        let mut buf = Vec::with_capacity(buf_len);
        unsafe { buf.set_len(buf.capacity()) };

        // long header
        let long_header = LongHeader::new(
            tx_key.is_some(),
            network_id,
            my_pk,
            my_pow,
            recipient,
            MessageType::HELLO,
        );
        long_header
            .write_to_prefix(&mut buf)
            .map_err(|e| Error::WriteLongHeaderFailed(e.to_string()))?;
        let body_slice = &mut buf[LONG_HEADER_LEN..];

        // body
        let hello = Self::mut_from_bytes(if tx_key.is_some() {
            &mut body_slice[ARM_HEADER_LEN..]
        } else {
            body_slice
        })
        .map_err(|_| Error::BuildHelloSuperPeerMessageFailed)?;
        hello.time = time.into();
        hello.child_time = HELLO_CHILD_TIME_SUPER_PEER.into();
        hello.endpoints.copy_from_slice(endpoints);

        log_hello_super_peer_message(&long_header, hello);

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

/// HELLO message sent between node peers for direct communication.
///
/// Node peer HELLO messages contain timing information and a short ID
/// for efficient message routing. They are used to establish direct
/// peer-to-peer connections.
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct HelloNodePeerMessage {
    /// Timestamp when the message was sent (in microseconds)
    pub time: U64,
    /// Short ID for efficient message routing
    pub short_id: ShortId,
}

impl fmt::Display for HelloNodePeerMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "HELLO_NODE_PEER:")?;
        writeln!(f, "└─ Time       : {} ms", self.time / 1000)?;
        writeln!(f, "└─ Short id   : {:}", self.short_id)?;
        Ok(())
    }
}

impl HelloNodePeerMessage {
    /// Create a new HELLO_NODE_PEER message.
    ///
    /// # Arguments
    /// * `time` - Timestamp for the message
    /// * `short_id` - Short ID for message routing
    ///
    /// # Returns
    /// New HelloNodePeerMessage instance
    fn new(time: u64, short_id: ShortId) -> Self {
        Self {
            time: time.into(),
            short_id,
        }
    }

    /// Parse a HELLO_NODE_PEER message from a buffer.
    ///
    /// # Arguments
    /// * `buf` - Buffer containing the HELLO message
    /// * `long_header` - The long header of the message
    /// * `rx_key` - Optional session key for decryption
    ///
    /// # Returns
    /// Reference to the parsed HELLO message or an error
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
            Ok((hello, _)) => Ok(hello),
            Err(e) => Err(Error::HelloMessageConversionFailed(e.to_string())),
        }
    }

    /// Build a HELLO_NODE_PEER message.
    ///
    /// # Arguments
    /// * `network_id` - Network identifier
    /// * `my_pk` - Sender's public key
    /// * `my_pow` - Sender's proof of work
    /// * `tx_key` - Optional session key for encryption
    /// * `recipient` - Recipient's public key
    /// * `time` - Timestamp for the message
    /// * `short_id` - Short ID for message routing
    ///
    /// # Returns
    /// Vector containing the complete HELLO message or an error
    #[allow(clippy::uninit_vec)]
    #[instrument(name = "HelloNodePeerMessage::build", skip_all)]
    pub fn build(
        network_id: &NetworkId,
        my_pk: &PubKey,
        my_pow: &Pow,
        tx_key: Option<&SessionKey>,
        recipient: &PubKey,
        time: u64,
        short_id: ShortId,
    ) -> Result<Vec<u8>, Error> {
        // buffer
        let buf_len =
            LONG_HEADER_LEN + HELLO_NODE_PEER_LEN + tx_key.is_some() as usize * ARM_HEADER_LEN;
        let mut buf = Vec::with_capacity(buf_len);
        unsafe { buf.set_len(buf.capacity()) };

        // long header
        let long_header = LongHeader::new(
            tx_key.is_some(),
            network_id,
            my_pk,
            my_pow,
            recipient,
            MessageType::HELLO,
        );
        long_header
            .write_to_prefix(&mut buf)
            .map_err(|e| Error::WriteLongHeaderFailed(e.to_string()))?;
        let body_slice = &mut buf[LONG_HEADER_LEN..];

        // body
        let hello = Self::new(time, short_id);
        log_hello_node_peer_message(&long_header, &hello);
        hello
            .write_to_suffix(body_slice)
            .map_err(|e| Error::WriteHelloNodePeerMessageFailed(e.to_string()))?;

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

/// Log a HELLO_NODE_PEER message for debugging purposes.
///
/// # Arguments
/// * `hdr` - The long header of the message
/// * `hello` - The HELLO_NODE_PEER message to log
#[inline]
pub fn log_hello_node_peer_message(hdr: &LongHeader, hello: &HelloNodePeerMessage) {
    trace!(
        r#type = %hdr.message_type,
        recipient = %hdr.recipient,
        sender = %hdr.sender,
        time = %hello.time,
        short_id = %hello.short_id,
    );
}

/// Log a HELLO_SUPER_PEER message for debugging purposes.
///
/// # Arguments
/// * `hdr` - The long header of the message
/// * `hello` - The HELLO_SUPER_PEER message to log
#[inline]
pub fn log_hello_super_peer_message(hdr: &LongHeader, hello: &HelloSuperPeerMessage) {
    trace!(
        r#type = %hdr.message_type,
        recipient = %hdr.recipient,
        sender = %hdr.sender,
        time = %hello.time,
        child_time = %hello.child_time,
        endpoints = %EndpointsList::from(&hello.endpoints),
    );
}
