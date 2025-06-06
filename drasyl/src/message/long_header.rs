use crate::crypto::ED25519_PUBLICKEYBYTES;
use crate::identity::{Pow, PubKey};
use crate::message::error::Error;
use std::convert::Into;
use std::fmt;
use std::fmt::{Display, Formatter};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
// long header
/// Size of magic number field in long header in bytes.
pub(crate) const LONG_HEADER_MAGIC_NUMBER_LEN: usize = 4;
/// Size of hop count field in long header in bytes.
pub(crate) const LONG_HEADER_HOP_COUNT_LEN: usize = 1;
/// Size of flags field in long header in bytes.
const LONG_HEADER_FLAGS_LEN: usize = 1;
/// Size of network ID field in long header in bytes.
pub(crate) const LONG_HEADER_NETWORK_ID_LEN: usize = 4;
/// Size of recipient public key field in long header in bytes.
const LONG_HEADER_RECIPIENT_LEN: usize = ED25519_PUBLICKEYBYTES;
/// Size of sender public key field in long header in bytes.
const LONG_HEADER_SENDER_LEN: usize = ED25519_PUBLICKEYBYTES;
/// Size of proof-of-work field in long header in bytes.
const LONG_HEADER_POW_LEN: usize = 4;
/// Size of message type field in long header in bytes.
const LONG_HEADER_MESSAGE_TYPE_LEN: usize = 1;
/// Total size of the complete long header in bytes.
pub const LONG_HEADER_LEN: usize = LONG_HEADER_MAGIC_NUMBER_LEN
    + LONG_HEADER_HOP_COUNT_LEN
    + LONG_HEADER_FLAGS_LEN
    + LONG_HEADER_NETWORK_ID_LEN
    + LONG_HEADER_RECIPIENT_LEN
    + LONG_HEADER_SENDER_LEN
    + LONG_HEADER_POW_LEN
    + LONG_HEADER_MESSAGE_TYPE_LEN;
/// Magic number constant for identifying drasyl protocol messages.
pub const LONG_HEADER_MAGIC_NUMBER: MagicNumber = MagicNumber(22527u32.pow(2).to_be_bytes());
/// Flag value indicating that the message payload is encrypted.
const LONG_HEADER_FLAGS_ARMED: u8 = 0x10u8;
/// Flag value indicating that the message payload is unencrypted.
const LONG_HEADER_FLAGS_UNARMED: u8 = 0x00u8;

/// Long header format for drasyl protocol messages.
///
/// The `LongHeader` represents the complete header format used in drasyl network messages.
/// It contains all routing information, security metadata, and protocol control data needed
/// for message transmission and processing in the peer-to-peer network.
///
/// # Purpose
///
/// The long header serves several critical functions:
/// * **Routing**: Contains sender and recipient public keys for message delivery
/// * **Security**: Includes proof-of-work and encryption flags for network protection
/// * **Protocol Control**: Specifies message type and network identification
/// * **Network Management**: Tracks hop count for routing and loop prevention
///
/// # Header Fields
///
/// * `magic_number` - Protocol identifier to distinguish drasyl messages (constant: 507,374,529)
/// * `hop_count` - Number of hops this message has traveled (starts at 0)
/// * `flags` - Control flags indicating message properties (bit 4: armed/encryption status)
/// * `network_id` - Network identifier to isolate different drasyl networks
/// * `recipient` - Public key of the intended message recipient
/// * `sender` - Public key of the message sender
/// * `pow` - Proof-of-work value demonstrating computational effort
/// * `message_type` - Type of message (ACK, APP, HELLO, UNITE)
///
/// # Wire Format
///
/// The header is laid out in network byte order (big-endian) with a total size of 75 bytes:
///
/// ```text
/// ┌─────────────────┬──────────────┬─────────────────────────────────────┐
/// │ Field           │ Size (bytes) │ Description                         │
/// ├─────────────────┼──────────────┼─────────────────────────────────────┤
/// │ magic_number    │ 4            │ Protocol identifier                 │
/// │ hop_count       │ 1            │ Number of routing hops              │
/// │ flags           │ 1            │ Control flags (encryption, etc.)    │
/// │ network_id      │ 4            │ Network isolation identifier        │
/// │ recipient       │ 32           │ Recipient's Ed25519 public key      │
/// │ sender          │ 32           │ Sender's Ed25519 public key         │
/// │ pow             │ 4            │ Proof-of-work nonce                 │
/// │ message_type    │ 1            │ Message type identifier             │
/// └─────────────────┴──────────────┴─────────────────────────────────────┘
/// ```
///
/// # Security Features
///
/// * **Proof-of-Work**: Prevents spam by requiring computational effort
/// * **Network Isolation**: Network ID prevents cross-network message delivery
/// * **Message Authentication**: Sender public key enables signature verification
/// * **Encryption Support**: Flags indicate whether message payload is encrypted
///
/// # Example
///
/// ```rust,ignore
/// use drasyl::message::{LongHeader, MessageType};
/// use drasyl::identity::{Identity, PoW};
///
/// // Parse a long header from received bytes
/// let mut buffer = received_message_bytes;
/// let (header, payload) = LongHeader::parse(&mut buffer)?;
///
/// // Check if message is encrypted
/// if header.is_armed() {
///     // Handle encrypted message
///     println!("Received encrypted {} from {}", header.message_type, header.sender);
/// } else {
///     // Handle unencrypted message
///     println!("Received unencrypted {} from {}", header.message_type, header.sender);
/// }
/// ```
///
/// # Protocol Compatibility
///
/// The long header format is designed for maximum compatibility and includes all
/// necessary information for routing messages through the drasyl network. For
/// established connections with cached routing information, a more compact
/// [`crate::message::ShortHeader`] format may be used instead.
#[repr(C, packed)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct LongHeader {
    pub magic_number: MagicNumber,
    pub hop_count: u8,
    pub flags: u8,
    pub network_id: NetworkId,
    pub recipient: PubKey,
    pub sender: PubKey,
    pub pow: Pow,
    pub message_type: MessageType,
}

impl LongHeader {
    pub fn parse(buf: &mut [u8]) -> Result<(&mut Self, &mut [u8]), Error> {
        match Self::mut_from_prefix(buf) {
            Ok((long_header, _)) if long_header.magic_number != LONG_HEADER_MAGIC_NUMBER => {
                Err(Error::MagicNumberInvalid(long_header.magic_number))
            }
            Ok((long_header, remainder)) => {
                if long_header.message_type == MessageType::ACK
                    || long_header.message_type == MessageType::APP
                    || long_header.message_type == MessageType::HELLO
                    || long_header.message_type == MessageType::UNITE
                {
                    Ok((long_header, remainder))
                } else {
                    Err(Error::MessageTypeInvalid(long_header.message_type.into()))
                }
            }
            Err(e) => Err(Error::LongHeaderConversionFailed(e.to_string())),
        }
    }

    pub fn is_armed(&self) -> bool {
        (self.flags & (1 << 4)) != 0 // Bit 4
    }

    pub(super) fn new(
        arm: bool,
        network_id: &NetworkId,
        my_pk: &PubKey,
        my_pow: &Pow,
        recipient: &PubKey,
        message_type: MessageType,
    ) -> Self {
        Self {
            magic_number: LONG_HEADER_MAGIC_NUMBER,
            hop_count: 0,
            flags: if arm {
                LONG_HEADER_FLAGS_ARMED
            } else {
                LONG_HEADER_FLAGS_UNARMED
            },
            network_id: *network_id,
            recipient: *recipient,
            sender: *my_pk,
            pow: *my_pow,
            message_type,
        }
    }

    pub(super) fn write_bytes<'a>(
        buf: &'a mut [u8],
        arm: bool,
        network_id: &NetworkId,
        my_pk: &PubKey,
        my_pow: &Pow,
        recipient: &PubKey,
        message_type: MessageType,
    ) -> Result<(&'a Self, &'a mut [u8]), Error> {
        let (long_header, remainder) = LongHeader::mut_from_prefix(buf)
            .map_err(|e| Error::WriteLongHeaderFailed(e.to_string()))?;
        long_header.magic_number = LONG_HEADER_MAGIC_NUMBER;
        long_header.hop_count = 0;
        long_header.flags = if arm {
            LONG_HEADER_FLAGS_ARMED
        } else {
            LONG_HEADER_FLAGS_UNARMED
        };
        long_header.network_id = *network_id;
        long_header.recipient = *recipient;
        long_header.sender = *my_pk;
        long_header.pow = *my_pow;
        long_header.message_type = message_type;

        Ok((long_header, remainder))
    }
}

impl fmt::Display for LongHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Long header:")?;
        writeln!(f, "├─ Magic number  : {}", self.magic_number)?;
        writeln!(f, "├─ Hop count     : {}", self.hop_count)?;
        writeln!(
            f,
            "├─ Flags         : {:08b} ({:#04x})",
            self.flags, self.flags
        )?;
        writeln!(f, "│  ├─ Armed      : {}", self.is_armed())?;
        writeln!(f, "│  └─ Reserved   : {:04b}", self.flags & 0b1111)?;
        writeln!(
            f,
            "├─ Network id    : {}",
            u32::from_be_bytes(self.network_id)
        )?;
        writeln!(f, "├─ Recipient     : {}", self.recipient)?;
        writeln!(f, "├─ Sender        : {}", self.sender)?;
        writeln!(f, "├─ PoW           : {}", self.pow)?;
        write!(f, "└─ Message type  : {}", self.message_type)?;
        Ok(())
    }
}

/// Message type identifier for drasyl protocol messages.
///
/// This structure represents the type of message being transmitted in the drasyl network.
/// Each message type corresponds to a specific protocol operation and determines how
/// the message should be processed by receiving peers.
///
/// # Protocol Message Types
///
/// The drasyl protocol defines four primary message types:
///
/// * **ACK** (`0`) - Acknowledgment messages for reliable delivery confirmation
/// * **APP** (`1`) - Application data messages containing user payload
/// * **HELLO** (`2`) - Peer discovery and handshake messages for connection establishment
/// * **UNITE** (`3`) - NAT traversal messages for direct peer-to-peer connection setup
///
/// # Wire Format
///
/// The message type is encoded as a single byte (u8) in the message header, allowing
/// for efficient parsing and minimal overhead. The current protocol reserves values
/// 0-3 for the defined message types, with values 4-255 reserved for future extensions.
///
/// # Example
///
/// ```rust
/// use drasyl::message::MessageType;
///
/// // Create message types for different protocol operations
/// let ack_type = MessageType::ACK;
/// let app_type = MessageType::APP;
/// let hello_type = MessageType::HELLO;
/// let unite_type = MessageType::UNITE;
///
/// // Convert to/from u8 for wire transmission
/// let type_byte: u8 = app_type.into();
/// let parsed_type = MessageType::try_from(type_byte)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Security Considerations
///
/// Message type validation is performed during parsing to ensure only valid
/// protocol messages are processed. Invalid message types are rejected to
/// prevent protocol confusion attacks.
#[allow(clippy::upper_case_acronyms)]
#[repr(transparent)]
#[derive(Debug, PartialEq, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct MessageType(pub u8);

impl MessageType {
    pub const ACK: Self = Self(0);
    pub const APP: Self = Self(1);
    pub const HELLO: Self = Self(2);
    pub const UNITE: Self = Self(3);
}

impl TryFrom<u8> for MessageType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value <= 3 {
            Ok(Self(value))
        } else {
            Err(Error::MessageTypeInvalid(value))
        }
    }
}

impl From<MessageType> for u8 {
    fn from(value: MessageType) -> u8 {
        value.0
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self.0 {
                0 => "ACK",
                1 => "APP",
                2 => "HELLO",
                3 => "UNITE",
                _ => "ERROR",
            }
        )
    }
}

/// Magic number type for identifying drasyl protocol messages in the header.
#[repr(transparent)]
#[derive(Debug, PartialEq, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct MagicNumber(pub [u8; LONG_HEADER_MAGIC_NUMBER_LEN]);

impl MagicNumber {
    /// Get the raw bytes of the magic number.
    pub fn as_bytes(&self) -> &[u8; LONG_HEADER_MAGIC_NUMBER_LEN] {
        &self.0
    }
}

impl From<[u8; 4]> for MagicNumber {
    fn from(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }
}

impl Display for MagicNumber {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", u32::from_be_bytes(self.0))
    }
}

/// Network identifier type for isolating different drasyl networks.
pub type NetworkId = [u8; LONG_HEADER_NETWORK_ID_LEN];
