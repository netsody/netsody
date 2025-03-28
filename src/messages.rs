use crate::utils::crypto::{
    AEGIS_ABYTES, AEGIS_KEYBYTES, AEGIS_NBYTES, ED25519_PUBLICKEYBYTES, random_bytes,
};
use crate::utils::hex::bytes_to_hex;
use crate::utils::net::{IPV4_LENGTH, IPV6_LENGTH};
use aegis::aegis256x2::Aegis256X2;
use log::{error, trace};
use std::array::TryFromSliceError;
use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use thiserror::Error;
use zerocopy::big_endian::{U16, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref, TryFromBytes};

// long header
pub(crate) const LONG_HEADER_MAGIC_NUMBER_LEN: usize = 4;
pub(crate) const LONG_HEADER_HOP_COUNT_LEN: usize = 1;
const LONG_HEADER_FLAGS_LEN: usize = 1;
pub(crate) const LONG_HEADER_NETWORK_ID_LEN: usize = 4;
const LONG_HEADER_RECIPIENT_LEN: usize = ED25519_PUBLICKEYBYTES;
const LONG_HEADER_SENDER_LEN: usize = ED25519_PUBLICKEYBYTES;
const LONG_HEADER_POW_LEN: usize = 4;
const LONG_HEADER_MESSAGE_TYPE_LEN: usize = 1;
pub(crate) const LONG_HEADER_LEN: usize = LONG_HEADER_MAGIC_NUMBER_LEN
    + LONG_HEADER_HOP_COUNT_LEN
    + LONG_HEADER_FLAGS_LEN
    + LONG_HEADER_NETWORK_ID_LEN
    + LONG_HEADER_RECIPIENT_LEN
    + LONG_HEADER_SENDER_LEN
    + LONG_HEADER_POW_LEN
    + LONG_HEADER_MESSAGE_TYPE_LEN;

pub(crate) const LONG_HEADER_MAGIC_NUMBER: [u8; LONG_HEADER_MAGIC_NUMBER_LEN] =
    22527u32.pow(2).to_be_bytes();
const LONG_HEADER_FLAGS_ARMED: u8 = 0x10u8;
const LONG_HEADER_FLAGS_UNARMED: u8 = 0x00u8;

// ACK body
const ACK_TIME_LEN: usize = 8;
const ACK_LEN: usize = ACK_TIME_LEN;

// HELLO body
const HELLO_TIME_LEN: usize = 8;
const HELLO_CHILD_TIME_LEN: usize = 8;
const HELLO_SHORT_ID_LEN: usize = 4;
pub(crate) const HELLO_ENDPOINT_LEN: usize = 2 + IPV6_LENGTH;
const HELLO_NODE_PEER_LEN: usize = HELLO_TIME_LEN + HELLO_SHORT_ID_LEN;
const HELLO_SUPER_PEER_MIN_LEN: usize = HELLO_TIME_LEN + HELLO_CHILD_TIME_LEN;
const HELLO_CHILD_TIME_SUPER_PEER: u64 = 1u64; // actual time not used; any non-zero value is accepted by super peers
pub(crate) const HELLO_MAX_ENDPOINTS: usize = 15;

// UNITE body
const UNITE_ADDRESS_LEN: usize = 32;
const UNITE_ENDPOINT_LEN: usize = 2 + IPV6_LENGTH;
const UNITE_MIN_LEN: usize = UNITE_ADDRESS_LEN + UNITE_ENDPOINT_LEN;
pub(crate) const UNITE_MAX_ENDPOINTS: usize = HELLO_MAX_ENDPOINTS + 1;

// short header
pub(crate) const SHORT_HEADER_ID_LEN: usize = 4;
pub(crate) const SHORT_ID_NONE: [u8; 4] = [0u8; 4];

pub const ARM_HEADER_LEN: usize = AEGIS_NBYTES + AEGIS_ABYTES;

#[derive(Debug, Error)]
pub enum MessageError {
    #[error("Packet too short to contain an APP: {0}")]
    AppMessageInvalid(String),

    #[error("Packet too short to contain a HELLO: {0}")]
    HelloMessageInvalid(String),

    #[error("Packet too short to contain a UNITE: {0}")]
    UniteMessageInvalid(String),

    #[error("Packet too short to contain an armed message")]
    ArmedMessageInvalid,

    #[error("Invalid magic number: {0:?}")]
    MagicNumberInvalid([u8; LONG_HEADER_MAGIC_NUMBER_LEN]),

    #[error("Invalid message type: {0}")]
    MessageTypeInvalid(u8),

    #[error("Disarming failed: body too short ({0} < {1} bytes)")]
    DisarmFailedTooShort(usize, usize),

    #[error("Time diff too large: {0} ms")]
    TimeDiffTooLarge(u64),

    #[error("Arming failed: body too short ({0} < {1} bytes)")]
    ArmFailedTooShort(usize, usize),

    #[error("Armed length invalid")]
    ArmedLengthInvalid,

    #[error("Agreement key conversion failed")]
    AgreementKeyConversionFailed,

    #[error("Invalid endpoint port")]
    EndpointPortInvalid,

    #[error("Invalid endpoint addr: {0}")]
    EndpointAddrInvalid(IpAddr),

    #[error("Public header conversion failed: {0}")]
    LongHeaderConversionFailed(String),

    #[error("Short header conversion failed: {0}")]
    ShortHeaderConversionFailed(String),

    #[error("Build ACK message failed: {0}")]
    BuildAckMessageFailed(String),

    #[error("Build long header failed: {0}")]
    WriteLongHeaderFailed(String),

    #[error("Build UNITE message failed: {0}")]
    BuildUniteMessageFailed(String),

    #[error("Write APP message failed: {0}")]
    WriteAppMessageFailed(String),

    #[error("Rx key for disarming not present")]
    RxKeyNotPresent,

    #[error("Tx key for arming not present")]
    TxKeyNotPresent,

    #[error("Build auth tag failed: {0}")]
    BuildAuthTagFailed(TryFromSliceError),

    #[error("ACK message conversion failed: {0}")]
    AckMessageConversionFailed(String),

    #[error("HELLO message conversion failed: {0}")]
    HelloMessageConversionFailed(String),

    #[error("Build HELLO_SUPER_PEER message failed")]
    BuildHelloSuperPeerMessageFailed,

    #[error("Write HELLO_NODE_PEER message failed: {0}")]
    WriteHelloNodePeerMessageFailed(String),

    #[error("Endpoint port conversion failed: {0}")]
    EndpointPortConversionFailed(String),

    #[error("Endpoint addr conversion failed: {0}")]
    EndpointAddrConversionFailed(String),

    #[error("Endpoint addr try from slice failed: {0}")]
    EndpointAddrTryFromSliceFailed(TryFromSliceError),

    #[error("Decrypt failed: {0}")]
    DecryptFailed(String),

    #[error("Encrypt failed: {0}")]
    EncryptFailed(String),

    #[error("Invalid child time in hello message")]
    HelloMessageInvalidChildTime,

    #[error("Invalid endpoints in hello message")]
    HelloMessageInvalidEndpoints,

    #[error("AEGISConversionError")]
    AEGISConversionError,
}

#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct ShortHeader {
    pub magic_number: [u8; LONG_HEADER_MAGIC_NUMBER_LEN],
    pub payload: [u8],
}

impl ShortHeader {
    pub(crate) fn parse<'a>(
        buf: &'a mut [u8],
        rx_key: Option<&[u8; AEGIS_KEYBYTES]>,
    ) -> Result<&'a [u8], MessageError> {
        if let Some(rx_key) = rx_key {
            let (ad, buf) = buf.split_at_mut(SHORT_HEADER_ID_LEN);
            disarm_message_body(buf, ad, rx_key)?;
            Ok(&buf[ARM_HEADER_LEN..])
        } else {
            Ok(&buf[SHORT_HEADER_ID_LEN..])
        }
    }

    pub fn build(
        short_id: [u8; 4],
        tx_key: Option<&[u8; AEGIS_KEYBYTES]>,
        payload: &[u8],
    ) -> Result<Vec<u8>, MessageError> {
        // buffer
        let buf_len =
            SHORT_HEADER_ID_LEN + payload.len() + tx_key.is_some() as usize * ARM_HEADER_LEN;
        let mut buf = Vec::with_capacity(buf_len);
        unsafe { buf.set_len(buf.capacity()) };

        buf[..SHORT_HEADER_ID_LEN].copy_from_slice(&short_id);
        if tx_key.is_some() {
            buf[SHORT_HEADER_ID_LEN + ARM_HEADER_LEN..].copy_from_slice(payload);
        } else {
            buf[SHORT_HEADER_ID_LEN..].copy_from_slice(payload);
        }

        if let Some(tx_key) = tx_key {
            let (ad, buf2) = buf.split_at_mut(SHORT_HEADER_ID_LEN);
            arm_message_body(buf2, ad, tx_key)?;
        }

        Ok(buf)
    }
}

#[repr(C, packed)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct LongHeader {
    pub magic_number: [u8; LONG_HEADER_MAGIC_NUMBER_LEN],
    pub hop_count: u8,
    pub flags: u8,
    pub network_id: [u8; LONG_HEADER_NETWORK_ID_LEN],
    pub recipient: [u8; LONG_HEADER_RECIPIENT_LEN],
    pub sender: [u8; LONG_HEADER_SENDER_LEN],
    pub pow: [u8; LONG_HEADER_POW_LEN],
    pub message_type: u8,
}

impl fmt::Display for LongHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Long header:")?;
        writeln!(
            f,
            "├─ Magic number  : {}",
            u32::from_be_bytes(self.magic_number)
        )?;
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
        writeln!(f, "├─ Recipient     : {}", bytes_to_hex(&self.recipient))?;
        writeln!(f, "├─ Sender        : {}", bytes_to_hex(&self.sender))?;
        writeln!(f, "├─ PoW           : {}", i32::from_be_bytes(self.pow))?;
        write!(
            f,
            "└─ Message type  : {}",
            match self.message_type.try_into() {
                Ok(MessageType::ACK) => "ACK",
                Ok(MessageType::APP) => "APP",
                Ok(MessageType::HELLO) => "HELLO",
                Ok(MessageType::UNITE) => "UNITE",
                Err(_) => "ERROR",
            }
        )?;
        Ok(())
    }
}

impl LongHeader {
    pub(crate) fn parse(buf: &mut [u8]) -> Result<(&mut Self, &mut [u8]), MessageError> {
        match Self::mut_from_prefix(buf) {
            Ok((long_header, _)) if long_header.magic_number != LONG_HEADER_MAGIC_NUMBER => {
                Err(MessageError::MagicNumberInvalid(long_header.magic_number))
            }
            Ok((long_header, remainder)) => {
                match <MessageType>::try_from(long_header.message_type) {
                    Ok(_) => Ok((long_header, remainder)),
                    Err(_) => Err(MessageError::MessageTypeInvalid(long_header.message_type)),
                }
            }
            Err(e) => Err(MessageError::LongHeaderConversionFailed(e.to_string())),
        }
    }

    pub fn is_armed(&self) -> bool {
        (self.flags & (1 << 4)) != 0 // Bit 4
    }

    fn new(
        arm: bool,
        network_id: &[u8; LONG_HEADER_NETWORK_ID_LEN],
        my_pk: &[u8; ED25519_PUBLICKEYBYTES],
        my_pow: &[u8; LONG_HEADER_POW_LEN],
        recipient: &[u8; ED25519_PUBLICKEYBYTES],
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
            message_type: message_type as u8,
        }
    }

    fn write_bytes<'a>(
        buf: &'a mut [u8],
        arm: bool,
        network_id: &[u8; LONG_HEADER_NETWORK_ID_LEN],
        my_pk: &[u8; ED25519_PUBLICKEYBYTES],
        my_pow: &[u8; LONG_HEADER_POW_LEN],
        recipient: &[u8; ED25519_PUBLICKEYBYTES],
        message_type: MessageType,
    ) -> Result<(&'a Self, &'a mut [u8]), MessageError> {
        let (long_header, remainder) = LongHeader::mut_from_prefix(buf)
            .map_err(|e| MessageError::WriteLongHeaderFailed(e.to_string()))?;
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
        long_header.message_type = message_type as u8;

        Ok((long_header, remainder))
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq)]
pub enum MessageType {
    ACK = 0,
    APP = 1,
    HELLO = 2,
    UNITE = 3,
}

impl TryFrom<u8> for MessageType {
    type Error = MessageError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ACK),
            1 => Ok(Self::APP),
            2 => Ok(Self::HELLO),
            3 => Ok(Self::UNITE),
            _ => Err(MessageError::MessageTypeInvalid(value)),
        }
    }
}

impl From<MessageType> for u8 {
    fn from(value: MessageType) -> u8 {
        match value {
            MessageType::ACK => 0,
            MessageType::APP => 1,
            MessageType::HELLO => 2,
            MessageType::UNITE => 3,
        }
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::ACK => "ACK",
                Self::APP => "APP",
                Self::HELLO => "HELLO",
                Self::UNITE => "UNITE",
            }
        )
    }
}

#[repr(C, packed)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct AckMessage {
    pub time: U64,
}

impl fmt::Display for AckMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ACK:")?;
        write!(f, "└─ Time : {} ms", self.time / 1000)
    }
}

impl AckMessage {
    pub(crate) fn parse<'a>(
        buf: &'a mut [u8],
        long_header: &'a LongHeader,
        rx_key: Option<&[u8; AEGIS_KEYBYTES]>,
    ) -> Result<&'a Self, MessageError> {
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
                return Err(MessageError::RxKeyNotPresent);
            }
        } else {
            buf
        };

        match Self::ref_from_prefix(buf) {
            Ok((ack, _)) => Ok(ack),
            Err(e) => Err(MessageError::AckMessageConversionFailed(e.to_string())),
        }
    }

    pub fn build(
        buf: &mut [u8],
        network_id: &[u8; LONG_HEADER_NETWORK_ID_LEN],
        my_pk: &[u8; ED25519_PUBLICKEYBYTES],
        my_pow: &[u8; LONG_HEADER_POW_LEN],
        tx_key: Option<&[u8; AEGIS_KEYBYTES]>,
        recipient: &[u8; ED25519_PUBLICKEYBYTES],
        time: u64,
    ) -> Result<usize, MessageError> {
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
        trace!("> {}", long_header);
        long_header
            .write_to_prefix(buf)
            .map_err(|e| MessageError::WriteLongHeaderFailed(e.to_string()))?;
        let body_slice = &mut buf[LONG_HEADER_LEN..];

        // body
        let ack = Self::mut_from_bytes(if tx_key.is_some() {
            &mut body_slice[ARM_HEADER_LEN..]
        } else {
            body_slice
        })
        .map_err(|e| MessageError::BuildAckMessageFailed(e.to_string()))?;
        ack.time = time.into();
        trace!("> {}", ack);

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
                return Err(MessageError::TxKeyNotPresent);
            }
        }

        Ok(buf_len)
    }
}

#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct AppMessage {
    pub payload: [u8],
}

impl fmt::Display for AppMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "APP:")?;
        write!(f, "└─ Payload length: {} bytes", self.payload.len())
    }
}

impl AppMessage {
    pub(crate) fn parse<'a>(
        buf: &'a mut [u8],
        long_header: &'a LongHeader,
        rx_key: Option<&[u8; AEGIS_KEYBYTES]>,
    ) -> Result<Ref<&'a [u8], Self>, MessageError> {
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
                return Err(MessageError::RxKeyNotPresent);
            }
        } else {
            buf
        };

        let app: Ref<&'a [u8], Self> =
            Ref::from_bytes(buf).map_err(|e| MessageError::AppMessageInvalid(e.to_string()))?;

        Ok(app)
    }

    pub fn build(
        network_id: &[u8; LONG_HEADER_NETWORK_ID_LEN],
        my_pk: &[u8; ED25519_PUBLICKEYBYTES],
        my_pow: &[u8; LONG_HEADER_POW_LEN],
        tx_key: Option<&[u8; AEGIS_KEYBYTES]>,
        recipient: &[u8; LONG_HEADER_RECIPIENT_LEN],
        payload: &[u8],
    ) -> Result<Vec<u8>, MessageError> {
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
        trace!("> {}", long_header);
        long_header
            .write_to_prefix(&mut buf)
            .map_err(|e| MessageError::WriteLongHeaderFailed(e.to_string()))?;
        let body_slice = &mut buf[LONG_HEADER_LEN..];

        // body
        let app = Self::mut_from_bytes(if tx_key.is_some() {
            &mut body_slice[ARM_HEADER_LEN..]
        } else {
            body_slice
        })
        .map_err(|e| MessageError::WriteAppMessageFailed(e.to_string()))?;
        app.payload[..payload.len()].copy_from_slice(payload);
        trace!("> {}", app);

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
                return Err(MessageError::TxKeyNotPresent);
            }
        }

        Ok(buf)
    }
}

pub struct EndpointsList(pub(crate) HashSet<SocketAddr>);

impl From<EndpointsList> for Vec<u8> {
    fn from(from: EndpointsList) -> Vec<u8> {
        let mut w_idx = 0;
        let mut buf = Vec::with_capacity(from.0.len() * HELLO_ENDPOINT_LEN);
        #[allow(clippy::uninit_vec)]
        unsafe {
            buf.set_len(buf.capacity());
        };
        for endpoint in &from.0 {
            let endpoint: Endpoint = endpoint.into();
            endpoint.to_bytes(&mut buf[w_idx..][..HELLO_ENDPOINT_LEN]);
            w_idx += HELLO_ENDPOINT_LEN;
        }
        buf
    }
}

impl From<&[u8]> for EndpointsList {
    fn from(buf: &[u8]) -> Self {
        let mut r_idx = 0;
        let mut endpoints = HashSet::with_capacity(HELLO_MAX_ENDPOINTS);
        while r_idx + HELLO_ENDPOINT_LEN <= buf.len() {
            if let Ok(endpoint) = Endpoint::try_from(&buf[r_idx..]) {
                endpoints.insert(endpoint.into());
            };
            r_idx += HELLO_ENDPOINT_LEN;
        }
        EndpointsList(endpoints)
    }
}

#[repr(C, packed)]
#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable)]
struct EndpointPort(U16);

impl EndpointPort {
    fn parse(buf: &[u8]) -> Result<&Self, MessageError> {
        let (port, _) = EndpointPort::try_ref_from_prefix(buf)
            .map_err(|e| MessageError::EndpointPortConversionFailed(e.to_string()))?;
        if port.0 == 0 {
            return Err(MessageError::EndpointPortInvalid);
        }

        Ok(port)
    }
}

#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
struct EndpointAddr([u8; IPV6_LENGTH]);

impl EndpointAddr {
    fn parse(buf: &[u8]) -> Result<&Self, MessageError> {
        let (addr, _) = EndpointAddr::try_ref_from_prefix(buf)
            .map_err(|e| MessageError::EndpointAddrConversionFailed(e.to_string()))?;
        Ok(addr)
    }

    fn ip_addr(&self) -> Result<IpAddr, MessageError> {
        let buf = self.as_bytes();
        let ip_addr = if buf[..10] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0] && buf[10..12] == [0xff, 0xff]
        {
            // Extract IPv4 bytes and convert to IPv4 address
            IpAddr::V4(std::net::Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]))
        } else {
            // Convert slice to array and create IPv6 address
            let bytes: [u8; IPV6_LENGTH] = buf[..IPV6_LENGTH]
                .try_into()
                .map_err(MessageError::EndpointAddrTryFromSliceFailed)?;
            IpAddr::V6(Ipv6Addr::from(bytes))
        };

        // ignore invalid addresses
        // 0.0.0.0 or ::
        // 224.0.0.0/4 or ff00::/8
        if ip_addr.is_unspecified() || ip_addr.is_multicast() {
            return Err(MessageError::EndpointAddrInvalid(ip_addr));
        }

        Ok(ip_addr)
    }

    fn set_ip_addr(&mut self, ip_addr: IpAddr) {
        match ip_addr {
            IpAddr::V6(ipv6) => {
                self.0.copy_from_slice(&ipv6.octets());
            }
            IpAddr::V4(ipv4) => {
                // convert to ipv6 mapped ipv4 (::ffff:0:0/96)
                self.0[..10].fill(0); // set first 10 bytes to 0
                self.0[10] = 0xff;
                self.0[11] = 0xff;
                // copy IPv4 address into the last 4 bytes
                self.0[IPV6_LENGTH - IPV4_LENGTH..IPV6_LENGTH].copy_from_slice(&ipv4.octets());
            }
        }
    }
}

#[derive(Debug)]
pub struct Endpoint {
    port: u16,
    addr: IpAddr,
}

impl Endpoint {
    pub fn to_bytes(&self, buf: &mut [u8]) {
        // port
        let (port, remainder) = EndpointPort::try_mut_from_prefix(&mut buf[0..])
            .map_err(|e| MessageError::EndpointPortConversionFailed(e.to_string()))
            .unwrap();
        port.0 = self.port.into();

        // address
        let (address, _) = EndpointAddr::try_mut_from_prefix(remainder)
            .map_err(|e| MessageError::EndpointAddrConversionFailed(e.to_string()))
            .unwrap();
        address.set_ip_addr(self.addr);
    }
}

impl TryFrom<&[u8]> for Endpoint {
    type Error = MessageError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        // port
        let port = EndpointPort::parse(buf)?;

        // addr
        let addr = EndpointAddr::parse(&buf[2..])?;

        Ok(Endpoint {
            port: port.0.into(),
            addr: addr.ip_addr()?,
        })
    }
}

impl From<&SocketAddr> for Endpoint {
    fn from(addr: &SocketAddr) -> Endpoint {
        Endpoint {
            addr: addr.ip(),
            port: addr.port(),
        }
    }
}

impl From<Endpoint> for SocketAddr {
    fn from(addr: Endpoint) -> SocketAddr {
        SocketAddr::new(addr.addr, addr.port)
    }
}

#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct HelloSuperPeerMessage {
    pub time: U64,
    pub child_time: U64,
    pub endpoints: [u8],
}

impl fmt::Display for HelloSuperPeerMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "HELLO_SUPER_PEER:")?;
        writeln!(f, "├─ Time       : {} ms", self.time / 1000)?;
        writeln!(f, "├─ Child time : {} ms", self.child_time / 1000)?;
        writeln!(f, "└─ Endpoints  :")?;
        let endpoints: HashSet<SocketAddr> =
            <&[u8] as Into<EndpointsList>>::into(&self.endpoints).0;
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
    pub(crate) fn parse<'a>(
        buf: &'a mut [u8],
        long_header: &'a LongHeader,
        rx_key: Option<&[u8; AEGIS_KEYBYTES]>,
    ) -> Result<Ref<&'a [u8], Self>, MessageError> {
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
                return Err(MessageError::RxKeyNotPresent);
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

        let hello: Ref<&'a [u8], Self> =
            Ref::from_bytes(buf).map_err(|e| MessageError::HelloMessageInvalid(e.to_string()))?;

        if hello.child_time == 0 {
            return Err(MessageError::HelloMessageInvalidChildTime);
        }

        if (hello.endpoints.len() % HELLO_ENDPOINT_LEN) != 0 {
            return Err(MessageError::HelloMessageInvalidEndpoints);
        }

        Ok(hello)
    }

    pub fn build(
        network_id: &[u8; LONG_HEADER_NETWORK_ID_LEN],
        my_pk: &[u8; ED25519_PUBLICKEYBYTES],
        my_pow: &[u8; LONG_HEADER_POW_LEN],
        tx_key: Option<&[u8; AEGIS_KEYBYTES]>,
        recipient: &[u8; ED25519_PUBLICKEYBYTES],
        time: u64,
        endpoints: &[u8],
    ) -> Result<Vec<u8>, MessageError> {
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
        trace!("> {}", long_header);
        long_header
            .write_to_prefix(&mut buf)
            .map_err(|e| MessageError::WriteLongHeaderFailed(e.to_string()))?;
        let body_slice = &mut buf[LONG_HEADER_LEN..];

        // body
        let hello = Self::mut_from_bytes(if tx_key.is_some() {
            &mut body_slice[ARM_HEADER_LEN..]
        } else {
            body_slice
        })
        .map_err(|_| MessageError::BuildHelloSuperPeerMessageFailed)?;
        hello.time = time.into();
        hello.child_time = HELLO_CHILD_TIME_SUPER_PEER.into();
        hello.endpoints.copy_from_slice(endpoints);
        trace!("> {}", hello);

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
                return Err(MessageError::TxKeyNotPresent);
            }
        }

        Ok(buf)
    }
}

#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct HelloNodePeerMessage {
    pub time: U64,
    pub short_id: [u8; 4],
}

impl fmt::Display for HelloNodePeerMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "HELLO_NODE_PEER:")?;
        writeln!(f, "└─ Time       : {} ms", self.time / 1000)?;
        writeln!(f, "└─ Short id   : {:?}", self.short_id)?;
        Ok(())
    }
}

impl HelloNodePeerMessage {
    fn new(time: u64, short_id: [u8; 4]) -> Self {
        Self {
            time: time.into(),
            short_id,
        }
    }

    pub(crate) fn parse<'a>(
        buf: &'a mut [u8],
        long_header: &'a LongHeader,
        rx_key: Option<&[u8; AEGIS_KEYBYTES]>,
    ) -> Result<&'a HelloNodePeerMessage, MessageError> {
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
                return Err(MessageError::RxKeyNotPresent);
            }
        } else {
            buf
        };

        match Self::ref_from_prefix(buf) {
            Ok((hello, _)) => Ok(hello),
            Err(e) => Err(MessageError::HelloMessageConversionFailed(e.to_string())),
        }
    }

    pub fn build(
        network_id: &[u8; LONG_HEADER_NETWORK_ID_LEN],
        my_pk: &[u8; ED25519_PUBLICKEYBYTES],
        my_pow: &[u8; LONG_HEADER_POW_LEN],
        tx_key: Option<&[u8; AEGIS_KEYBYTES]>,
        recipient: &[u8; ED25519_PUBLICKEYBYTES],
        time: u64,
        short_id: [u8; 4],
    ) -> Result<Vec<u8>, MessageError> {
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
        trace!("> {}", long_header);
        long_header
            .write_to_prefix(&mut buf)
            .map_err(|e| MessageError::WriteLongHeaderFailed(e.to_string()))?;
        let body_slice = &mut buf[LONG_HEADER_LEN..];

        // body
        let hello = Self::new(time, short_id);
        trace!("> {}", hello);
        hello
            .write_to_suffix(body_slice)
            .map_err(|e| MessageError::WriteHelloNodePeerMessageFailed(e.to_string()))?;

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
                return Err(MessageError::TxKeyNotPresent);
            }
        }

        Ok(buf)
    }
}

#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct UniteMessage {
    pub address: [u8; UNITE_ADDRESS_LEN],
    pub endpoints: [u8],
}

impl fmt::Display for UniteMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "UNITE:")?;
        writeln!(f, "├─ Address   : {}", bytes_to_hex(&self.address))?;
        writeln!(f, "└─ Endpoints  :")?;
        let endpoints: HashSet<SocketAddr> =
            <&[u8] as Into<EndpointsList>>::into(&self.endpoints).0;
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

impl UniteMessage {
    pub(crate) fn parse<'a>(
        buf: &'a mut [u8],
        long_header: &'a LongHeader,
        rx_key: Option<&[u8; AEGIS_KEYBYTES]>,
    ) -> Result<Ref<&'a [u8], Self>, MessageError> {
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
                return Err(MessageError::RxKeyNotPresent);
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

        let unite: Ref<&'a [u8], Self> =
            Ref::from_bytes(buf).map_err(|e| MessageError::UniteMessageInvalid(e.to_string()))?;

        Ok(unite)
    }

    pub fn build(
        network_id: &[u8; LONG_HEADER_NETWORK_ID_LEN],
        my_pk: &[u8; ED25519_PUBLICKEYBYTES],
        my_pow: &[u8; LONG_HEADER_POW_LEN],
        tx_key: Option<&[u8; AEGIS_KEYBYTES]>,
        recipient: &[u8; LONG_HEADER_RECIPIENT_LEN],
        address: &[u8; UNITE_ADDRESS_LEN],
        endpoints: &[u8],
    ) -> Result<Vec<u8>, MessageError> {
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
        trace!("> {}", long_header);

        // body
        let unite = Self::mut_from_bytes(if tx_key.is_some() {
            &mut body_slice[ARM_HEADER_LEN..]
        } else {
            body_slice
        })
        .map_err(|e| MessageError::BuildUniteMessageFailed(e.to_string()))?;
        unite.address = *address;
        unite.endpoints.copy_from_slice(endpoints);
        trace!("> {}", unite);

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
                return Err(MessageError::TxKeyNotPresent);
            }
        }

        Ok(buf)
    }
}

pub(crate) fn arm_message_body(
    buf: &mut [u8],
    ad: &[u8],
    tx_key: &[u8; AEGIS_KEYBYTES],
) -> Result<(), MessageError> {
    let min_len = ARM_HEADER_LEN;
    if buf.len() < min_len {
        return Err(MessageError::ArmFailedTooShort(buf.len(), min_len));
    }

    // split buf
    let (nonce, remainder) = buf.split_at_mut(AEGIS_NBYTES);
    let (tag_slice, mc) = remainder.split_at_mut(AEGIS_ABYTES);
    let nonce: &mut [u8; AEGIS_NBYTES] = nonce.try_into().unwrap();
    let tag_slice: &mut [u8; AEGIS_ABYTES] = tag_slice.try_into().unwrap();

    // nonce
    random_bytes(nonce);

    let state = Aegis256X2::<AEGIS_ABYTES>::new(nonce, tx_key);
    let tag = state.encrypt_in_place(mc, ad);
    tag_slice.copy_from_slice(&tag);

    Ok(())
}

pub(crate) fn disarm_message_body(
    buf: &mut [u8],
    ad: &[u8],
    rx_key: &[u8; AEGIS_KEYBYTES],
) -> Result<(), MessageError> {
    let min_len = ARM_HEADER_LEN;
    if buf.len() < min_len {
        return Err(MessageError::DisarmFailedTooShort(buf.len(), min_len));
    }

    // split buf
    let (nonce, remainder) = buf.split_at_mut(AEGIS_NBYTES);
    let (tag_slice, mc) = remainder.split_at_mut(AEGIS_ABYTES);
    let nonce: &mut [u8; AEGIS_NBYTES] = nonce.try_into().unwrap();
    let tag: &mut [u8; AEGIS_ABYTES] = tag_slice.try_into().unwrap();

    let state = Aegis256X2::<AEGIS_ABYTES>::new(nonce, rx_key);
    state
        .decrypt_in_place(mc, tag, ad)
        .map_err(|e| MessageError::DecryptFailed(e.to_string()))?;

    Ok(())
}
