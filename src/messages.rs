use crate::utils::crypto::{
    CryptoError, ED25519_PUBLICKEYBYTES, SESSIONKEYBYTES, SIGN_BYTES,
    XCHACHA20POLY1305_IETF_ABYTES, XCHACHA20POLY1305_IETF_NPUBBYTES, decrypt, encrypt,
    random_bytes,
};
use crate::utils::hex::bytes_to_hex;
use crate::utils::net::{IPV4_LENGTH, IPV6_LENGTH};
use crate::utils::rand::pseudorandom_bytes;
use log::trace;
use std::array::TryFromSliceError;
use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use thiserror::Error;
use zerocopy::big_endian::{U16, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref, TryFromBytes};

// public header
pub(crate) const PUBLIC_HEADER_MAGIC_NUMBER_LEN: usize = 4;
const PUBLIC_HEADER_FLAGS_LEN: usize = 1;
pub(crate) const PUBLIC_HEADER_NETWORK_ID_LEN: usize = 4;
pub const PUBLIC_HEADER_NONCE_LEN: usize = XCHACHA20POLY1305_IETF_NPUBBYTES;
const PUBLIC_HEADER_RECIPIENT_LEN: usize = ED25519_PUBLICKEYBYTES;
const PUBLIC_HEADER_SENDER_LEN: usize = ED25519_PUBLICKEYBYTES;
const PUBLIC_HEADER_POW_LEN: usize = 4;
pub(crate) const PUBLIC_HEADER_LEN: usize = PUBLIC_HEADER_MAGIC_NUMBER_LEN
    + PUBLIC_HEADER_FLAGS_LEN
    + PUBLIC_HEADER_NETWORK_ID_LEN
    + PUBLIC_HEADER_NONCE_LEN
    + PUBLIC_HEADER_RECIPIENT_LEN
    + PUBLIC_HEADER_SENDER_LEN
    + PUBLIC_HEADER_POW_LEN;

const PUBLIC_HEADER_MAGIC_NUMBER: [u8; PUBLIC_HEADER_MAGIC_NUMBER_LEN] =
    22527u32.pow(2).to_be_bytes();
const PUBLIC_HEADER_NONCE_ZERO_HOP_COUNT_ARMED_FLAGS: u8 = 0x10u8;
const PUBLIC_HEADER_NONCE_ZERO_HOP_COUNT_UNARMED_FLAGS: u8 = 0x00u8;

// private header
const PRIVATE_HEADER_MESSAGE_TYPE_LEN: usize = 1;
const PRIVATE_HEADER_ARMED_LENGTH_LEN: usize = 2;
const PRIVATE_HEADER_AUTHENTICATION_HEADER_LEN: usize = XCHACHA20POLY1305_IETF_ABYTES;
pub(crate) const PRIVATE_HEADER_UNARMED_LEN: usize =
    PRIVATE_HEADER_MESSAGE_TYPE_LEN + PRIVATE_HEADER_ARMED_LENGTH_LEN;
pub(crate) const PRIVATE_HEADER_ARMED_LEN: usize =
    PRIVATE_HEADER_UNARMED_LEN + PRIVATE_HEADER_AUTHENTICATION_HEADER_LEN;

// ACK body
const ACK_TIME_LEN: usize = 8;
const ACK_LEN: usize = ACK_TIME_LEN;

// HELLO body
const HELLO_TIME_LEN: usize = 8;
const HELLO_CHILD_TIME_LEN: usize = 8;
const HELLO_SIGNATURE_LEN: usize = SIGN_BYTES;
pub(crate) const HELLO_ENDPOINT_LEN: usize = 2 + IPV6_LENGTH;
const HELLO_UNSIGNED_LEN: usize = HELLO_TIME_LEN + HELLO_CHILD_TIME_LEN;
const HELLO_SIGNED_MIN_LEN: usize = HELLO_UNSIGNED_LEN + HELLO_SIGNATURE_LEN;
const HELLO_CHILD_TIME_SUPER_PEER: u64 = 1u64; // actual time not used; any non-zero value is accepted by super peers
pub(crate) const HELLO_MAX_ENDPOINTS: usize = 15;

// UNITE body
const UNITE_ADDRESS_LEN: usize = 32;
const UNITE_ENDPOINT_LEN: usize = 2 + IPV6_LENGTH;
const UNITE_MIN_LEN: usize = UNITE_ADDRESS_LEN + UNITE_ENDPOINT_LEN;
pub(crate) const UNITE_MAX_ENDPOINTS: usize = HELLO_MAX_ENDPOINTS + 1;

#[derive(Debug, Error)]
pub enum MessageError {
    #[error("Packet too short to contain an ACK")]
    AckMessageInvalid,

    #[error("Packet too short to contain an APP")]
    AppMessageInvalid,

    #[error("Packet too short to contain a HELLO")]
    HelloMessageInvalid,

    #[error("Packet too short to contain a UNITE")]
    UniteMessageInvalid,

    #[error("Packet too short to contain an armed message")]
    ArmedMessageInvalid,

    #[error("Invalid magic number: {0:?}")]
    MagicNumberInvalid([u8; PUBLIC_HEADER_MAGIC_NUMBER_LEN]),

    #[error("Invalid message type: {0}")]
    MessageTypeInvalid(u8),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(#[from] CryptoError),

    #[error("Time diff too large: {0} ms")]
    TimeDiffTooLarge(u64),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(CryptoError),

    #[error("Armed length invalid")]
    ArmedLengthInvalid,

    #[error("Agreement key conversion failed")]
    AgreementKeyConversionFailed,

    #[error("Invalid endpoint port")]
    EndpointPortInvalid,

    #[error("Invalid endpoint addr: {0}")]
    EndpointAddrInvalid(IpAddr),

    #[error("Public header conversion failed: {0}")]
    PublicHeaderConversionFailed(String),

    #[error("Private header conversion failed: {0}")]
    PrivateHeaderConversionFailed(String),

    #[error("Build ACK message failed")]
    BuildAckMessageFailed,

    #[error("Build public header failed")]
    BuildPublicHeaderFailed,

    #[error("Build private header failed")]
    BuildPrivateHeaderFailed,

    #[error("Build UNITE message failed")]
    BuildUniteMessageFailed,

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

    #[error("Build HELLO message failed")]
    BuildHelloMessageFailed,

    #[error("Endpoint port conversion failed: {0}")]
    EndpointPortConversionFailed(String),

    #[error("Endpoint addr conversion failed: {0}")]
    EndpointAddrConversionFailed(String),

    #[error("Endpoint addr try from slice failed: {0}")]
    EndpointAddrTryFromSliceFailed(TryFromSliceError),
}

#[repr(C, packed)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct PublicHeader {
    pub magic_number: [u8; PUBLIC_HEADER_MAGIC_NUMBER_LEN],
    pub flags: u8,
    pub network_id: [u8; PUBLIC_HEADER_NETWORK_ID_LEN],
    pub nonce: [u8; PUBLIC_HEADER_NONCE_LEN],
    pub recipient: [u8; PUBLIC_HEADER_RECIPIENT_LEN],
    pub sender: [u8; PUBLIC_HEADER_SENDER_LEN],
    pub pow: [u8; PUBLIC_HEADER_POW_LEN],
}

impl fmt::Display for PublicHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Public header:")?;
        writeln!(
            f,
            "├─ Magic number  : {}",
            u32::from_be_bytes(self.magic_number)
        )?;
        writeln!(
            f,
            "├─ Flags         : {:08b} ({:#04x})",
            self.flags, self.flags
        )?;
        writeln!(f, "│  ├─ Hop count  : {}", self.hop_count())?;
        writeln!(f, "│  ├─ Armed      : {}", self.is_armed())?;
        writeln!(f, "│  └─ Reserved   : {:04b}", self.flags & 0b1111)?;
        writeln!(
            f,
            "├─ Network id    : {}",
            u32::from_be_bytes(self.network_id)
        )?;
        writeln!(f, "├─ Nonce         : {}", bytes_to_hex(&self.nonce))?;
        writeln!(f, "├─ Recipient     : {}", bytes_to_hex(&self.recipient))?;
        writeln!(f, "├─ Sender        : {}", bytes_to_hex(&self.sender))?;
        write!(f, "└─ PoW           : {}", i32::from_be_bytes(self.pow))?;
        Ok(())
    }
}

impl PublicHeader {
    pub(crate) fn parse(buf: &mut [u8]) -> Result<(&mut Self, &mut [u8]), MessageError> {
        match Self::mut_from_prefix(buf) {
            Ok((public_header, _)) if public_header.magic_number != PUBLIC_HEADER_MAGIC_NUMBER => {
                Err(MessageError::MagicNumberInvalid(public_header.magic_number))
            }
            Ok((public_header, remainder)) => Ok((public_header, remainder)),
            Err(e) => Err(MessageError::PublicHeaderConversionFailed(e.to_string())),
        }
    }

    pub fn is_armed(&self) -> bool {
        (self.flags & (1 << 4)) != 0 // Bit 4
    }

    pub fn hop_count(&self) -> u8 {
        (self.flags >> 5) & 0b111 // Most significant bits (5-7)
    }

    pub(crate) fn increment_hop_count(&mut self) {
        let incremented_hop_count = self.hop_count() + 1u8;
        self.flags = (self.flags & 0b00011111) | (incremented_hop_count << 5);
    }

    fn write_bytes<'a>(
        buf: &'a mut [u8],
        arm: bool,
        network_id: &[u8; PUBLIC_HEADER_NETWORK_ID_LEN],
        my_pk: &[u8; ED25519_PUBLICKEYBYTES],
        my_pow: &[u8; PUBLIC_HEADER_POW_LEN],
        recipient: &[u8; ED25519_PUBLICKEYBYTES],
    ) -> Result<(&'a Self, &'a mut [u8]), MessageError> {
        let (public_header, remainder) = PublicHeader::mut_from_prefix(buf)
            .map_err(|_| MessageError::BuildPublicHeaderFailed)?;
        public_header.magic_number = PUBLIC_HEADER_MAGIC_NUMBER;
        public_header.flags = if arm {
            PUBLIC_HEADER_NONCE_ZERO_HOP_COUNT_ARMED_FLAGS
        } else {
            PUBLIC_HEADER_NONCE_ZERO_HOP_COUNT_UNARMED_FLAGS
        };
        public_header.network_id = *network_id;
        if arm {
            random_bytes(public_header.nonce.as_mut());
        } else {
            pseudorandom_bytes(public_header.nonce.as_mut());
        }
        public_header.recipient = *recipient;
        public_header.sender = *my_pk;
        public_header.pow = *my_pow;

        Ok((public_header, remainder))
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
pub struct PrivateHeader {
    pub message_type: u8,
    pub armed_len: U16,
}

impl fmt::Display for PrivateHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Private header:")?;
        writeln!(
            f,
            "├─ Message type : {}",
            match self.message_type.try_into() {
                Ok(MessageType::ACK) => "ACK",
                Ok(MessageType::APP) => "APP",
                Ok(MessageType::HELLO) => "HELLO",
                Ok(MessageType::UNITE) => "UNITE",
                Err(_) => "ERROR",
            }
        )?;
        let armed_len = self.armed_len;
        write!(f, "└─ Armed length : {armed_len} bytes")
    }
}

impl PrivateHeader {
    pub(crate) fn parse<'a>(
        buf: &'a mut [u8],
        public_header: &'a PublicHeader,
        rx_key: Option<&[u8; SESSIONKEYBYTES]>,
    ) -> Result<(&'a Self, &'a mut [u8]), MessageError> {
        let is_armed = public_header.is_armed();
        if is_armed {
            // disarm private header
            if let Some(rx_key) = rx_key {
                Self::disarm(buf, public_header, rx_key)?;
            } else {
                return Err(MessageError::RxKeyNotPresent);
            }
        }

        match Self::mut_from_prefix(buf) {
            Ok((private_header, remainder)) => {
                match <MessageType>::try_from(private_header.message_type) {
                    Ok(_) => {
                        if is_armed {
                            let armed_len = private_header.armed_len.get() as usize;
                            if armed_len > remainder.len() {
                                return Err(MessageError::ArmedLengthInvalid);
                            }
                        }

                        Ok((
                            private_header,
                            if is_armed {
                                &mut remainder[PRIVATE_HEADER_AUTHENTICATION_HEADER_LEN..]
                            } else {
                                remainder
                            },
                        ))
                    }
                    Err(_) => Err(MessageError::MessageTypeInvalid(
                        private_header.message_type,
                    )),
                }
            }
            Err(e) => Err(MessageError::PrivateHeaderConversionFailed(e.to_string())),
        }
    }

    fn disarm(
        buf: &mut [u8],
        public_header: &PublicHeader,
        rx_key: &[u8; SESSIONKEYBYTES],
    ) -> Result<(), MessageError> {
        if buf.len() < PRIVATE_HEADER_ARMED_LEN {
            return Err(MessageError::ArmedMessageInvalid);
        }

        let auth_tag = if public_header.flags == PUBLIC_HEADER_NONCE_ZERO_HOP_COUNT_ARMED_FLAGS {
            // no need to build auth tag
            &public_header.as_bytes()[PUBLIC_HEADER_MAGIC_NUMBER_LEN..]
        } else {
            &build_auth_tag(
                public_header
                    .as_bytes()
                    .try_into()
                    .map_err(MessageError::BuildAuthTagFailed)?,
            )
        };

        let private_header_slice = &mut buf[..PRIVATE_HEADER_ARMED_LEN];

        let decrypted_header =
            decrypt(private_header_slice, auth_tag, &public_header.nonce, rx_key)
                .map_err(MessageError::DecryptionFailed)?;

        // Overwrite the encrypted header with the decrypted header
        private_header_slice[..PRIVATE_HEADER_UNARMED_LEN].copy_from_slice(&decrypted_header);

        Ok(())
    }

    fn write_bytes<'a>(
        buf: &'a mut [u8],
        message_type: MessageType,
        armed_len: u16,
        public_header: &'a PublicHeader,
        tx_key: Option<&[u8; SESSIONKEYBYTES]>,
    ) -> Result<&'a mut [u8], MessageError> {
        let (private_header, _) = PrivateHeader::mut_from_prefix(buf)
            .map_err(|_| MessageError::BuildPrivateHeaderFailed)?;
        private_header.message_type = message_type as u8;
        private_header.armed_len = armed_len.into();
        trace!("{}", private_header);

        if public_header.is_armed() {
            // arm private header
            if let Some(tx_key) = tx_key {
                PrivateHeader::arm(buf, public_header, tx_key)?;
            } else {
                return Err(MessageError::TxKeyNotPresent);
            }

            Ok(&mut buf[PRIVATE_HEADER_ARMED_LEN..])
        } else {
            Ok(&mut buf[PRIVATE_HEADER_UNARMED_LEN..])
        }
    }

    fn arm(
        buf: &mut [u8],
        public_header: &PublicHeader,
        tx_key: &[u8; SESSIONKEYBYTES],
    ) -> Result<(), MessageError> {
        let auth_tag = &public_header.as_bytes()[PUBLIC_HEADER_MAGIC_NUMBER_LEN..];

        let encrypted_header = encrypt(
            &buf[..PRIVATE_HEADER_UNARMED_LEN],
            auth_tag,
            &public_header.nonce,
            tx_key,
        )
        .map_err(MessageError::EncryptionFailed)?;

        // Overwrite the unencrypted header with the encrypted header
        buf[..PRIVATE_HEADER_ARMED_LEN].copy_from_slice(&encrypted_header);

        Ok(())
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
        write!(f, "└─ Time : {} ms", self.time)
    }
}

impl AckMessage {
    pub(crate) fn parse<'a>(
        buf: &'a mut [u8],
        public_header: &'a PublicHeader,
        private_header: &'a PrivateHeader,
        rx_key: Option<&[u8; SESSIONKEYBYTES]>,
    ) -> Result<&'a Self, MessageError> {
        let buf = if private_header.armed_len > 0 && rx_key.is_some() {
            // disarm body
            if let Some(rx_key) = rx_key {
                disarm_message_body(buf, public_header, rx_key)?;
                &buf[..buf.len() - XCHACHA20POLY1305_IETF_ABYTES]
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
        network_id: &[u8; PUBLIC_HEADER_NETWORK_ID_LEN],
        my_pk: &[u8; ED25519_PUBLICKEYBYTES],
        my_pow: &[u8; PUBLIC_HEADER_POW_LEN],
        tx_key: Option<&[u8; SESSIONKEYBYTES]>,
        recipient: &[u8; ED25519_PUBLICKEYBYTES],
        time: u64,
    ) -> Result<usize, MessageError> {
        // buffer
        let len = if tx_key.is_some() {
            PUBLIC_HEADER_LEN + PRIVATE_HEADER_ARMED_LEN + ACK_LEN + XCHACHA20POLY1305_IETF_ABYTES
        } else {
            PUBLIC_HEADER_LEN + PRIVATE_HEADER_UNARMED_LEN + ACK_LEN
        };
        let buf = &mut buf[..len];

        // public header
        let (public_header, private_header_and_body_slice) =
            PublicHeader::write_bytes(buf, tx_key.is_some(), network_id, my_pk, my_pow, recipient)?;
        trace!("{}", public_header);

        // private header
        let armed_len = if public_header.is_armed() {
            ACK_LEN as u16
        } else {
            0
        };
        let body_slice = PrivateHeader::write_bytes(
            private_header_and_body_slice,
            MessageType::ACK,
            armed_len,
            public_header,
            tx_key,
        )?;

        // body
        let (ack, _) =
            Self::mut_from_prefix(body_slice).map_err(|_| MessageError::BuildAckMessageFailed)?;
        ack.time = time.into();
        trace!("{}", ack);

        if public_header.is_armed() {
            // arm body
            if let Some(tx_key) = tx_key {
                arm_message_body(body_slice, public_header, tx_key)?;
            } else {
                return Err(MessageError::TxKeyNotPresent);
            }
        }

        Ok(len)
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
        public_header: &'a PublicHeader,
        private_header: &'a PrivateHeader,
        rx_key: Option<&[u8; SESSIONKEYBYTES]>,
    ) -> Result<Ref<&'a [u8], Self>, MessageError> {
        let buf = if private_header.armed_len > 0 && rx_key.is_some() {
            // disarm body
            if let Some(rx_key) = rx_key {
                disarm_message_body(buf, public_header, rx_key)?;
                &buf[..buf.len() - XCHACHA20POLY1305_IETF_ABYTES]
            } else {
                return Err(MessageError::RxKeyNotPresent);
            }
        } else {
            buf
        };

        let app: Ref<&'a [u8], Self> =
            Ref::from_bytes(buf).map_err(|_| MessageError::AppMessageInvalid)?;

        Ok(app)
    }

    pub fn build(
        network_id: &[u8; PUBLIC_HEADER_NETWORK_ID_LEN],
        my_pk: &[u8; ED25519_PUBLICKEYBYTES],
        my_pow: &[u8; PUBLIC_HEADER_POW_LEN],
        tx_key: Option<&[u8; SESSIONKEYBYTES]>,
        recipient: &[u8; PUBLIC_HEADER_RECIPIENT_LEN],
        payload: &[u8],
    ) -> Result<Vec<u8>, MessageError> {
        // buffer
        let body_len = payload.len();
        // TODO: kann man hier nicht einen hot buffer nehmen anstelle immer wieder einen neuen zu erstellen?
        let mut buf = if tx_key.is_some() {
            Vec::with_capacity(
                PUBLIC_HEADER_LEN
                    + PRIVATE_HEADER_ARMED_LEN
                    + body_len
                    + if body_len > 0 {
                        XCHACHA20POLY1305_IETF_ABYTES
                    } else {
                        0
                    },
            )
        } else {
            Vec::with_capacity(PUBLIC_HEADER_LEN + PRIVATE_HEADER_UNARMED_LEN + body_len)
        };
        unsafe { buf.set_len(buf.capacity()) };

        // public header
        let (public_header, private_header_and_body_slice) = PublicHeader::write_bytes(
            &mut buf,
            tx_key.is_some(),
            network_id,
            my_pk,
            my_pow,
            recipient,
        )?;
        trace!("{}", public_header);

        // private header
        let armed_len = if public_header.is_armed() {
            body_len as u16
        } else {
            0
        };
        let body_slice = PrivateHeader::write_bytes(
            private_header_and_body_slice,
            MessageType::APP,
            armed_len,
            public_header,
            tx_key,
        )?;

        if body_len != 0 {
            // body
            let (app, _) = Self::mut_from_prefix(body_slice)
                .map_err(|_| MessageError::BuildUniteMessageFailed)?;
            app.payload[..payload.len()].copy_from_slice(payload);
            trace!("{}", app);

            if public_header.is_armed() {
                // arm body
                if let Some(tx_key) = tx_key {
                    arm_message_body(body_slice, public_header, tx_key)?;
                } else {
                    return Err(MessageError::TxKeyNotPresent);
                }
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
pub struct HelloMessageSigned {
    pub time: U64,
    pub child_time: U64,
    pub signature: [u8; SIGN_BYTES],
    pub endpoints: [u8],
}

impl fmt::Display for HelloMessageSigned {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "HELLO:")?;
        writeln!(f, "├─ Time       : {} ms", self.time)?;
        writeln!(f, "├─ Child time : {} ms", self.child_time)?;
        writeln!(f, "├─ Signature  : {}", bytes_to_hex(&self.signature))?;
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

impl HelloMessageSigned {
    pub(crate) fn parse<'a>(
        buf: &'a mut [u8],
        public_header: &'a PublicHeader,
        private_header: &'a PrivateHeader,
        rx_key: Option<&[u8; SESSIONKEYBYTES]>,
    ) -> Result<Ref<&'a [u8], Self>, MessageError> {
        let buf = if private_header.armed_len > 0 && rx_key.is_some() {
            // disarm body
            if let Some(rx_key) = rx_key {
                disarm_message_body(buf, public_header, rx_key)?;
                &buf[..buf.len() - XCHACHA20POLY1305_IETF_ABYTES]
            } else {
                return Err(MessageError::RxKeyNotPresent);
            }
        } else {
            buf
        };

        // rust implementation has a limit for endpoints. To not break compatibility with Java
        // implementation, we just take the first N endpoints instead of discarding the HELLO
        let buf = if buf.len() > HELLO_SIGNED_MIN_LEN + HELLO_ENDPOINT_LEN * HELLO_MAX_ENDPOINTS {
            &buf[..HELLO_SIGNED_MIN_LEN + HELLO_ENDPOINT_LEN * HELLO_MAX_ENDPOINTS]
        } else {
            buf
        };

        let hello: Ref<&'a [u8], Self> =
            Ref::from_bytes(buf).map_err(|_| MessageError::HelloMessageInvalid)?;

        if hello.child_time == 0 {
            return Err(MessageError::HelloMessageInvalid);
        }

        if (hello.endpoints.len() % HELLO_ENDPOINT_LEN) != 0 {
            return Err(MessageError::HelloMessageInvalid);
        }

        Ok(hello)
    }

    pub fn build(
        network_id: &[u8; PUBLIC_HEADER_NETWORK_ID_LEN],
        my_pk: &[u8; ED25519_PUBLICKEYBYTES],
        my_pow: &[u8; PUBLIC_HEADER_POW_LEN],
        tx_key: Option<&[u8; SESSIONKEYBYTES]>,
        recipient: &[u8; ED25519_PUBLICKEYBYTES],
        time: u64,
        endpoints: &[u8],
    ) -> Result<Vec<u8>, MessageError> {
        // buffer
        let body_len = HELLO_SIGNED_MIN_LEN + endpoints.len();
        let mut buf = if tx_key.is_some() {
            Vec::with_capacity(
                PUBLIC_HEADER_LEN
                    + PRIVATE_HEADER_ARMED_LEN
                    + body_len
                    + XCHACHA20POLY1305_IETF_ABYTES,
            )
        } else {
            Vec::with_capacity(PUBLIC_HEADER_LEN + PRIVATE_HEADER_UNARMED_LEN + body_len)
        };
        unsafe { buf.set_len(buf.capacity()) };

        // public header
        let (public_header, private_header_and_body_slice) = PublicHeader::write_bytes(
            &mut buf,
            tx_key.is_some(),
            network_id,
            my_pk,
            my_pow,
            recipient,
        )?;
        trace!("{}", public_header);

        // private header
        let armed_len = if public_header.is_armed() {
            body_len as u16
        } else {
            0
        };
        let body_slice = PrivateHeader::write_bytes(
            private_header_and_body_slice,
            MessageType::HELLO,
            armed_len,
            public_header,
            tx_key,
        )?;

        // body
        let hello =
            Self::mut_from_bytes(body_slice).map_err(|_| MessageError::BuildHelloMessageFailed)?;
        hello.time = time.into();
        hello.child_time = HELLO_CHILD_TIME_SUPER_PEER.into();
        if public_header.is_armed() {
            let endpoints_len = hello.endpoints.len();
            hello.endpoints[..endpoints_len - XCHACHA20POLY1305_IETF_ABYTES]
                .copy_from_slice(endpoints);
        } else {
            hello.endpoints.copy_from_slice(endpoints);
        }
        trace!("{}", hello);

        if public_header.is_armed() {
            // arm body
            if let Some(tx_key) = tx_key {
                arm_message_body(body_slice, public_header, tx_key)?;
            } else {
                return Err(MessageError::TxKeyNotPresent);
            }
        }

        Ok(buf)
    }
}

#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct HelloMessageUnsigned {
    pub time: U64,
}

impl fmt::Display for HelloMessageUnsigned {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "HELLO:")?;
        writeln!(f, "└─ Time       : {} ms", self.time)?;
        Ok(())
    }
}

impl HelloMessageUnsigned {
    pub(crate) fn parse<'a>(
        buf: &'a mut [u8],
        public_header: &'a PublicHeader,
        private_header: &'a PrivateHeader,
        rx_key: Option<&[u8; SESSIONKEYBYTES]>,
    ) -> Result<&'a HelloMessageUnsigned, MessageError> {
        let buf = if private_header.armed_len > 0 && rx_key.is_some() {
            // disarm body
            if let Some(rx_key) = rx_key {
                disarm_message_body(buf, public_header, rx_key)?;
                &buf[..buf.len() - XCHACHA20POLY1305_IETF_ABYTES]
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
        network_id: &[u8; PUBLIC_HEADER_NETWORK_ID_LEN],
        my_pk: &[u8; ED25519_PUBLICKEYBYTES],
        my_pow: &[u8; PUBLIC_HEADER_POW_LEN],
        tx_key: Option<&[u8; SESSIONKEYBYTES]>,
        recipient: &[u8; ED25519_PUBLICKEYBYTES],
        time: u64,
    ) -> Result<Vec<u8>, MessageError> {
        // buffer
        let mut buf = if tx_key.is_some() {
            Vec::with_capacity(
                PUBLIC_HEADER_LEN
                    + PRIVATE_HEADER_ARMED_LEN
                    + HELLO_UNSIGNED_LEN
                    + XCHACHA20POLY1305_IETF_ABYTES,
            )
        } else {
            Vec::with_capacity(PUBLIC_HEADER_LEN + PRIVATE_HEADER_UNARMED_LEN + HELLO_UNSIGNED_LEN)
        };
        unsafe { buf.set_len(buf.capacity()) };

        // public header
        let (public_header, private_header_and_body_slice) = PublicHeader::write_bytes(
            &mut buf,
            tx_key.is_some(),
            network_id,
            my_pk,
            my_pow,
            recipient,
        )?;
        trace!("{}", public_header);

        // private header
        let armed_len = if public_header.is_armed() {
            HELLO_UNSIGNED_LEN as u16
        } else {
            0
        };
        let body_slice = PrivateHeader::write_bytes(
            private_header_and_body_slice,
            MessageType::HELLO,
            armed_len,
            public_header,
            tx_key,
        )?;

        // body
        let (hello, _) =
            Self::mut_from_prefix(body_slice).map_err(|_| MessageError::BuildHelloMessageFailed)?;
        hello.time = time.into();
        trace!("{}", hello);

        if public_header.is_armed() {
            // arm body
            if let Some(tx_key) = tx_key {
                arm_message_body(body_slice, public_header, tx_key)?;
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
        public_header: &'a PublicHeader,
        private_header: &'a PrivateHeader,
        rx_key: Option<&[u8; SESSIONKEYBYTES]>,
    ) -> Result<Ref<&'a [u8], Self>, MessageError> {
        let buf = if private_header.armed_len > 0 && rx_key.is_some() {
            // disarm body
            if let Some(rx_key) = rx_key {
                disarm_message_body(buf, public_header, rx_key)?;
                &buf[..buf.len() - XCHACHA20POLY1305_IETF_ABYTES]
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

        let hello: Ref<&'a [u8], Self> =
            Ref::from_bytes(buf).map_err(|_| MessageError::UniteMessageInvalid)?;

        Ok(hello)
    }

    pub fn build(
        network_id: &[u8; PUBLIC_HEADER_NETWORK_ID_LEN],
        my_pk: &[u8; ED25519_PUBLICKEYBYTES],
        my_pow: &[u8; PUBLIC_HEADER_POW_LEN],
        tx_key: Option<&[u8; SESSIONKEYBYTES]>,
        recipient: &[u8; PUBLIC_HEADER_RECIPIENT_LEN],
        address: &[u8; UNITE_ADDRESS_LEN],
        endpoints: &[u8],
    ) -> Result<Vec<u8>, MessageError> {
        // buffer
        let body_len = UNITE_MIN_LEN + endpoints.len() - UNITE_ENDPOINT_LEN;
        let mut buf = if tx_key.is_some() {
            Vec::with_capacity(
                PUBLIC_HEADER_LEN
                    + PRIVATE_HEADER_ARMED_LEN
                    + body_len
                    + XCHACHA20POLY1305_IETF_ABYTES,
            )
        } else {
            Vec::with_capacity(PUBLIC_HEADER_LEN + PRIVATE_HEADER_UNARMED_LEN + body_len)
        };
        unsafe { buf.set_len(buf.capacity()) };

        // public header
        let (public_header, private_header_and_body_slice) = PublicHeader::write_bytes(
            &mut buf,
            tx_key.is_some(),
            network_id,
            my_pk,
            my_pow,
            recipient,
        )?;
        trace!("{}", public_header);

        // private header
        let armed_len = if public_header.is_armed() {
            body_len as u16
        } else {
            0
        };
        let body_slice = PrivateHeader::write_bytes(
            private_header_and_body_slice,
            MessageType::UNITE,
            armed_len,
            public_header,
            tx_key,
        )?;

        // body
        let (unite, _) =
            Self::mut_from_prefix(body_slice).map_err(|_| MessageError::BuildUniteMessageFailed)?;
        unite.address = *address;
        if public_header.is_armed() {
            let endpoints_len = unite.endpoints.len();
            unite.endpoints[..endpoints_len - XCHACHA20POLY1305_IETF_ABYTES]
                .copy_from_slice(endpoints);
        } else {
            unite.endpoints.copy_from_slice(endpoints);
        }
        trace!("{}", unite);

        if public_header.is_armed() {
            // arm body
            if let Some(tx_key) = tx_key {
                arm_message_body(body_slice, public_header, tx_key)?;
            } else {
                return Err(MessageError::TxKeyNotPresent);
            }
        }

        Ok(buf)
    }
}

fn build_auth_tag(
    public_header: &[u8; PUBLIC_HEADER_LEN],
) -> [u8; PUBLIC_HEADER_LEN - PUBLIC_HEADER_MAGIC_NUMBER_LEN] {
    let mut auth_bytes = [0u8; PUBLIC_HEADER_LEN - PUBLIC_HEADER_MAGIC_NUMBER_LEN];

    // do not include magic number

    // "empty" flags
    auth_bytes[0] = PUBLIC_HEADER_NONCE_ZERO_HOP_COUNT_ARMED_FLAGS;

    // remaining fields
    auth_bytes[PUBLIC_HEADER_FLAGS_LEN..].copy_from_slice(
        &public_header[PUBLIC_HEADER_FLAGS_LEN + PUBLIC_HEADER_MAGIC_NUMBER_LEN..],
    );

    auth_bytes
}

fn disarm_message_body(
    buf: &mut [u8],
    public_header: &PublicHeader,
    rx_key: &[u8; SESSIONKEYBYTES],
) -> Result<(), MessageError> {
    let decrypted_body =
        decrypt(buf, &[], &public_header.nonce, rx_key).map_err(MessageError::DecryptionFailed)?;
    let unarmed_buf_len = buf.len() - XCHACHA20POLY1305_IETF_ABYTES;
    buf[..unarmed_buf_len].copy_from_slice(&decrypted_body);

    Ok(())
}

fn arm_message_body(
    buf: &mut [u8],
    public_header: &PublicHeader,
    tx_key: &[u8; SESSIONKEYBYTES],
) -> Result<(), MessageError> {
    let encrypted_body = encrypt(
        &buf[..buf.len() - XCHACHA20POLY1305_IETF_ABYTES],
        &[],
        &public_header.nonce,
        tx_key,
    )
    .map_err(MessageError::EncryptionFailed)?;
    buf.copy_from_slice(&encrypted_body);

    Ok(())
}
