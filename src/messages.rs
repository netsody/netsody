use crate::messages;
use crate::node::Node;
use crate::utils::hex;
use crate::utils::{crypto, net};
use log::trace;
use std::fmt;
use std::net::SocketAddr;

// public header
pub(crate) const PUBLIC_HEADER_MAGIC_NUMBER_LEN: usize = 4;
const PUBLIC_HEADER_FLAGS_LEN: usize = 1;
const PUBLIC_HEADER_NETWORK_ID_LEN: usize = 4;
const PUBLIC_HEADER_NONCE_LEN: usize = crypto::XCHACHA20POLY1305_IETF_NPUBBYTES;
const PUBLIC_HEADER_RECIPIENT_LEN: usize = crypto::ED25519_PUBLICKEYBYTES;
const PUBLIC_HEADER_SENDER_LEN: usize = crypto::ED25519_PUBLICKEYBYTES;
const PUBLIC_HEADER_POW_LEN: usize = 4;
pub(crate) const PUBLIC_HEADER_LEN: usize = PUBLIC_HEADER_MAGIC_NUMBER_LEN
    + PUBLIC_HEADER_FLAGS_LEN
    + PUBLIC_HEADER_NETWORK_ID_LEN
    + PUBLIC_HEADER_NONCE_LEN
    + PUBLIC_HEADER_RECIPIENT_LEN
    + PUBLIC_HEADER_SENDER_LEN
    + PUBLIC_HEADER_POW_LEN;

const PUBLIC_HEADER_NONCE_IDX: usize =
    PUBLIC_HEADER_MAGIC_NUMBER_LEN + PUBLIC_HEADER_FLAGS_LEN + PUBLIC_HEADER_NETWORK_ID_LEN;

const PUBLIC_HEADER_MAGIC_NUMBER: [u8; PUBLIC_HEADER_MAGIC_NUMBER_LEN] =
    22527u32.pow(2).to_be_bytes();
const PUBLIC_HEADER_NONCE_ZERO_HOP_COUNT_ARMED_FLAGS: u8 = 0x10u8;
const PUBLIC_HEADER_NONCE_ZERO_HOP_COUNT_UNARMED_FLAGS: u8 = 0x00u8;

// private header
const PRIVATE_HEADER_MESSAGE_TYPE_LEN: usize = 1;
const PRIVATE_HEADER_ARMED_LENGTH_LEN: usize = 2;
const PRIVATE_HEADER_AUTHENTICATION_HEADER_LEN: usize = crypto::XCHACHA20POLY1305_IETF_ABYTES;
pub(crate) const PRIVATE_HEADER_UNARMED_LEN: usize =
    PRIVATE_HEADER_MESSAGE_TYPE_LEN + PRIVATE_HEADER_ARMED_LENGTH_LEN;
pub(crate) const PRIVATE_HEADER_ARMED_LEN: usize =
    PRIVATE_HEADER_UNARMED_LEN + PRIVATE_HEADER_AUTHENTICATION_HEADER_LEN;

// ACK body
const ACK_TIME_LEN: usize = 8;
const ACK_LEN: usize = ACK_TIME_LEN;

// HELLO body
const HELLO_TIME_LEN: usize = 8;
const HELLO_CHILDREN_TIME_LEN: usize = 8;
const HELLO_SIGNATURE_LEN: usize = crypto::SIGN_BYTES;
const HELLO_ENDPOINT_LEN: usize = 2 + net::IPV6_LENGTH;
const HELLO_UNSIGNED_MIN_LEN: usize = HELLO_TIME_LEN + HELLO_CHILDREN_TIME_LEN;
const HELLO_SIGNED_MIN_LEN: usize = HELLO_UNSIGNED_MIN_LEN + HELLO_SIGNATURE_LEN;
const HELLO_MAX_ENDPOINTS: usize = 10;

// UNITE body
const UNITE_ADDRESS_LEN: usize = 32;
const UNITE_ENDPOINT_LEN: usize = 2 + net::IPV6_LENGTH;
const UNITE_MIN_LEN: usize = UNITE_ADDRESS_LEN + UNITE_ENDPOINT_LEN;

#[derive(Debug)]
pub enum MessageError {
    LengthTooSmall(usize),
    MagicNumberInvalid([u8; PUBLIC_HEADER_MAGIC_NUMBER_LEN]),
    NetworkIdOther([u8; PUBLIC_HEADER_NETWORK_ID_LEN]),
    MessageTypeInvalid(u8),
    DecryptionFailed,
    TimeDiffTooLarge(u64),
    EncryptionFailed,
    ArmedLengthInvalid,
    AgreementKeyConversionFailed,
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageError::LengthTooSmall(size) => {
                write!(f, "Message too small: {} bytes", size)
            }
            MessageError::MagicNumberInvalid(magic_number) => {
                write!(f, "Invalid magic number: {:?}", magic_number)
            }
            MessageError::NetworkIdOther(id) => {
                write!(f, "Other network id: {:?}", id)
            }
            MessageError::MessageTypeInvalid(message_type) => {
                write!(f, "Invalid message type: {}", message_type)
            }
            MessageError::DecryptionFailed => {
                write!(f, "Decryption failed")
            }
            MessageError::EncryptionFailed => {
                write!(f, "Encryption failed")
            }
            MessageError::TimeDiffTooLarge(time_diff) => {
                write!(f, "Time diff too large: {} ms", time_diff)
            }
            MessageError::ArmedLengthInvalid => {
                write!(f, "Armed length invalid")
            }
            MessageError::AgreementKeyConversionFailed => {
                write!(f, "Agreement key conversion failed")
            }
        }
    }
}

#[derive(Debug)]
pub struct PublicHeader<'a> {
    pub magic_number: &'a [u8; PUBLIC_HEADER_MAGIC_NUMBER_LEN],
    pub flags: &'a u8,
    pub network_id: &'a [u8; PUBLIC_HEADER_NETWORK_ID_LEN],
    pub nonce: &'a [u8; PUBLIC_HEADER_NONCE_LEN],
    pub recipient: &'a [u8; PUBLIC_HEADER_RECIPIENT_LEN],
    pub sender: &'a [u8; PUBLIC_HEADER_SENDER_LEN],
    pub pow: &'a [u8; PUBLIC_HEADER_POW_LEN],
}

impl<'a> fmt::Display for PublicHeader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let magic_int = u32::from_be_bytes(*self.magic_number);
        writeln!(f, "Public Header:")?;
        writeln!(f, "├─ Magic Number  : {} (0x{:08x})", magic_int, magic_int)?;
        writeln!(
            f,
            "├─ Flags         : {:08b} ({:#04x})",
            self.flags, self.flags
        )?;
        writeln!(f, "│  ├─ Hop Count  : {}", self.hop_count())?;
        writeln!(f, "│  ├─ Armed      : {}", self.is_armed())?;
        writeln!(f, "│  └─ Reserved   : {:04b}", self.flags & 0b1111)?;
        let network_id = u32::from_be_bytes(*self.network_id);
        writeln!(
            f,
            "├─ Network Id    : {} (0x{:08x})",
            network_id, network_id
        )?;
        writeln!(f, "├─ Nonce         : {}", hex::bytes_to_hex(self.nonce))?;
        writeln!(f, "├─ Recipient     : {}", hex::bytes_to_hex(self.recipient))?;
        writeln!(f, "├─ Sender        : {}", hex::bytes_to_hex(self.sender))?;
        write!(f, "└─ Proof of Work : {}", i32::from_be_bytes(*self.pow))
    }
}

impl<'a> PublicHeader<'a> {
    pub fn is_armed(&self) -> bool {
        (*self.flags & (1 << 4)) != 0 // Bit 4
    }

    pub fn hop_count(&self) -> u8 {
        (*self.flags >> 5) & 0b111 // Obere 3 Bits (5-7)
    }

    fn new(
        buf: &'a mut [u8; PUBLIC_HEADER_LEN],
        arm: bool,
        node: &Node,
        recipient: &[u8; crypto::ED25519_PUBLICKEYBYTES],
    ) -> PublicHeader<'a> {
        let mut w_idx = 0;

        // magic number
        buf[w_idx..][..PUBLIC_HEADER_MAGIC_NUMBER_LEN].copy_from_slice(&PUBLIC_HEADER_MAGIC_NUMBER);
        w_idx += PUBLIC_HEADER_MAGIC_NUMBER_LEN;

        // flags
        buf[w_idx] = if arm {
            PUBLIC_HEADER_NONCE_ZERO_HOP_COUNT_ARMED_FLAGS
        } else {
            PUBLIC_HEADER_NONCE_ZERO_HOP_COUNT_UNARMED_FLAGS
        };
        w_idx += PUBLIC_HEADER_FLAGS_LEN;

        // network id
        buf[w_idx..][..PUBLIC_HEADER_NETWORK_ID_LEN].copy_from_slice(node.network_id());
        w_idx += PUBLIC_HEADER_NETWORK_ID_LEN;

        // nonce
        crypto::random_bytes(&mut buf[w_idx..][..PUBLIC_HEADER_NONCE_LEN]);
        w_idx += PUBLIC_HEADER_NONCE_LEN;

        // recipient
        buf[w_idx..][..PUBLIC_HEADER_RECIPIENT_LEN].copy_from_slice(recipient);
        w_idx += PUBLIC_HEADER_RECIPIENT_LEN;

        // sender
        buf[w_idx..][..PUBLIC_HEADER_SENDER_LEN].copy_from_slice(node.public_key());
        w_idx += PUBLIC_HEADER_SENDER_LEN;

        // proof of work
        buf[w_idx..][..PUBLIC_HEADER_POW_LEN].copy_from_slice(node.pow());

        Self::from_bytes_trusted(buf, node.network_id(), true).unwrap()
    }

    pub fn from_bytes(
        buf: &'a [u8; PUBLIC_HEADER_LEN],
        my_network_id: &[u8; 4],
    ) -> Result<PublicHeader<'a>, MessageError> {
        Self::from_bytes_trusted(buf, my_network_id, false)
    }

    fn from_bytes_trusted(
        buf: &'a [u8; PUBLIC_HEADER_LEN],
        my_network_id: &[u8; 4],
        trust: bool,
    ) -> Result<PublicHeader<'a>, MessageError> {
        let mut r_idx = 0;

        // magic number
        let magic_number: &[u8; PUBLIC_HEADER_MAGIC_NUMBER_LEN] = buf[r_idx..]
            [..PUBLIC_HEADER_MAGIC_NUMBER_LEN]
            .try_into()
            .unwrap();
        if !trust && magic_number != &PUBLIC_HEADER_MAGIC_NUMBER {
            return Err(MessageError::MagicNumberInvalid(*magic_number));
        }
        r_idx += PUBLIC_HEADER_MAGIC_NUMBER_LEN;

        // flags
        let flags = &buf[r_idx];
        r_idx += PUBLIC_HEADER_FLAGS_LEN;

        // network id
        let network_id: &[u8; PUBLIC_HEADER_NETWORK_ID_LEN] = buf[r_idx..]
            [..PUBLIC_HEADER_NETWORK_ID_LEN]
            .try_into()
            .unwrap();
        if !trust && network_id != my_network_id {
            return Err(MessageError::NetworkIdOther(*network_id));
        }
        r_idx += PUBLIC_HEADER_NETWORK_ID_LEN;

        // nonce
        let nonce: &[u8; PUBLIC_HEADER_NONCE_LEN] =
            buf[r_idx..][..PUBLIC_HEADER_NONCE_LEN].try_into().unwrap();
        r_idx += PUBLIC_HEADER_NONCE_LEN;

        // recipient
        let recipient: &[u8; PUBLIC_HEADER_RECIPIENT_LEN] = buf[r_idx..]
            [..PUBLIC_HEADER_RECIPIENT_LEN]
            .try_into()
            .unwrap();
        r_idx += PUBLIC_HEADER_RECIPIENT_LEN;

        // sender
        let sender: &[u8; PUBLIC_HEADER_SENDER_LEN] =
            buf[r_idx..][..PUBLIC_HEADER_SENDER_LEN].try_into().unwrap();
        r_idx += PUBLIC_HEADER_SENDER_LEN;

        // sender's proof of work
        let pow: &[u8; PUBLIC_HEADER_POW_LEN] =
            buf[r_idx..][..PUBLIC_HEADER_POW_LEN].try_into().unwrap();

        Ok(PublicHeader {
            magic_number,
            flags,
            network_id,
            nonce,
            recipient,
            sender,
            pow,
        })
    }
}

#[derive(Debug)]
pub struct MessageType;

impl MessageType {
    pub const ACK: u8 = 0;
    pub const APP: u8 = 1;
    pub const HELLO: u8 = 2;
    pub const UNITE: u8 = 3;

    pub fn byte_to_str(byte: u8) -> &'static str {
        match byte {
            Self::ACK => "ACK",
            Self::APP => "APP",
            Self::HELLO => "HELLO",
            Self::UNITE => "UNITE",
            _ => "UNKNOWN",
        }
    }
}

#[derive(Debug)]
pub struct PrivateHeader<'a> {
    pub message_type: &'a u8,
    pub armed_len: &'a [u8; PRIVATE_HEADER_ARMED_LENGTH_LEN],
}

impl<'a> fmt::Display for PrivateHeader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Private Header:")?;
        writeln!(
            f,
            "├─ Message Type : {} ({})",
            MessageType::byte_to_str(*self.message_type),
            self.message_type
        )?;
        write!(
            f,
            "└─ Armed Length : {} bytes",
            u16::from_be_bytes(*self.armed_len)
        )
    }
}

impl<'a> PrivateHeader<'a> {
    fn new(
        buf: &'a mut [u8; PRIVATE_HEADER_UNARMED_LEN],
        message_type: u8,
        armed_len: u16,
    ) -> PrivateHeader<'a> {
        let mut w_idx = 0;

        // message type
        buf[w_idx] = message_type;
        w_idx += PRIVATE_HEADER_MESSAGE_TYPE_LEN;

        // armed length
        buf[w_idx..][..PRIVATE_HEADER_ARMED_LENGTH_LEN].copy_from_slice(&armed_len.to_be_bytes());

        Self::from_bytes_trusted(buf, true).unwrap()
    }

    pub fn from_bytes(
        buf: &'a [u8; PRIVATE_HEADER_UNARMED_LEN],
    ) -> Result<PrivateHeader<'a>, MessageError> {
        Self::from_bytes_trusted(buf, false)
    }

    fn from_bytes_trusted(
        buf: &'a [u8; PRIVATE_HEADER_UNARMED_LEN],
        trust: bool,
    ) -> Result<PrivateHeader<'a>, MessageError> {
        let mut r_idx = 0;

        // message_type
        let message_type = &buf[r_idx];
        if !trust {
            match *message_type {
                MessageType::ACK | MessageType::APP | MessageType::HELLO | MessageType::UNITE => {}
                _ => return Err(MessageError::MessageTypeInvalid(*message_type)),
            }
        }
        r_idx += PRIVATE_HEADER_MESSAGE_TYPE_LEN;

        // armed length
        let armed_length: &[u8; PRIVATE_HEADER_ARMED_LENGTH_LEN] = buf[r_idx..]
            [..PRIVATE_HEADER_ARMED_LENGTH_LEN]
            .try_into()
            .unwrap();

        Ok(PrivateHeader {
            message_type,
            armed_len: armed_length,
        })
    }
}

#[derive(Debug)]
pub struct AckMessage<'a> {
    pub time: &'a [u8; HELLO_TIME_LEN],
}

impl<'a> fmt::Display for AckMessage<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ACK:")?;
        let time = u64::from_be_bytes(*self.time);
        write!(f, "└─ Time : {} ms", time)
    }
}

impl<'a> AckMessage<'a> {
    pub fn new(
        node: &Node,
        arm: bool,
        recipient: &[u8; PUBLIC_HEADER_RECIPIENT_LEN],
        time: &'a [u8; ACK_TIME_LEN],
    ) -> Result<Vec<u8>, MessageError> {
        let (mut buf, body_idx) =
            create_buf_and_headers(node, arm, recipient, MessageType::ACK, ACK_LEN);

        // body
        let ack = AckMessage {
            time: time,
        };
        trace!("{}", ack);
        let body_slice = <&mut [u8; ACK_LEN]>::try_from(&mut buf[body_idx..][..ACK_LEN]).unwrap();
        ack.to_bytes(body_slice);

        if arm {
            if let Err(e) = messages::arm(node, recipient, ACK_LEN as u16, &mut buf) {
                return Err(e);
            }
        }

        Ok(buf)
    }

    pub fn from_bytes(_buf: &[u8]) -> Result<AckMessage, MessageError> {
        todo!()
    }

    fn to_bytes(&self, buf: &mut [u8; ACK_LEN]) {
        // time
        buf[..ACK_TIME_LEN].copy_from_slice(self.time);
    }
}

fn create_buf_and_headers(
    node: &Node,
    arm: bool,
    recipient: &[u8; crypto::ED25519_PUBLICKEYBYTES],
    message_type: u8,
    body_len: usize,
) -> (Vec<u8>, usize) {
    // buffer
    let mut buf = if arm {
        Vec::with_capacity(
            PUBLIC_HEADER_LEN
                + PRIVATE_HEADER_ARMED_LEN
                + body_len
                + crypto::XCHACHA20POLY1305_IETF_ABYTES,
        )
    } else {
        Vec::with_capacity(PUBLIC_HEADER_LEN + PRIVATE_HEADER_UNARMED_LEN + body_len)
    };
    unsafe { buf.set_len(buf.capacity()) }; // avoid unnecessary initialized of buf

    // slices
    let (public_header_slice, body_slice) = buf.split_at_mut(PUBLIC_HEADER_LEN);
    let public_header_slice: &mut [u8; PUBLIC_HEADER_LEN] = public_header_slice.try_into().unwrap(); // set known length

    let (private_header_slice, _) = body_slice.split_at_mut(PRIVATE_HEADER_UNARMED_LEN);
    let private_header_slice: &mut [u8; PRIVATE_HEADER_UNARMED_LEN] =
        private_header_slice.try_into().unwrap(); // set known length

    // public header
    let public_header = PublicHeader::new(public_header_slice, arm, node, recipient);
    trace!("{}", public_header);

    // private header
    let armed_len = body_len as u16;
    let private_header = PrivateHeader::new(private_header_slice, message_type, armed_len);
    trace!("{}", private_header);

    let body_idx = if arm {
        PUBLIC_HEADER_LEN + PRIVATE_HEADER_ARMED_LEN
    } else {
        PUBLIC_HEADER_LEN + PRIVATE_HEADER_UNARMED_LEN
    };

    (buf, body_idx)
}

#[derive(Debug)]
pub struct AppMessage {
    pub data: Vec<u8>,
}

impl fmt::Display for AppMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "APP:")?;
        write!(f, "└─ Data length: {} bytes", self.data.len())
    }
}

impl AppMessage {
    pub fn from_bytes(_buf: &[u8]) -> Result<AppMessage, MessageError> {
        todo!()
    }
}

#[derive(Debug)]
pub struct HelloMessage<'a> {
    pub time: &'a [u8; HELLO_TIME_LEN],
    pub children_time: &'a [u8; HELLO_CHILDREN_TIME_LEN],
    pub signature: &'a [u8; HELLO_SIGNATURE_LEN],
    pub endpoints: Vec<SocketAddr>,
}

impl<'a> fmt::Display for HelloMessage<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "HELLO:")?;
        let time = u64::from_be_bytes(*self.time);
        writeln!(f, "├─ Time          : {} ms", time)?;
        let children_time = u64::from_be_bytes(*self.children_time);
        writeln!(f, "├─ Children Time : {} s", children_time)?;
        writeln!(f, "├─ Signature: {}", hex::bytes_to_hex(self.signature))?;
        writeln!(f, "└─ Endpoints     :")?;
        for (i, endpoint) in self.endpoints.iter().enumerate() {
            if i == self.endpoints.len() - 1 {
                write!(f, "    └─ {}", endpoint)?;
            } else {
                writeln!(f, "    ├─ {}", endpoint)?;
            }
        }
        Ok(())
    }
}

impl<'a> HelloMessage<'a> {
    pub fn from_bytes(buf: &'a [u8], now: u64) -> Result<HelloMessage<'a>, MessageError> {
        if buf.len() < HELLO_SIGNED_MIN_LEN {
            return Err(MessageError::LengthTooSmall(buf.len()));
        }

        let mut r_idx = 0;

        // time
        let time: &[u8; HELLO_TIME_LEN] = buf[r_idx..][..HELLO_TIME_LEN].try_into().unwrap();
        let time_number = u64::from_be_bytes(*time);
        let time_diff = if now > time_number {
            now - time_number
        } else {
            time_number - now
        };
        if time_diff > *crate::MESSAGE_MAX_AGE {
            return Err(MessageError::TimeDiffTooLarge(time_diff));
        }
        r_idx += HELLO_TIME_LEN;

        // children time
        let children_time: &[u8; HELLO_TIME_LEN] =
            buf[r_idx..][..HELLO_TIME_LEN].try_into().unwrap();
        r_idx += HELLO_TIME_LEN;

        // signature
        let signature: &[u8; HELLO_SIGNATURE_LEN] =
            buf[r_idx..][..HELLO_SIGNATURE_LEN].try_into().unwrap();
        r_idx += HELLO_SIGNATURE_LEN;

        // endpoints
        let mut endpoints = Vec::with_capacity(std::cmp::min(
            buf.len() - r_idx,
            HELLO_MAX_ENDPOINTS * HELLO_ENDPOINT_LEN,
        ));
        while r_idx + HELLO_ENDPOINT_LEN <= buf.len() {
            // port
            let port = u16::from_be_bytes(buf[r_idx..][..2].try_into().unwrap());

            // verify port
            if port == 0 {
                break;
            }

            // address
            let addr_bytes =
                <&[u8; net::IPV6_LENGTH]>::try_from(&buf[r_idx + 2..][..net::IPV6_LENGTH]).unwrap();
            let addr = net::addr_from_bytes(addr_bytes);

            // ignore invalid addresses
            // 0.0.0.0 or ::
            // 224.0.0.0/4 or ff00::/8
            if addr.is_unspecified() || addr.is_multicast() {
                continue;
            }

            // convert to endpoint
            endpoints.push(SocketAddr::from((addr, port)));
            r_idx += HELLO_ENDPOINT_LEN;
        }
        endpoints.shrink_to_fit();

        Ok(HelloMessage {
            time,
            children_time,
            signature,
            endpoints,
        })
    }
}

#[derive(Debug)]
pub struct UniteMessage {
    pub address: [u8; UNITE_ADDRESS_LEN],
    pub endpoints: Vec<SocketAddr>,
}

impl fmt::Display for UniteMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "UNITE:")?;
        let address_hex = hex::bytes_to_hex(&self.address);
        writeln!(f, "├─ Address   : {}", address_hex)?;
        writeln!(f, "└─ Endpoints :")?;
        for (i, endpoint) in self.endpoints.iter().enumerate() {
            if i == self.endpoints.len() - 1 {
                write!(f, "    └─ {}", endpoint)?;
            } else {
                writeln!(f, "    ├─ {}", endpoint)?;
            }
        }
        Ok(())
    }
}

impl UniteMessage {
    pub fn new(
        node: &Node,
        arm: bool,
        recipient: &[u8; PUBLIC_HEADER_RECIPIENT_LEN],
        address: &[u8; UNITE_ADDRESS_LEN],
        endpoints: Vec<SocketAddr>,
    ) -> Result<Vec<u8>, MessageError> {
        let body_len = UNITE_MIN_LEN + endpoints.len() * UNITE_ENDPOINT_LEN - UNITE_ENDPOINT_LEN; // subtract one endpoint as unit must contain at least one
        let (mut buf, body_idx) =
            create_buf_and_headers(node, arm, recipient, MessageType::UNITE, body_len);

        // body
        let unite = UniteMessage {
            address: *address,
            endpoints,
        };
        trace!("{}", unite);
        let body_slice = &mut buf[body_idx..][..body_len];
        unite.to_bytes(body_slice);

        if arm {
            if let Err(e) = messages::arm(node, recipient, body_len as u16, &mut buf) {
                return Err(e);
            }
        }

        Ok(buf)
    }

    pub fn from_bytes(_buf: &[u8]) -> Result<UniteMessage, MessageError> {
        todo!()
    }

    fn to_bytes(&self, buf: &mut [u8]) {
        let mut w_idx = 0;

        // address
        buf[w_idx..][..UNITE_ADDRESS_LEN].copy_from_slice(&self.address);
        w_idx += UNITE_ADDRESS_LEN;

        // endpoints
        for endpoint in &self.endpoints {
            // port
            buf[w_idx..][..2].copy_from_slice(&endpoint.port().to_be_bytes());
            w_idx += 2;

            // address
            let addr_bytes =
                <&mut [u8; 16]>::try_from(&mut buf[w_idx..][..net::IPV6_LENGTH]).unwrap();
            net::addr_to_bytes(endpoint.ip(), addr_bytes);
            w_idx += net::IPV6_LENGTH;
        }
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

pub fn disarm<'a, 'b>(
    node: &Node,
    public_header: &'b PublicHeader,
    public_header_slice: &'b [u8; PUBLIC_HEADER_LEN],
    cipher: &'a mut [u8],
) -> Result<PrivateHeader<'a>, MessageError> {
    if cipher.len() < PRIVATE_HEADER_ARMED_LEN {
        return Err(MessageError::LengthTooSmall(cipher.len()));
    }

    let my_agreement_public_key =
        crypto::convert_identity_public_key_to_key_agreement_public_key(node.public_key());
    let my_agreement_private_key =
        crypto::convert_identity_secret_key_to_key_agreement_secret_key(node.secret_key());
    let peer_agreement_public_key =
        crypto::convert_identity_public_key_to_key_agreement_public_key(public_header.sender);

    match (
        my_agreement_public_key,
        my_agreement_private_key,
        peer_agreement_public_key,
    ) {
        (
            Ok(our_agreement_public_key),
            Ok(our_agreement_private_key),
            Ok(peer_agreement_public_key),
        ) => match crypto::generate_session_key_pair(
            &our_agreement_public_key,
            &our_agreement_private_key,
            &peer_agreement_public_key,
        ) {
            Ok((rx_key, _)) => {
                let auth_tag = if public_header.hop_count()
                    == PUBLIC_HEADER_NONCE_ZERO_HOP_COUNT_ARMED_FLAGS
                {
                    // no need to build auth tag
                    &public_header_slice[PUBLIC_HEADER_MAGIC_NUMBER_LEN..]
                } else {
                    &build_auth_tag(public_header_slice)
                };

                let (private_header_slice, body_slice) =
                    cipher.split_at_mut(PRIVATE_HEADER_ARMED_LEN);
                let private_header_slice: &mut [u8; PRIVATE_HEADER_ARMED_LEN] =
                    private_header_slice.try_into().unwrap(); // set known length

                match crypto::decrypt(private_header_slice, auth_tag, public_header.nonce, rx_key) {
                    Ok(decrypted_header) => {
                        // Überschreibe den verschlüsselten Header mit dem entschlüsselten Header
                        private_header_slice[..PRIVATE_HEADER_UNARMED_LEN]
                            .copy_from_slice(&decrypted_header);

                        // Versuche die entschlüsselten Bytes als PrivateHeader zu interpretieren
                        match PrivateHeader::from_bytes(
                            <&[u8; PRIVATE_HEADER_UNARMED_LEN]>::try_from(
                                &private_header_slice[..PRIVATE_HEADER_UNARMED_LEN],
                            )
                            .unwrap(),
                        ) {
                            Ok(private_header) => {
                                let armed_length =
                                    u16::from_be_bytes(*private_header.armed_len) as usize;

                                if armed_length > body_slice.len() {
                                    Err(MessageError::ArmedLengthInvalid)
                                } else if armed_length > 0 {
                                    // Hole den zusätzlichen (noch verschlüsselten) Teil
                                    match crypto::decrypt(
                                        body_slice,
                                        &[],
                                        public_header.nonce,
                                        rx_key,
                                    ) {
                                        Ok(decrypted_body) => {
                                            body_slice[..armed_length]
                                                .copy_from_slice(&decrypted_body);
                                            Ok(private_header)
                                        }
                                        Err(_) => Err(MessageError::DecryptionFailed),
                                    }
                                } else {
                                    // Kein zusätzlicher verschlüsselter Teil
                                    Ok(private_header)
                                }
                            }
                            Err(e) => Err(e),
                        }
                    }
                    Err(_) => Err(MessageError::DecryptionFailed),
                }
            }
            Err(_) => Err(MessageError::DecryptionFailed),
        },
        _ => Err(MessageError::AgreementKeyConversionFailed),
    }
}

fn arm(
    node: &Node,
    recipient: &[u8; crypto::ED25519_PUBLICKEYBYTES],
    armed_len: u16,
    buf: &mut [u8],
) -> Result<(), MessageError> {
    let my_agreement_public_key =
        crypto::convert_identity_public_key_to_key_agreement_public_key(node.public_key());
    let my_agreement_private_key =
        crypto::convert_identity_secret_key_to_key_agreement_secret_key(node.secret_key());
    let peer_agreement_public_key =
        crypto::convert_identity_public_key_to_key_agreement_public_key(recipient);

    match (
        my_agreement_public_key,
        my_agreement_private_key,
        peer_agreement_public_key,
    ) {
        (
            Ok(our_agreement_public_key),
            Ok(our_agreement_private_key),
            Ok(peer_agreement_public_key),
        ) => match crypto::generate_session_key_pair(
            &our_agreement_public_key,
            &our_agreement_private_key,
            &peer_agreement_public_key,
        ) {
            Ok((_, tx_key)) => {
                let (public_header_slice, body_slice) = buf.split_at_mut(PUBLIC_HEADER_LEN);
                let public_header_slice: &mut [u8; PUBLIC_HEADER_LEN] =
                    public_header_slice.try_into().unwrap(); // set known length
                let (private_header_slice, body_slice) =
                    body_slice.split_at_mut(PRIVATE_HEADER_ARMED_LEN);
                let private_header_slice: &mut [u8; PRIVATE_HEADER_ARMED_LEN] =
                    private_header_slice.try_into().unwrap(); // set known length

                // obtain nonce from buf
                let nonce = <&[u8; PUBLIC_HEADER_NONCE_LEN]>::try_from(
                    &public_header_slice[PUBLIC_HEADER_NONCE_IDX..][..PUBLIC_HEADER_NONCE_LEN],
                )
                .unwrap();

                // no need to build auth tag
                let auth_tag = &public_header_slice[PUBLIC_HEADER_MAGIC_NUMBER_LEN..];

                match crypto::encrypt(
                    &private_header_slice[..PRIVATE_HEADER_UNARMED_LEN],
                    auth_tag,
                    nonce,
                    tx_key,
                ) {
                    Ok(encrypted_header) => {
                        // Überschreibe den unverschlüsselten Header mit dem verschlüsselten Header
                        private_header_slice.copy_from_slice(&encrypted_header);

                        if armed_len > 0 {
                            match crypto::encrypt(
                                &body_slice[..armed_len as usize],
                                &[],
                                nonce,
                                tx_key,
                            ) {
                                Ok(encrypted_body) => {
                                    body_slice.copy_from_slice(&encrypted_body);
                                    Ok(())
                                }
                                Err(_) => Err(MessageError::EncryptionFailed),
                            }
                        } else {
                            // Kein zusätzlicher verschlüsselter Teil
                            Ok(())
                        }
                    }
                    Err(_) => Err(MessageError::EncryptionFailed),
                }
            }
            Err(_) => Err(MessageError::EncryptionFailed),
        },
        _ => Err(MessageError::AgreementKeyConversionFailed),
    }
}
