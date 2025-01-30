use crate::messages::*;
use crate::node::Node;
use crate::peers::PeersManagerError;
use crate::utils::crypto;
use log::trace;
use std::fmt;
use std::io::Error;
use std::net::SocketAddr;

#[derive(Debug)]
pub enum ServerError {
    HelloChildrenTimeInvalid,
    SendFailed(Error),
    MessageError(MessageError),
    HopCountExceeded,
    ForwardRecipientOffline,
    PublicHeaderMissing,
    PrivateHeaderMissing,
    UnexpectedMessage(u8),
    UnarmedMessageReceived,
    InvalidPow,
    ForwardRecipientIdenticalToSender,
    PeersManagerError(PeersManagerError),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerError::HelloChildrenTimeInvalid => {
                write!(f, "HELLO message has invalid children_time")
            }
            ServerError::SendFailed(e) => {
                write!(f, "Send failed: {}", e)
            }
            ServerError::MessageError(e) => {
                write!(f, "Message error: {}", e)
            }
            ServerError::HopCountExceeded => {
                write!(f, "Hop count exceeded")
            }
            ServerError::ForwardRecipientOffline => {
                write!(f, "Forward recipient offline")
            }
            ServerError::PublicHeaderMissing => {
                write!(f, "Message to short to contain a public header")
            }
            ServerError::PrivateHeaderMissing => {
                write!(f, "Message to short to contain a private header")
            }
            ServerError::UnexpectedMessage(message_type) => {
                write!(f, "Unexpected message: {}", message_type)
            }
            ServerError::UnarmedMessageReceived => {
                write!(f, "Received unarmed message")
            }
            ServerError::InvalidPow => {
                write!(f, "Invalid proof of work")
            }
            ServerError::ForwardRecipientIdenticalToSender => {
                write!(f, "Forward recipient identical to sender")
            }
            ServerError::PeersManagerError(e) => {
                write!(f, "Peers manager error: {}", e)
            }
        }
    }
}

pub fn on_datagram(node: &Node, buf: &mut [u8], src: SocketAddr) -> Result<(), ServerError> {
    if buf.len() < PUBLIC_HEADER_LEN {
        return Err(ServerError::PublicHeaderMissing);
    }

    let (public_header_slice, private_header_and_body_slice) = buf.split_at_mut(PUBLIC_HEADER_LEN);
    let public_header_slice: &mut [u8; PUBLIC_HEADER_LEN] = public_header_slice.try_into().unwrap(); // set known length

    match PublicHeader::from_bytes(public_header_slice, node.network_id()) {
        Ok(public_header) => {
            trace!("{}", public_header);

            if public_header.recipient == node.public_key() {
                match node
                    .peers()
                    .valid_pow(public_header.sender, public_header.pow, node.now())
                {
                    Ok(valid_pow) => {
                        if !valid_pow {
                            return Err(ServerError::InvalidPow);
                        }
                    }
                    Err(e) => return Err(ServerError::PeersManagerError(e)),
                }

                if !*crate::ACCEPT_UNARMED_MESSAGES && !public_header.is_armed() {
                    return Err(ServerError::UnarmedMessageReceived);
                }

                if private_header_and_body_slice.len() < PRIVATE_HEADER_UNARMED_LEN {
                    return Err(ServerError::PrivateHeaderMissing);
                }

                let private_header: Result<PrivateHeader, MessageError> =
                    if public_header.is_armed() {
                        disarm(
                            node,
                            &public_header,
                            public_header_slice,
                            private_header_and_body_slice,
                        )
                    } else {
                        PrivateHeader::from_bytes(
                            <&[u8; PRIVATE_HEADER_UNARMED_LEN]>::try_from(
                                &private_header_and_body_slice[..PRIVATE_HEADER_UNARMED_LEN],
                            )
                            .unwrap(),
                        )
                    };

                match private_header {
                    Ok(private_header) => {
                        trace!("{}", private_header);

                        let message_type = *private_header.message_type;
                        match message_type {
                            MessageType::HELLO => {
                                // get body slice
                                let private_header_len = if public_header.is_armed() {
                                    PRIVATE_HEADER_ARMED_LEN
                                } else {
                                    PRIVATE_HEADER_UNARMED_LEN
                                };
                                let body = &private_header_and_body_slice[private_header_len..];

                                match message_type {
                                    MessageType::HELLO => {
                                        match HelloMessage::from_bytes(body, node.now()) {
                                            Ok(hello) => {
                                                on_hello(node, src, &public_header, &hello)
                                            }
                                            Err(e) => Err(ServerError::MessageError(e)),
                                        }
                                    }
                                    _ => unreachable!(),
                                }
                            }
                            _ => Err(ServerError::UnexpectedMessage(message_type)),
                        }
                    }
                    Err(e) => Err(ServerError::MessageError(e)),
                }
            } else {
                let hop_count = public_header.hop_count();
                let recipient = *public_header.recipient;
                let sender = *public_header.sender;

                forward(node, hop_count, &recipient, &sender, buf)
            }
        }
        Err(e) => Err(ServerError::MessageError(e)),
    }
}

fn on_ack(
    _node: &Node,
    _src: SocketAddr,
    _public_header: &PublicHeader,
    ack: &AckMessage,
) -> Result<(), ServerError> {
    trace!("{}", ack);
    todo!()
}

fn on_app(
    _node: &Node,
    _src: SocketAddr,
    _public_header: &PublicHeader,
    app: &AppMessage,
) -> Result<(), ServerError> {
    trace!("{}", app);
    todo!()
}

fn on_hello(
    node: &Node,
    src: SocketAddr,
    public_header: &PublicHeader,
    hello: &HelloMessage,
) -> Result<(), ServerError> {
    trace!("{}", hello);

    // we're super peer!
    if hello.children_time == &[0; 8] {
        return Err(ServerError::HelloChildrenTimeInvalid);
    }

    // update peer information
    match node.peers().hello_received(
        public_header.sender,
        src,
        node.now(),
        hello.endpoints.clone(),
    ) {
        Ok(_) => {
            // reply with ACK
            match AckMessage::new(node, *crate::ARM_MESSAGES, public_header.sender, hello.time) {
                Ok(buf) => {
                    if let Err(e) = node.socket().send_to(&buf, src) {
                        return Err(ServerError::SendFailed(e));
                    }
                    Ok(())
                }
                Err(e) => Err(ServerError::MessageError(e)),
            }
        }
        Err(e) => Err(ServerError::PeersManagerError(e)),
    }
}

fn on_unite(
    _node: &Node,
    _src: SocketAddr,
    _public_header: &PublicHeader,
    unite: &UniteMessage,
) -> Result<(), ServerError> {
    trace!("{}", unite);
    todo!()
}

fn forward(
    node: &Node,
    hop_count: u8,
    recipient: &[u8; crypto::ED25519_PUBLICKEYBYTES],
    sender: &[u8; crypto::ED25519_PUBLICKEYBYTES],
    buf: &mut [u8],
) -> Result<(), ServerError> {
    // forwarding to yourself makes no sense :)
    if recipient == sender {
        return Err(ServerError::ForwardRecipientIdenticalToSender);
    }

    // verify if hop count is exceeded
    if hop_count > *crate::HOP_COUNT_LIMIT {
        return Err(ServerError::HopCountExceeded);
    }

    // search recipient
    match node.peers().get_peer(recipient) {
        Some(peer) => {
            if peer.is_online(node.now()) {
                // increment hop count
                let incremented_hop_count = hop_count + 1u8;
                let flags_offset = PUBLIC_HEADER_MAGIC_NUMBER_LEN; // = 4
                buf[flags_offset] = (buf[flags_offset] & 0b00011111) | (incremented_hop_count << 5);

                if let Err(e) = node.socket().send_to(buf, peer.last_hello_src().unwrap()) {
                    return Err(ServerError::SendFailed(e));
                }
                trace!("Forwarded message to {}.", *peer);

                // hole punching
                let now = node.now();
                if node.peers().send_unites(sender, recipient, now) {
                    let _ = match (
                        node.peers().get_peer(sender),
                        node.peers().get_peer(recipient),
                    ) {
                        (Some(sender_peer), Some(recipient_peer)) => {
                            if sender_peer.is_online(now) && recipient_peer.is_online(now) {
                                // send sender all information we have to reach recipient
                                let recipient_candidates = recipient_peer.contact_candidates();
                                let sender_unite = UniteMessage::new(
                                    node,
                                    *crate::ARM_MESSAGES,
                                    sender,
                                    recipient,
                                    recipient_candidates,
                                );

                                // send recipient all information we have to reach sender
                                let sender_candidates = sender_peer.contact_candidates();
                                let recipient_unite = UniteMessage::new(
                                    node,
                                    *crate::ARM_MESSAGES,
                                    recipient,
                                    sender,
                                    sender_candidates,
                                );

                                match (sender_unite, recipient_unite) {
                                    (Ok(sender_unite), Ok(recipient_unite)) => {
                                        let sender_result = node.socket().send_to(
                                            &sender_unite,
                                            sender_peer.last_hello_src().unwrap(),
                                        );
                                        let recipient_result = node.socket().send_to(
                                            &recipient_unite,
                                            sender_peer.last_hello_src().unwrap(),
                                        );
                                        match (sender_result, recipient_result) {
                                            (Ok(_), Ok(_)) => Ok(()),
                                            _ => Err(()),
                                        }
                                    }
                                    _ => Err(()),
                                }
                            } else {
                                Ok(())
                            }
                        }
                        _ => Ok(()),
                    };
                }

                Ok(())
            } else {
                Err(ServerError::ForwardRecipientOffline)
            }
        }
        None => Err(ServerError::ForwardRecipientOffline),
    }
}
