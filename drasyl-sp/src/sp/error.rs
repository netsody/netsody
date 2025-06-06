use crate::sp::PeersError;
use drasyl::identity::PubKey;
use drasyl::message::{MessageType, NetworkId};
use drasyl::{crypto, message};
use std::io;
use thiserror::Error;
use tokio::task::JoinError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Send failed: {0}")]
    SendFailed(#[from] io::Error),

    #[error("Message error: {0}")]
    MessageError(#[from] message::Error),

    #[error("Peers manager error: {0}")]
    PeersError(#[from] PeersError),

    #[error("Crypto error: {0}")]
    CryptoError(#[from] crypto::Error),

    #[error("UDP4 bind error: {0}")]
    Udp4BindError(io::Error),

    #[error("UDP6 bind error: {0}")]
    Udp6BindError(io::Error),

    #[error("TCP4 bind error: {0}")]
    Tcp4BindError(io::Error),

    #[error("TCP6 bind error: {0}")]
    Tcp6BindError(io::Error),

    #[error("Message from other network: {}", i32::from_be_bytes(*.0))]
    NetworkIdInvalid(NetworkId),

    #[error("Invalid proof of work")]
    PowInvalid,

    #[error("Received an unarmed message where an armed message was expected")]
    MessageUnarmed,

    #[error("Received an armed message where an unarmed message was expected")]
    MessageArmed,

    #[error("Unexpected message type {0}")]
    MessageTypeUnexpected(MessageType),

    #[error("HELLO from {0} time diff too large: {1} ms")]
    HelloTimeInvalid(PubKey, u64),

    #[error("Loopback forwarding not allowed")]
    LoopbackForwarding,

    #[error("Task error: {0}")]
    TaskError(#[from] JoinError),

    #[error("UDP4 failed: {0}")]
    Udp4Failed(JoinError),

    #[error("UDP6 failed: {0}")]
    Udp6Failed(JoinError),

    #[error("TCP4 failed: {0}")]
    Tcp4Failed(JoinError),

    #[error("TCP6 failed: {0}")]
    Tcp6Failed(JoinError),

    #[error("Neither UDP nor TCP servers has been started")]
    NeitherUdpNorTcpServers,

    #[error("No route to peer: {0}")]
    NoRouteToPeer(PubKey),
}
