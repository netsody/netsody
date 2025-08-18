use crate::identity::PubKey;
use crate::message::{MessageType, NetworkId};
use crate::peer::TransportProt;
use crate::{crypto, message, peer};
use std::io;
use std::net::{AddrParseError, SocketAddr};
use thiserror::Error;
use tokio::task::JoinError;

/// Error type for operations on a [`crate::node::Node`].
///
/// This enum represents all possible errors that can occur during node operations,
/// including message sending, peer management, and network communication.
///
/// # Categories
///
/// The errors can be grouped into several categories:
///
/// ## Network Communication
/// * [`SendFailed`](Error::SendFailed) - Failed to send a message via a specific transport protocol
/// * [`BindError`](Error::BindError) - Failed to bind to a network address
/// * [`BindParseError`](Error::BindParseError) - Invalid network address format
/// * [`GetAddrsFailed`](Error::GetAddrsFailed) - Failed to get network addresses
/// * [`UdpLocalAddrError`](Error::UdpLocalAddrError) - Failed to get UDP socket local address
///
/// ## Message Handling
/// * [`MessageError`](Error::MessageError) - General message processing error
/// * [`MessageTypeUnexpected`](Error::MessageTypeUnexpected) - Received unexpected message type
/// * [`MessageTypeInvalid`](Error::MessageTypeInvalid) - Invalid message type
/// * [`MessageInvalidRecipient`](Error::MessageInvalidRecipient) - Message not intended for this node
/// * [`MessageUnarmed`](Error::MessageUnarmed) - Received unencrypted message when encrypted was expected
/// * [`MessageArmed`](Error::MessageArmed) - Received encrypted message when unencrypted was expected
/// * [`AppLenInvalid`](Error::AppLenInvalid) - Message payload exceeds MTU
///
/// ## Security
/// * [`CryptoError`](Error::CryptoError) - Cryptographic operation failed
/// * [`PowInvalid`](Error::PowInvalid) - Invalid proof of work
/// * [`NetworkIdInvalid`](Error::NetworkIdInvalid) - Message from different network
///
/// ## Peer Management
/// * [`PeersError`](Error::PeerError) - Error in peer management
/// * [`NoSuperPeers`](Error::NoSuperPeers) - No super peers available
/// * [`PeerNotPresent`](Error::PeerNotPresent) - Requested peer not found
/// * [`PeersListCapacityExceeded`](Error::PeersListCapacityExceeded) - Too many peers
/// * [`SendHandleAlreadyCreated`](Error::SendHandleAlreadyCreated) - Send handle already exists
/// * [`SendHandleClosed`](Error::SendHandleClosed) - Send handle was closed
///
/// ## Protocol Timing
/// * [`HelloTooOld`](Error::HelloTooOld) - Received HELLO message is too old
/// * [`AckTimeIsInFuture`](Error::AckTimeIsInFuture) - ACK timestamp is in the future
/// * [`AckTooOld`](Error::AckTooOld) - ACK message is too old
///
/// # Example
///
/// ```rust
/// use drasyl_p2p::node::Error;
///
/// fn handle_error(error: Error) {
///     match error {
///         Error::SendFailed(transport, io_error) => {
///             eprintln!("Failed to send message via {}: {}", transport, io_error);
///         }
///         Error::MessageInvalidRecipient => {
///             eprintln!("Received message not intended for this node");
///         }
///         // Handle other error variants...
///         _ => eprintln!("Other error: {}", error),
///     }
/// }
/// ```
#[derive(Debug, Error)]
pub enum Error {
    #[error("Send via {0} failed: {1}")]
    SendFailed(TransportProt, io::Error),

    #[error("Message error: {0}")]
    MessageError(#[from] message::Error),

    #[error("Peer error: {0}")]
    PeerError(#[from] peer::Error),

    #[error("Crypto error: {0}")]
    CryptoError(#[from] crypto::Error),

    #[error("Bind parse error: {0}")]
    BindParseError(AddrParseError),

    #[error("Bind error: {0}")]
    BindError(io::Error),

    #[error("Message from other network: {}", i32::from_be_bytes(*.0))]
    NetworkIdInvalid(NetworkId),

    #[error("Super peers have inconsistent network IDs: expected {}, but found {}", i32::from_be_bytes(*.0), i32::from_be_bytes(*.1))]
    SuperPeerNetworkIdMismatch(NetworkId, NetworkId),

    #[error("Invalid proof of work")]
    PowInvalid,

    #[error("Received an unarmed message where an armed message was expected")]
    MessageUnarmed,

    #[error("Received an armed message where an unarmed message was expected")]
    MessageArmed,

    #[error("Unexpected message type {0}")]
    MessageTypeUnexpected(MessageType),

    #[error("No super peers")]
    NoSuperPeers,

    #[error("Message invalid recipient")]
    MessageInvalidRecipient,

    #[error("HELLO time too old: {0} ms")]
    HelloTooOld(u64),

    #[error("ACK time is in the future")]
    AckTimeIsInFuture,

    #[error("ACK time too old: {0} ms")]
    AckTooOld(u64),

    #[error("Recv buf is closed")]
    RecvBufDisconnected,

    #[error("Message type invalid")]
    MessageTypeInvalid,

    #[error("Get addrs failed: {0}")]
    GetAddrsFailed(io::Error),

    #[error("Sending direct to {1} error: {0}")]
    SendingDirectError(io::Error, SocketAddr),

    #[error("Failed to relay message for {0} via {1}")]
    SendingRelayedError(PubKey, PubKey),

    #[error("UDP local_addr error: {0}")]
    UdpLocalAddrError(io::Error),

    #[error("Peer not present")]
    PeerNotPresent,

    #[error("TCP shutdown error: {0}")]
    TcpShutdownError(io::Error),

    #[error("Housekeeping failed: {0}")]
    HousekeepingFailed(#[from] JoinError),

    #[error("Invalid HELLO endpoint: {0}")]
    HelloEndpointInvalid(String),

    #[error("Invalid HELLO address: {0}")]
    HelloAddressInvalid(String),

    #[error("APP len {0} is larger than MTU {1}")]
    AppLenInvalid(usize, usize),

    #[error("Peers list capacity ({0}) exceeded")]
    PeersListCapacityExceeded(u64),

    #[error("Super peer host lookup returned no usable address matching node's listen addr")]
    SuperPeerResolveWrongFamily,

    #[error("Send handle for peer already exist")]
    SendHandleAlreadyCreated,

    #[error("Short id received after peer removal")]
    ShortIdOutdated,

    #[error("Send handle is closed due to node drop")]
    SendHandleClosed,

    #[error("Cannot create send handle for super peer {0}")]
    RecipientIsSuperPeer(PubKey),
}
