use crate::message::long_header::MagicNumber;
use std::array::TryFromSliceError;
use std::net::IpAddr;
use thiserror::Error;

/// Error type for message operations in the Netsody protocol.
///
/// This enum represents all possible errors that can occur during message operations,
/// including parsing, building, and validation of message types.
///
#[derive(Debug, Error)]
pub enum Error {
    #[error("Packet too short to contain an APP: {0}")]
    AppMessageInvalid(String),

    #[error("Packet too short to contain a HELLO: {0}")]
    HelloMessageInvalid(String),

    #[error("Packet too short to contain a UNITE: {0}")]
    UniteMessageInvalid(String),

    #[error("Packet too short to contain an armed message")]
    ArmedMessageInvalid,

    #[error("Invalid magic number: {0:?}")]
    MagicNumberInvalid(MagicNumber),

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

    #[error("Invalid endpoint: {0}")]
    EndpointInvalid(String),

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

    #[error("Invalid short id")]
    InvalidShortId,
}
