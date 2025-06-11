use crate::identity::{Identity, PubKey};
use crate::message::NetworkId;
use crate::peer::SuperPeerUrl;
use derive_builder::Builder;
use lazy_static::lazy_static;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

/// Default network identifier for the drasyl network.
/// Nodes with different network IDs cannot communicate with each other.
pub const NETWORK_ID_DEFAULT: i32 = 1;
/// Default setting for message encryption.
/// When true, all messages are encrypted using the node's cryptographic keys.
pub const ARM_MESSAGES_DEFAULT: bool = true;
/// Default maximum number of peers a node can connect to.
/// Set to 0 to remove the peer limit.
pub const MAX_PEERS_DEFAULT: u64 = 1 << 13;
/// Default minimum proof of work difficulty required for peer connections.
/// Higher values make it harder for peers to connect, providing protection against spam.
pub const MIN_POW_DIFFICULTY_DEFAULT: u8 = 24;
/// Default timeout in milliseconds for HELLO message responses.
/// If no response is received within this time, the connection attempt is considered failed.
pub const HELLO_TIMEOUT_DEFAULT: u64 = 30 * 1_000;
/// Default maximum age in milliseconds for HELLO messages.
/// Messages older than this are considered invalid and will be rejected.
pub const HELLO_MAX_AGE_DEFAULT: u64 = 300 * 1_000;
/// Default Maximum Transmission Unit size in bytes.
/// Calculated as: Ethernet MTU (1500) - IPv4 header (20) - UDP header (8)
pub const MTU_DEFAULT: usize = 1472;
/// Default setting for processing UNITE messages.
/// When true, the node will process UNITE messages for peer discovery.
pub const PROCESS_UNITES_DEFAULT: bool = true;
/// Default interval in milliseconds between housekeeping tasks.
/// These tasks maintain the health of peer connections and clean up stale data.
pub const HOUSEKEEPING_INTERVAL_DEFAULT: u64 = 5 * 1_000;
/// Default number of UDP sockets to create for each IP address.
/// Multiple sockets can improve performance on multi-core systems.
pub const UDP_SOCKETS_DEFAULT: usize = 1;
/// Timeout in milliseconds for direct peer connections.
/// If no communication occurs within this time, the direct connection is considered lost.
pub(crate) const DIRECT_LINK_TIMEOUT: u64 = 60_000;
/// Timeout in milliseconds for DNS lookups.
/// If a hostname cannot be resolved within this time, the lookup is considered failed.
pub(crate) const DNS_LOOKUP_TIMEOUT: u64 = 2_000;

lazy_static! {
    /// Default list of super peers for the drasyl network.
    /// These servers help with peer discovery and message relaying.
    pub static ref SUPER_PEERS_DEFAULT: Vec<SuperPeerUrl> = vec![
        // SuperPeerUrl::from_str("udp://sp-fkb1.drasyl.org:22527?publicKey=c0900bcfabc493d062ecd293265f571edb70b85313ba4cdda96c9f77163ba62d&networkId=1&tcpPort=8443").unwrap(),
        SuperPeerUrl::from_str("udp://sp-rjl1.drasyl.org:22527?publicKey=5b4578909bf0ad3565bb5faf843a9f68b325dd87451f6cb747e49d82f6ce5f4c&networkId=1&tcpPort=8443").unwrap(),
        SuperPeerUrl::from_str("udp://sp-nyc1.drasyl.org:22527?publicKey=bf3572dba7ebb6c5ccd037f3a978707b5d7c5a9b9b01b56b4b9bf059af56a4e0&networkId=1&tcpPort=8443").unwrap(),
        SuperPeerUrl::from_str("udp://sp-sgp1.drasyl.org:22527?publicKey=ab7a1654d463f9986530bed00569cc895697827b802153b8ef1598579713045f&networkId=1&tcpPort=8443").unwrap(),
    ];
}

/// Configuration options for creating a new [`crate::node::Node`].
///
/// This struct contains all the necessary configuration parameters for initializing a drasyl node.
/// It is recommended to use [`NodeOptsBuilder`] to create instances of this struct, as it provides
/// a more convenient way to set optional parameters with default values.
///
/// # Required Parameters
///
/// The following parameters must be set when creating a new node:
/// * `id` - The node's identity
/// * `message_sink` - The message sink for receiving messages
///
/// All other parameters have sensible default values that can be overridden if needed.
///
/// # Example
///
/// ```rust
/// use drasyl::node::{Node, NodeOpts, NodeOptsBuilder, Identity, MIN_POW_DIFFICULTY_DEFAULT};
///
/// async fn example() {
///     // Create or load an identity
///     let identity = Identity::load_or_generate("drasyl.identity", MIN_POW_DIFFICULTY_DEFAULT).expect("Failed to load identity");
///     
///     // Create node options using the builder pattern
///     let opts = NodeOptsBuilder::default()
///         .id(identity)
///         .arm_messages(true)  // Enable message encryption
///         .max_peers(1024)     // Set maximum number of peers
///         .build().expect("Failed to build node opts");
///     
///     // Use the options to create a node
///     let node = Node::bind(opts).await.expect("Failed to bind node");
/// }
/// ```
///
/// # Default Values
///
/// Most fields have sensible default values that can be overridden using the builder:
/// * `network_id`: [`NETWORK_ID_DEFAULT`]
/// * `arm_messages`: [`ARM_MESSAGES_DEFAULT`]
/// * `max_peers`: [`MAX_PEERS_DEFAULT`]
/// * `min_pow_difficulty`: [`MIN_POW_DIFFICULTY_DEFAULT`]
/// * `hello_timeout`: [`HELLO_TIMEOUT_DEFAULT`]
/// * `hello_max_age`: [`HELLO_MAX_AGE_DEFAULT`]
/// * `super_peers`: [`SUPER_PEERS_DEFAULT`]
/// * `mtu`: [`MTU_DEFAULT`]
/// * `process_unites`: [`PROCESS_UNITES_DEFAULT`]
/// * `housekeeping_interval`: [`HOUSEKEEPING_INTERVAL_DEFAULT`]
/// * `udp_sockets`: [`UDP_SOCKETS_DEFAULT`]
#[derive(Builder, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NodeOpts {
    /// The identity of this node, containing its public/private key pair and proof of work.
    /// This is a required parameter with no default value.
    pub id: Identity,
    /// The message sink that receives all incoming messages for this node.
    /// This is a required parameter with no default value.
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing, skip_deserializing, default = "dummy_message_sink")
    )]
    pub message_sink: Arc<dyn MessageSink>,
    /// The network identifier to ensure nodes only communicate within the same network.
    /// Default: [`NETWORK_ID_DEFAULT`]
    #[builder(default = "NETWORK_ID_DEFAULT.to_be_bytes()")]
    pub network_id: NetworkId,
    /// List of IP addresses to bind UDP sockets to; if empty, all available addresses are used.
    /// Default: empty vector (all available addresses)
    #[builder(default)]
    pub udp_addrs: Vec<IpAddr>,
    /// UDP port to bind to; if None, a port is derived from the node's public key.
    /// Default: None (derived from public key)
    #[builder(default)]
    pub udp_port: Option<u16>,
    /// Number of UDP sockets to create for each IP address.
    /// Default: [`UDP_SOCKETS_DEFAULT`]
    #[builder(default = "UDP_SOCKETS_DEFAULT")]
    pub udp_sockets: usize,
    /// Whether to encrypt messages using the node's cryptographic keys.
    /// Default: [`ARM_MESSAGES_DEFAULT`]
    #[builder(default = "ARM_MESSAGES_DEFAULT")]
    pub arm_messages: bool,
    /// Maximum number of peers this node can maintain connections with.
    /// Default: [`MAX_PEERS_DEFAULT`]
    #[builder(default = "MAX_PEERS_DEFAULT")]
    pub max_peers: u64,
    /// Minimum proof of work difficulty required for peer connections.
    /// Default: [`MIN_POW_DIFFICULTY_DEFAULT`]
    #[builder(default = "MIN_POW_DIFFICULTY_DEFAULT")]
    pub min_pow_difficulty: u8,
    /// Timeout in milliseconds for HELLO message responses.
    /// Default: [`HELLO_TIMEOUT_DEFAULT`]
    #[builder(default = "HELLO_TIMEOUT_DEFAULT")]
    pub hello_timeout: u64,
    /// Maximum age in milliseconds for HELLO messages before they are considered invalid.
    /// Default: [`HELLO_MAX_AGE_DEFAULT`]
    #[builder(default = "HELLO_MAX_AGE_DEFAULT")]
    pub hello_max_age: u64,
    /// List of super peer URLs that this node can use for message relaying.
    /// Default: [`SUPER_PEERS_DEFAULT`]
    #[builder(default = "SUPER_PEERS_DEFAULT.clone()")]
    pub super_peers: Vec<SuperPeerUrl>,
    /// Maximum Transmission Unit size in bytes for network packets.
    /// Default: [`MTU_DEFAULT`]
    #[builder(default = "MTU_DEFAULT")]
    pub mtu: usize,
    /// Whether to process UNITE messages for peer discovery.
    /// Default: [`PROCESS_UNITES_DEFAULT`]
    #[builder(default = "PROCESS_UNITES_DEFAULT")]
    pub process_unites: bool,
    /// Interval in milliseconds between housekeeping tasks.
    /// Default: [`HOUSEKEEPING_INTERVAL_DEFAULT`]
    #[builder(default = "HOUSEKEEPING_INTERVAL_DEFAULT")]
    pub housekeeping_interval: u64,
    /// Whether to enforce TCP connections for all communication.
    /// Default: false
    #[builder(default)]
    pub enforce_tcp: bool,
    #[cfg(feature = "prometheus")]
    #[builder(default)]
    pub prometheus_url: Option<String>,
    #[cfg(feature = "prometheus")]
    #[builder(default)]
    pub prometheus_user: Option<String>,
    #[cfg(feature = "prometheus")]
    #[builder(default)]
    pub prometheus_pass: Option<String>,
}

pub const COMPRESSION: bool = false;

/// A trait for receiving messages from the drasyl network.
///
/// This trait defines the interface for handling incoming messages in a drasyl node.
/// Implementations of this trait will receive all messages that are sent to the node.
pub trait MessageSink: Send + Sync {
    /// Called when a message is received from a peer.
    ///
    /// # Arguments
    ///
    /// * `sender` - The public key of the peer that sent the message
    /// * `message` - The raw message payload
    ///
    /// # Implementation Notes
    ///
    /// * This method should handle messages quickly to avoid blocking the network thread
    /// * Consider using channels or other async mechanisms for message processing
    /// * The message payload is already decrypted if the node is configured with `arm_messages`
    fn accept(&self, sender: PubKey, message: Vec<u8>);
}

#[cfg(feature = "serde")]
pub struct DummySink;

#[cfg(feature = "serde")]
impl MessageSink for DummySink {
    fn accept(&self, _: PubKey, _: Vec<u8>) {
        panic!("DummySink should not be used!");
    }
}

#[cfg(feature = "serde")]
fn dummy_message_sink() -> Arc<dyn MessageSink> {
    Arc::new(DummySink {})
}
