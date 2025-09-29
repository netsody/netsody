//! # Node used to communicate with peers via the Netsody network.
//!
//! This module provides the core networking functionality for the Netsody peer-to-peer network.
//! It implements the central `Node` structure that serves as the main entry point for all
//! network operations, peer management, and message routing.
//!
//! ## Overview
//!
//! The node module is the heart of the Netsody network stack, responsible for:
//! - Managing network connections (UDP/TCP)
//! - Peer discovery and connection establishment
//! - Message routing and delivery
//! - Network security and encryption
//! - Protocol housekeeping and maintenance
//!
//! ## Architecture
//!
//! The module follows a layered architecture with clear separation of concerns:
//!
//! ### Core Components
//! - **Node**: The main public interface for network operations
//! - **NodeInner**: Internal implementation handling low-level networking
//! - **NodeOpts**: Configuration builder for node initialization
//! - **SendHandle**: Handle for sending messages to specific peers
//!
//! ### Network Transport
//! - **UDP**: Primary transport protocol for peer-to-peer communication
//! - **TCP**: Fallback transport when UDP communication to super peers is blocked
//!
//! ### Peer Management
//! - **Super Peers**: Relay nodes for network discovery and message routing
//! - **Node Peers**: Direct peer-to-peer connections
//! - **Peers List**: Thread-safe collection of all known peers
//!
//! ### Supporting Infrastructure
//! - **Error Handling**: Comprehensive error types for network operations
//! - **Housekeeping**: Background tasks for connection maintenance
//! - **Options**: Flexible configuration system
//!
//! ## Key Features
//!
//! ### Security
//! - End-to-end encryption using Curve25519 and Ed25519 cryptography
//! - Message authentication and integrity verification
//! - Configurable proof-of-work for spam protection
//!
//! ### Network Resilience
//! - Automatic peer discovery and connection recovery
//! - Multiple transport protocols with automatic fallback
//! - NAT traversal using UNITE messages
//! - Connection pooling and load balancing
//!
//! ### Performance
//! - Asynchronous I/O with Tokio runtime
//! - Connection reuse and multiplexing
//! - Configurable buffer sizes and timeouts
//! - Efficient message routing algorithms
//!
//! ## Usage Patterns
//!
//! ### Basic Node Creation
//! ```rust,ignore
//! use netsody_p2p::node::{Node, NodeOpts};
//! use netsody_p2p::identity::Identity;
//!
//! // Create node with default configuration
//! let identity = Identity::generate(24)?;
//! let opts = NodeOpts::builder().id(identity).build().expect("Failed to build node opts");
//! let node = Node::bind(opts).await?;
//! ```
//!
//! ### Advanced Configuration
//! ```rust,ignore
//! let opts = NodeOpts::builder()
//!     .id(identity)
//!     .arm_messages(true)           // Enable encryption
//!     .max_peers(2048)              // Set peer limit
//!     .udp_sockets(4)               // Multiple UDP sockets
//!     .hello_timeout(30_000)        // Connection timeout
//!     .build().expect("Failed to build node opts");
//! ```
//!
//! ### Message Sending
//! ```rust,ignore
//! // Direct sending
//! node.send_to(&recipient_key, &message_data).await.expect("Failed to send message");
//!
//! // Using send handles for repeated communication
//! let handle = node.send_handle(&recipient_key).expect("Failed to create send handle");
//! handle.send(&message_data).await.expect("Failed to send message");
//! ```
//!
//! ## Thread Safety
//!
//! All public APIs are thread-safe and can be safely shared across async tasks.
//! The internal implementation uses lock-free data structures where possible
//! for optimal performance in concurrent environments.

mod error;
mod housekeeping;
mod inner;
mod opts;
mod send_handle;
mod tcp;
mod udp;

use crate::crypto::{convert_ed25519_pk_to_curve25519_pk, convert_ed25519_sk_to_curve25519_sk};
pub use crate::identity::{Identity, PubKey};
use crate::peer::{Peer, PeersList, SuperPeer};
use crate::util::get_addrs;
use ahash::RandomState;
pub use error::*;
use housekeeping::UdpBindingGuard;
pub use inner::NodeInner;
pub use opts::*;
use papaya::HashMap as PapayaHashMap;
pub use send_handle::*;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::AtomicPtr;
pub(crate) use tcp::*;
use tokio::task::JoinSet;
use tokio_util::sync::{CancellationToken, WaitForCancellationFuture};
use tracing::{error, instrument, trace, warn};
pub use udp::*;

/// The central access point for communication over the Netsody network.
///
/// A `Node` represents a participant in the Netsody network and provides the main interface
/// for sending and receiving messages. It manages network connections, peer discovery,
/// and message routing.
///
/// # Features
///
/// * Secure end-to-end encrypted communication
/// * Peer-to-peer and relayed message delivery
/// * Automatic peer discovery and connection management
/// * Support for both UDP and TCP transport protocols
/// * Configurable network parameters and security settings
///
/// # Example
///
/// ```rust
/// use netsody_p2p::node::{Node, NodeOpts, NodeOptsBuilder, Identity, MIN_POW_DIFFICULTY_DEFAULT};
///
/// async fn example() {
///     // Create or load an identity
///     let identity = Identity::load_or_generate("netsody.identity", MIN_POW_DIFFICULTY_DEFAULT).expect("Failed to load identity");
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
pub struct Node {
    pub inner: Arc<NodeInner>,
}

impl Node {
    // #[instrument(skip_all, fields(pk = %opts.id.pk))]
    #[instrument(skip_all)]
    pub async fn bind(opts: NodeOpts) -> Result<Self, Error> {
        // generate agreement keys
        let (agreement_sk, agreement_pk) = if opts.arm_messages {
            (
                Some(convert_ed25519_sk_to_curve25519_sk(&opts.id.sk.into())?),
                Some(convert_ed25519_pk_to_curve25519_pk(&opts.id.pk.into())?),
            )
        } else {
            (None, None)
        };

        // collect addresses we bind to
        let udp_addrs = if opts.udp_addrs.is_empty() {
            get_addrs().map_err(Error::GetAddrsFailed)?
        } else {
            opts.udp_addrs
                .clone()
                .into_iter()
                .map(|ip| (String::new(), ip))
                .collect()
        };
        trace!("UDP addresses: {:?}", udp_addrs);

        // port we bind to
        let udp_port = if let Some(udp_port) = opts.udp_port {
            udp_port
        } else {
            opts.id.pk.udp_port()
        };
        trace!("UDP port: {}", udp_port);

        // node cancellation token
        let cancellation_token = CancellationToken::new();

        // start udp servers
        let num_udp_sockets = opts.udp_sockets;
        let mut udp_bindings = Vec::with_capacity(num_udp_sockets * udp_addrs.len());
        for (my_iface, my_addr) in udp_addrs {
            for i in 0..num_udp_sockets {
                let addr = SocketAddr::new(my_addr, udp_port);
                trace!(%addr, "Bind new UDP server");
                match NodeInner::new_udp_reuseport(addr, my_iface.clone()) {
                    Ok(udp_socket) => {
                        if i == 0 {
                            trace!(%addr, "Bound UDP server");
                        }
                        udp_bindings.push(Arc::new(UdpBinding::new(
                            cancellation_token.child_token(),
                            udp_socket,
                        )));
                    }
                    Err(e) => {
                        if opts.udp_addrs.is_empty() {
                            warn!(%addr, "Failed to bind new UDP server: {e}");
                        } else {
                            return Err(Error::BindError(e, addr));
                        }
                    }
                }
            }
        }

        // Check if we have any UDP bindings, if not, write warning to log
        if udp_bindings.is_empty() {
            warn!(
                "Could not bind to any UDP addresses. This may be because the system currently has no IP address (which is fine; the node will automatically bind once addresses become available)."
            );
        }

        // peers
        let peers = PapayaHashMap::builder()
            .capacity(opts.max_peers as usize)
            .hasher(RandomState::new())
            .build();

        if opts.super_peers.is_empty() {
            return Err(Error::NoSuperPeers);
        }

        // Check that all super peers have the same network_id and create them
        let network_id = opts.super_peers[0].network_id;
        for super_peer in &opts.super_peers {
            if super_peer.network_id != network_id {
                return Err(Error::SuperPeerNetworkIdMismatch(
                    network_id.to_be_bytes(),
                    super_peer.network_id.to_be_bytes(),
                ));
            }

            let super_peer_key = super_peer.pk;
            let super_peer = SuperPeer::new(
                opts.arm_messages,
                &super_peer_key,
                agreement_sk.as_ref(),
                agreement_pk.as_ref(),
                super_peer.addr.clone(),
                super_peer.tcp_port,
                udp_bindings.clone(),
            )
            .await?;
            peers
                .pin()
                .insert(super_peer_key, Peer::SuperPeer(super_peer));
        }

        // make first peer default route
        let default_key = peers.pin().keys().next().unwrap() as *const PubKey as *mut PubKey;
        let default_route = AtomicPtr::new(default_key);

        let mut join_set = JoinSet::new();

        let inner = Arc::new(NodeInner::new(
            opts,
            network_id.to_be_bytes(),
            peers,
            agreement_sk,
            agreement_pk,
            default_route,
            udp_bindings,
            udp_port,
            cancellation_token.clone(),
        ));

        // housekeeping task
        join_set.spawn(NodeInner::housekeeping_runner(
            inner.clone(),
            cancellation_token.clone(),
        ));

        // udp server readers
        for udp_binding in inner.udp_bindings().iter() {
            tokio::spawn(NodeInner::udp_reader(UdpBindingGuard {
                inner: inner.clone(),
                udp_binding: udp_binding.clone(),
            }));
        }

        #[cfg(feature = "prometheus")]
        join_set.spawn(NodeInner::prometheus_pusher(
            inner.clone(),
            cancellation_token.clone(),
        ));

        let monitoring_token = cancellation_token.clone();
        tokio::spawn(async move {
            while let Some(result) = join_set.join_next().await {
                if let Err(e) = result {
                    error!("Task failed: {e}");
                    monitoring_token.cancel();
                    break;
                }
            }
        });

        Ok(Self { inner })
    }

    pub async fn send_to<'a>(&self, recipient: &'a PubKey, bytes: &'a [u8]) -> Result<(), Error> {
        self.send_handle(recipient)?.send(bytes).await
    }

    pub fn send_handle(&self, recipient: &PubKey) -> Result<Arc<SendHandle>, Error> {
        trace!(%recipient, "Creating send handle");
        self.inner
            .send_handles
            .get_or_insert(recipient, self.inner.clone())
    }

    pub fn id(&self) -> &Identity {
        &self.inner.opts.id
    }

    pub fn direct_path(&self, pk: &PubKey) -> bool {
        if let Some(Peer::NodePeer(node_peer)) = self.inner.peers_list.peers.pin().get(pk) {
            return node_peer.best_path_key().is_some();
        }
        false
    }

    /// Returns a reference to the list of peers this node is connected to.
    ///
    /// The peers list contains all known peers, including both direct node peers and super peers.
    /// This can be used to monitor the node's connections and peer status.
    pub fn peers_list(&self) -> &PeersList {
        &self.inner.peers_list
    }

    pub fn opts(&self) -> &NodeOpts {
        &self.inner.opts
    }

    pub(crate) fn my_addrs() -> Result<Vec<(String, IpAddr)>, Error> {
        get_addrs().map_err(Error::GetAddrsFailed)
    }

    pub fn cancelled(&self) -> WaitForCancellationFuture<'_> {
        self.inner.cancellation_token.cancelled()
    }

    pub fn udp_port(&self) -> u16 {
        self.inner.udp_port
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        // destroy send handles
        self.inner.send_handles.for_each(|_, send_handle| {
            send_handle.inner.store(None);
        });
        trace!("Drop node. Cancel token.");
        self.inner.cancellation_token.cancel();
    }
}
