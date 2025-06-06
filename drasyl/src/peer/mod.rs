//! Manages peer information and connections.
//!
//! This module provides functionality for managing connections to other peers
//! in the drasyl network, including both direct node peers and super peers.
//!
//! # Overview
//!
//! The peer management system handles:
//! * Direct connections to other nodes (NodePeer)
//! * Connections to super peers for relay and discovery (SuperPeer)
//! * Network path management and latency tracking
//! * Session key management for encrypted communication
//! * Proof of work validation for network security
//!
//! # Peer Types
//!
//! * **NodePeer**: Direct peer-to-peer connections with other nodes
//! * **SuperPeer**: Connections to relay nodes that help with discovery and routing

mod error;
mod node_peer;
mod path;
mod peers_list;
mod pow_status;
mod super_peer;

pub(crate) use error::*;
pub use node_peer::*;
pub use path::*;
pub use peers_list::*;
pub use pow_status::*;
pub use super_peer::*;

use std::fmt;
use std::fmt::Display;
// Standard library imports
use crate::crypto::SessionKey;

/// Session keys for encrypted communication with a peer.
///
/// This structure holds the transmission and reception keys used for
/// encrypting and decrypting messages with a specific peer.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SessionKeys {
    /// Key for encrypting messages sent to the peer.
    pub tx: SessionKey,
    /// Key for decrypting messages received from the peer.
    pub rx: SessionKey,
}

impl SessionKeys {
    /// Create new session keys from a key pair.
    ///
    /// # Arguments
    /// * `keys` - Tuple of (rx_key, tx_key) from key exchange
    ///
    /// # Returns
    /// A new SessionKeys instance
    pub(crate) fn new(keys: (SessionKey, SessionKey)) -> Self {
        Self {
            tx: keys.1,
            rx: keys.0,
        }
    }
}

impl Display for SessionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "TX: {:?}", self.tx)?;
        writeln!(f, "RX: {:?}", self.rx)
    }
}

/// A peer in the drasyl network.
///
/// This enum represents either a direct node peer or a super peer connection.
/// It provides a unified interface for working with different types of peers.
#[doc(hidden)]
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Peer {
    /// A super peer that provides relay and discovery services.
    SuperPeer(SuperPeer),
    /// A direct node peer for peer-to-peer communication.
    NodePeer(NodePeer),
}

impl PartialEq for Peer {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

/// Transport protocol used for network communication.
///
/// This enum specifies whether communication is happening over TCP or UDP.
#[doc(hidden)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TransportProt {
    /// Transmission Control Protocol - reliable, connection-oriented.
    TCP,
    /// User Datagram Protocol - unreliable, connectionless.
    UDP,
}

impl fmt::Display for TransportProt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::TCP => "tcp",
                Self::UDP => "udp",
            }
        )
    }
}
