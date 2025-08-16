//! Peer list management for the drasyl network.
//!
//! This module provides the PeersList type which maintains a thread-safe
//! collection of all known peers and their connection information.

// Standard library imports
use std::fmt;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering::SeqCst;

// External crate imports
use ahash::RandomState;
use papaya::HashMap as PapayaHashMap;

// Crate-internal imports
use crate::identity::PubKey;
use crate::message::ShortId;
use crate::node::NodeInner;
use crate::peer::{Peer, PeerPath};

/// A thread-safe list of peers that this node is connected to.
///
/// The `PeersList` maintains a collection of all known peers, including both direct node peers
/// and super peers. It provides thread-safe access to peer information and manages peer
/// connections.
pub struct PeersList {
    /// Map of public keys to peer instances.
    pub peers: PapayaHashMap<PubKey, Peer, RandomState>,
    /// Atomic pointer to the default route peer's public key.
    pub(crate) default_route_ptr: AtomicPtr<PubKey>,
    /// Map of short IDs to public keys for efficient message routing.
    pub(crate) rx_short_ids: PapayaHashMap<ShortId, PubKey, RandomState>,
}

impl PeersList {
    /// Create a new peers list.
    ///
    /// # Arguments
    /// * `peers` - The peer map to use
    /// * `default_route_ptr` - Atomic pointer to the default route peer
    ///
    /// # Returns
    /// A new PeersList instance
    pub(crate) fn new(
        peers: PapayaHashMap<PubKey, Peer, RandomState>,
        default_route_ptr: AtomicPtr<PubKey>,
    ) -> Self {
        PeersList {
            peers,
            default_route_ptr,
            rx_short_ids: Default::default(),
        }
    }

    /// Get the public key of the default route peer.
    ///
    /// # Returns
    /// Reference to the default route peer's public key
    pub fn default_route(&self) -> &PubKey {
        let ptr = self.default_route_ptr.load(SeqCst);
        unsafe { &*ptr }
    }

    /// Iterate over all peers with a function.
    ///
    /// # Arguments
    /// * `f` - Function to call for each peer
    pub fn for_each_peer<F>(&self, mut f: F)
    where
        F: FnMut(&PubKey, &Peer),
    {
        let guard = self.peers.guard();
        for (pk, peer) in self.peers.iter(&guard) {
            f(pk, peer);
        }
    }
}

impl fmt::Display for PeersList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let guard = self.peers.guard();

        // sort peers
        let mut super_peers = Vec::new();
        let mut clients = Vec::new();

        for (key, value) in self.peers.iter(&guard) {
            match (key, value) {
                (super_peer_pk, Peer::SuperPeer(super_peer)) => {
                    super_peers.push((super_peer_pk, super_peer));
                }
                (node_peer_pk, Peer::NodePeer(node_peer)) => {
                    clients.push((node_peer_pk, node_peer));
                }
            }
        }
        super_peers.sort_by(|a, b| a.0.cmp(b.0));
        clients.sort_by(|a, b| a.0.cmp(b.0));

        // print peers
        let now = NodeInner::clock();

        writeln!(
            f,
            "{:<64} {:<3} {:<4} {:<6} {:<7} {:<7} {:<7} Path",
            "Peer", "PoW", "Role", "MedLat", "AckRx", "AppTx", "AppRx",
        )?;

        for (super_peer_pk, super_peer) in super_peers {
            let default_route = self.default_route() == super_peer_pk;

            let udp_paths = super_peer.udp_paths.pin();
            let udp_path_guards = super_peer.udp_paths.guard();
            let best_udp_path = super_peer.best_udp_path(&udp_path_guards);
            let tcp_path = super_peer.tcp_connection();

            let (median_lat, ack_age, path) = match &*tcp_path {
                // TODO: It would be better to use `tcp_path.reachable` instead of `has_stream`, as this would ensure that an ACK has actually been received. However, `reachable` requires `hello_timeout`, which is not available here.
                Some(tcp_path) if tcp_path.has_stream() => (
                    tcp_path.median_lat(),
                    tcp_path.ack_age(now),
                    format!("tcp://{}", super_peer.tcp_addr()),
                ),
                _ => match best_udp_path {
                    Some((key, path)) => {
                        (path.median_lat(), path.ack_age(now), format!("udp://{key}"))
                    }
                    None => (None, None, String::new()),
                },
            };

            writeln!(
                f,
                "{:<64} {:<3} {:<4} {:<6} {:<7} {:<7} {:<7} {}",
                super_peer_pk.to_string(),
                "ign",
                if default_route { "S*" } else { "S" },
                median_lat.map_or_else(String::new, |median_lat| format!(
                    "{:<6.1}",
                    median_lat as f64 / 1_000.0
                )),
                ack_age.map_or_else(String::new, |ack_age| format!(
                    "{:<6.1}",
                    ack_age as f64 / 1_000.0
                )),
                "",
                "",
                path,
            )?;
            if tcp_path.is_some()
                && let Some((key, path)) = best_udp_path
            {
                writeln!(
                    f,
                    "{:<64} {:<3} {:<4} {:<6} {:<7} {:<7} {:<7} udp://{}",
                    "",
                    "",
                    "",
                    path.median_lat()
                        .map_or_else(String::new, |median_lat| format!(
                            "{:<6.1}",
                            median_lat as f64 / 1_000.0
                        )),
                    path.ack_age(now)
                        .map_or_else(String::new, |ack_age| format!(
                            "{:<6.1}",
                            ack_age as f64 / 1_000.0
                        )),
                    "",
                    "",
                    key,
                )?;
            }

            for (key, path) in &udp_paths {
                if best_udp_path.map(|(k, _)| k) != Some(key) {
                    writeln!(
                        f,
                        "{:<64} {:<3} {:<4} {:<6} {:<7} {:<7} {:<7} udp://{}",
                        "",
                        "",
                        "",
                        path.median_lat()
                            .map_or_else(String::new, |median_lat| format!(
                                "{:<6.1}",
                                median_lat as f64 / 1_000.0
                            )),
                        path.ack_age(now)
                            .map_or_else(String::new, |ack_age| format!(
                                "{:<6.1}",
                                ack_age as f64 / 1_000.0
                            )),
                        "",
                        "",
                        key,
                    )?;
                }
            }
        }

        for (node_peer_pk, node_peer) in clients {
            let best_addr = node_peer.best_path_key();
            let guard = node_peer.paths.guard();
            let best_path = best_addr.and_then(|addr| node_peer.paths.get(addr, &guard));
            writeln!(
                f,
                "{:<64} {:<3} {:<4} {:<6} {:<7} {:<7} {:<7} {}",
                node_peer_pk.to_string(),
                &node_peer.pow().to_string(),
                "C",
                best_path.and_then(PeerPath::median_lat).map_or_else(
                    String::new,
                    |median_lat| format!("{:<6.1}", median_lat as f64 / 1_000.0)
                ),
                best_path
                    .map(|path| path.ack_age(now))
                    .map_or_else(String::new, |ack_age| ack_age
                        .map_or_else(String::new, |ack_age| (ack_age / 1000).to_string())),
                node_peer
                    .app_rx_age(now)
                    .map_or_else(String::new, |ack_age| (ack_age / 1000).to_string()),
                node_peer
                    .app_tx_age(now)
                    .map_or_else(String::new, |ack_age| (ack_age / 1000).to_string()),
                if let Some(best_addr) = best_addr {
                    format!("udp://{best_addr}")
                } else {
                    String::new()
                },
            )?;
            for (key, path) in &node_peer.paths.pin() {
                if best_addr != Some(key) {
                    writeln!(
                        f,
                        "{:<64} {:<3} {:<4} {:<6} {:<7} {:<7} {:<7} udp://{}",
                        "",
                        "",
                        "",
                        path.median_lat()
                            .map_or_else(String::new, |median_lat| format!(
                                "{:<6.1}",
                                median_lat as f64 / 1_000.0
                            )),
                        path.ack_age(now)
                            .map_or_else(String::new, |ack_age| (ack_age / 1_000).to_string()),
                        "",
                        "",
                        key,
                    )?;
                }
            }
        }
        Ok(())
    }
}
