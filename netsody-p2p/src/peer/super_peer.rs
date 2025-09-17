//! Super peer management for the Netsody network.
//!
//! This module provides functionality for managing connections to super peers,
//! which act as relay nodes and help with peer discovery in the Netsody network.

// Standard library imports
use std::fmt::{self, Formatter};
use std::net::SocketAddr;
use std::ptr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering::SeqCst;
use std::time::Duration;

// External crate imports
use arc_swap::{ArcSwapOption, Guard};
use papaya::{HashMap as PapayaHashMap, HashMap, LocalGuard};
use thiserror::Error;
use tokio::net::lookup_host;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{trace, warn};

// Crate-internal imports
use crate::crypto::{
    AgreementPubKey, AgreementSecKey, compute_kx_session_keys, convert_ed25519_pk_to_curve25519_pk,
};
// Crate-internal imports
use crate::crypto::SessionKey;
use crate::identity::PubKey;
use crate::node::DNS_LOOKUP_TIMEOUT;
use crate::node::TcpConnection;
use crate::node::UdpBinding;
use crate::peer::PeerPathKey;
use crate::peer::error::Error;
use crate::peer::{PeerPath, SessionKeys};

/// A super peer connection in the Netsody network.
///
/// Super peers are special nodes that help with peer discovery and message
/// relaying. They maintain both TCP and UDP connections and can resolve
/// hostnames to IP addresses.
#[doc(hidden)]
#[derive(Debug)]
pub struct SuperPeer {
    /// Hostname or IP address of the super peer.
    pub addr: String,
    /// TCP port number for the super peer.
    pub tcp_port: u16,
    /// Atomic reference to the TCP connection.
    tcp_connection_store: ArcSwapOption<TcpConnection>,
    /// Session keys for message encryption/decryption.
    pub session_keys: Option<SessionKeys>,
    /// Atomic reference to resolved IP addresses.
    resolved_addrs_store: ArcSwapOption<Vec<SocketAddr>>,
    /// Atomic pointer to the best UDP path key.
    best_udp_path_store: AtomicPtr<PeerPathKey>,
    /// Map of all UDP paths to this super peer.
    pub udp_paths: PapayaHashMap<PeerPathKey, PeerPath>,
}

impl SuperPeer {
    /// Create a new super peer connection.
    ///
    /// This method initializes a new super peer connection, resolves the hostname,
    /// creates UDP paths for each local binding, and generates session keys if
    /// message encryption is enabled.
    ///
    /// # Arguments
    /// * `arm_messages` - Whether to enable message encryption
    /// * `pk` - Public key of the super peer
    /// * `agreement_sk` - Our agreement secret key for key exchange
    /// * `agreement_pk` - Our agreement public key for key exchange
    /// * `addr` - Hostname or IP address of the super peer
    /// * `tcp_port` - TCP port number
    /// * `udp_bindings` - List of local UDP bindings to create paths for
    ///
    /// # Returns
    /// A new SuperPeer instance or an error if creation fails
    ///
    /// # Errors
    /// * [`Error::SuperPeerLookupFailed`] - If hostname resolution fails
    /// * [`Error::SuperPeerResolveTimeout`] - If hostname resolution times out
    /// * [`Error::SuperPeerResolveEmpty`] - If hostname resolution returns no results
    /// * [`Error::AgreementPkNotPresent`] - If agreement keys are missing when encryption is enabled
    /// * [`Error::Crypto`] - If cryptographic operations fail
    pub(crate) async fn new(
        arm_messages: bool,
        pk: &PubKey,
        agreement_sk: Option<&AgreementSecKey>,
        agreement_pk: Option<&AgreementPubKey>,
        addr: String,
        tcp_port: u16,
        udp_bindings: Vec<Arc<UdpBinding>>,
    ) -> Result<Self, Error> {
        let resolved_addrs = SuperPeer::lookup_host(&addr).await.ok();

        let udp_paths = PapayaHashMap::new();
        Self::add_paths_for_resolved_addrs(&udp_bindings, resolved_addrs.as_ref(), &udp_paths);

        let session_keys = if arm_messages {
            Some(SessionKeys::new(compute_kx_session_keys(
                agreement_pk.ok_or(Error::AgreementPkNotPresent)?,
                agreement_sk.ok_or(Error::AgreementSkNotPresent)?,
                &convert_ed25519_pk_to_curve25519_pk(&(*pk).into())?,
            )?))
        } else {
            None
        };

        Ok(Self {
            addr: addr.clone(),
            tcp_port,
            tcp_connection_store: Default::default(),
            session_keys,
            resolved_addrs_store: ArcSwapOption::from_pointee(resolved_addrs),
            best_udp_path_store: Default::default(),
            udp_paths,
        })
    }

    /// Get the hostname or IP address of this super peer.
    ///
    /// # Returns
    /// The address string
    pub(crate) fn addr(&self) -> &str {
        self.addr.as_str()
    }

    /// Get the TCP address (hostname:port) of this super peer.
    ///
    /// # Returns
    /// A formatted TCP address string
    pub(crate) fn tcp_addr(&self) -> String {
        format!(
            "{}:{}",
            self.addr()
                .split(':')
                .next()
                .expect("Invalid address format"),
            self.tcp_port
        )
    }

    /// Get the transmission session key for this super peer.
    ///
    /// # Returns
    /// The session key for encrypting messages to this super peer, or `None` if encryption is disabled
    pub(crate) fn tx_key(&self) -> Option<SessionKey> {
        self.session_keys.as_ref().map(|keys| keys.tx)
    }

    /// Get the reception session key for this super peer.
    ///
    /// # Returns
    /// The session key for decrypting messages from this super peer, or `None` if encryption is disabled
    pub(crate) fn rx_key(&self) -> Option<SessionKey> {
        self.session_keys.as_ref().map(|keys| keys.rx)
    }

    /// Create a new TCP connection path to this super peer.
    ///
    /// # Returns
    /// A cancellation token that can be used to cancel the connection
    pub(crate) fn new_tcp_path(&self) -> Arc<CancellationToken> {
        let cancellation_token = CancellationToken::new();
        let cancellation_token = Arc::new(cancellation_token);

        self.tcp_connection_store
            .store(Some(Arc::new(TcpConnection::new(
                cancellation_token.clone(),
            ))));

        cancellation_token
    }

    /// Reset the TCP connection path.
    pub(crate) fn reset_tcp_path(&self) {
        self.tcp_connection_store.store(None);
    }

    /// Determine if a TCP connection should be established.
    ///
    /// This method checks whether a TCP connection should be established based
    /// on the current state of UDP paths and configuration.
    ///
    /// # Arguments
    /// * `time` - Current timestamp
    /// * `hello_timeout` - Timeout period in seconds
    /// * `enforce_tcp` - Whether TCP connections are enforced
    ///
    /// # Returns
    /// `true` if a TCP connection should be established, `false` otherwise
    pub(crate) fn establish_tcp_connection(
        &self,
        time: u64,
        hello_timeout: u64,
        enforce_tcp: bool,
    ) -> bool {
        if self.tcp_connection().is_none() {
            if enforce_tcp {
                trace!("TCP connection should be established because TCP is enforced");
                return true;
            }

            let all_paths_stale = self
                .udp_paths
                .pin()
                .iter()
                .all(|(_, path)| path.stale(time, hello_timeout));
            if all_paths_stale {
                trace!("TCP connection should be established because all UDP paths are stale");
            }
            all_paths_stale
        } else {
            false
        }
    }

    /// Resolve a hostname to IP addresses.
    ///
    /// This method performs DNS resolution with a timeout to convert a hostname
    /// to a list of IP addresses.
    ///
    /// # Arguments
    /// * `addr` - The hostname or IP address to resolve
    ///
    /// # Returns
    /// A vector of resolved socket addresses
    ///
    /// # Errors
    /// * [`Error::SuperPeerLookupFailed`] - If DNS resolution fails
    /// * [`Error::SuperPeerResolveTimeout`] - If DNS resolution times out
    /// * [`Error::SuperPeerResolveEmpty`] - If no addresses are returned
    pub(crate) async fn lookup_host(host: &str) -> Result<Vec<SocketAddr>, Error> {
        // resolve hostname
        trace!("Resolve hostname {}", host);
        let addrs: Vec<SocketAddr> =
            match timeout(Duration::from_millis(DNS_LOOKUP_TIMEOUT), lookup_host(host)).await {
                Ok(Ok(addrs)) => {
                    let addrs = addrs.collect();
                    trace!("Resolved hostname {} to {:?}", host, addrs);
                    addrs
                }
                Ok(Err(e)) => {
                    warn!("Failed to resolve hostname {}: {}", host, e);
                    return Err(Error::SuperPeerLookupFailed(
                        host.to_string(),
                        e.to_string(),
                    ));
                }
                Err(_) => {
                    warn!(
                        "Timeout of {} ms exceeded while attempting to resolve hostname {}",
                        DNS_LOOKUP_TIMEOUT, host
                    );
                    return Err(Error::SuperPeerResolveTimeout(
                        host.to_string(),
                        DNS_LOOKUP_TIMEOUT,
                    ));
                }
            };

        if addrs.is_empty() {
            // do nothing. keep previous (if present)
            return Err(Error::SuperPeerResolveEmpty);
        }

        Ok(addrs)
    }

    /// Get the median latency to this super peer.
    ///
    /// This method returns the median latency of the best available path,
    /// preferring TCP over UDP if available.
    ///
    /// # Returns
    /// The median latency in microseconds, or `None` if no latency data is available
    pub(crate) fn median_lat(&self) -> Option<u64> {
        if let Some(tcp_path) = self.tcp_connection().as_ref() {
            tcp_path.median_lat()
        } else {
            let guard = self.udp_paths.guard();
            self.best_udp_path(&guard)
                .and_then(|(_, path)| path.median_lat())
        }
    }

    /// Get the currently resolved IP addresses for this super peer.
    ///
    /// # Returns
    /// An atomic reference to the vector of resolved addresses
    pub fn resolved_addrs(&self) -> Option<Arc<Vec<SocketAddr>>> {
        self.resolved_addrs_store.load_full()
    }

    /// Update the resolved IP addresses for this super peer.
    ///
    /// # Arguments
    /// * `new_addrs` - The new list of resolved addresses
    pub(crate) fn update_resolved_addrs(&self, new_addrs: Vec<SocketAddr>) {
        self.resolved_addrs_store.store(Some(Arc::new(new_addrs)));
    }

    /// Get the TCP connection path.
    ///
    /// # Returns
    /// A guard containing the TCP connection, or `None` if no connection exists
    pub fn tcp_connection(&self) -> Guard<Option<Arc<TcpConnection>>> {
        self.tcp_connection_store.load()
    }

    /// Get the key of the best UDP path to this super peer.
    ///
    /// # Returns
    /// Reference to the best UDP path key, or `None` if no UDP paths are available
    pub fn best_udp_path_key(&self) -> Option<&PeerPathKey> {
        let ptr = self.best_udp_path_store.load(SeqCst);
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &*ptr })
        }
    }

    /// Get the best UDP path to this super peer.
    ///
    /// # Arguments
    /// * `guard` - Local guard for accessing the UDP paths map
    ///
    /// # Returns
    /// Tuple of (path_key, path) for the best UDP path, or `None` if no UDP paths are available
    pub(crate) fn best_udp_path<'a>(
        &self,
        guard: &'a LocalGuard<'a>,
    ) -> Option<(&PeerPathKey, &'a PeerPath)> {
        match self.best_udp_path_key() {
            Some(path_key) => self
                .udp_paths
                .get(path_key, guard)
                .map(|path| (path_key, path)),
            None => None,
        }
    }

    /// Update the best UDP path based on current latency measurements.
    ///
    /// This method finds the UDP path with the lowest median latency and updates
    /// the internal best path pointer accordingly.
    pub(crate) fn update_best_udp_path(&self) {
        let best_path_ptr = if let Some(best_key) = self
            .udp_paths
            .pin()
            .iter()
            .filter_map(|(key, path)| path.median_lat().map(|lat| (key, lat)))
            .min_by_key(|&(_, lat)| lat)
            .map(|(key, _)| key)
        {
            best_key as *const PeerPathKey as *mut PeerPathKey
        } else {
            ptr::null_mut()
        };
        self.best_udp_path_store.store(best_path_ptr, SeqCst);
    }

    /// Record that an ACK message was received from this super peer.
    ///
    /// This method updates the appropriate path (TCP or UDP) with the ACK
    /// information and may cancel TCP connections if UDP is working well.
    ///
    /// # Arguments
    /// * `udp_local_addr` - Local UDP address if the ACK was received via UDP
    /// * `src` - Source address of the ACK
    /// * `time` - Timestamp when the ACK was received
    /// * `ack_time` - Timestamp of the original message
    /// * `enforce_tcp` - Whether TCP connections are enforced
    pub(crate) fn ack_rx(
        &self,
        udp_local_addr: Option<SocketAddr>,
        src: SocketAddr,
        time: u64,
        ack_time: u64,
        enforce_tcp: bool,
    ) {
        if let Some(udp_local_addr) = udp_local_addr {
            trace!("Got ACK via UDP");

            let path_key = PeerPathKey((udp_local_addr, src));
            if let Some(udp_path) = self.udp_paths.pin().get(&path_key) {
                trace!("ACK received via know path {}", path_key);
                udp_path.ack_rx(time, src, ack_time);
            } else {
                trace!(
                    "ACK received via unknown path {}. Create new path",
                    path_key
                );
                let udp_path = PeerPath::new();
                udp_path.ack_rx(time, src, ack_time);
                self.udp_paths.pin().insert(path_key, udp_path);
            }
            self.update_best_udp_path();

            if !enforce_tcp && let Some(tcp_path) = self.tcp_connection().as_ref() {
                tcp_path.cancel_connection();
            }
        } else {
            trace!("Got ACK via TCP");
            if let Some(tcp_path) = self.tcp_connection().as_ref() {
                tcp_path.ack_rx(time, src, ack_time);
            }
        }
    }

    /// Remove stale UDP paths that haven't received responses within the timeout period.
    ///
    /// # Arguments
    /// * `time` - Current timestamp
    /// * `hello_timeout` - Timeout period in seconds
    pub(crate) fn remove_stale_udp_paths(&self, time: u64, hello_timeout: u64) {
        let guard = self.udp_paths.guard();
        self.udp_paths.retain(
            |key, candidate| {
                let valid = !candidate.stale(time, hello_timeout);
                if !valid {
                    trace!(path = %key, "Remove stale path");
                }
                valid
            },
            &guard,
        );
        self.update_best_udp_path();
    }

    /// Check if this super peer is currently reachable.
    ///
    /// # Returns
    /// `true` if there are active UDP paths to this super peer, `false` otherwise
    pub fn is_reachable(&self) -> bool {
        self.best_udp_path_key().is_some()
    }

    pub(crate) fn add_paths_for_resolved_addrs(
        udp_bindings: &Vec<Arc<UdpBinding>>,
        resolved_addrs: Option<&Vec<SocketAddr>>,
        udp_paths: &HashMap<PeerPathKey, PeerPath>,
    ) {
        if let Some(resolved_addrs) = &resolved_addrs {
            for udp_binding in udp_bindings {
                let local_addr = udp_binding.local_addr;

                let remote_addr = resolved_addrs.iter().find(|addr| match local_addr {
                    SocketAddr::V4(_) => addr.is_ipv4(),
                    SocketAddr::V6(_) => addr.is_ipv6(),
                });

                if let Some(remote_addr) = remote_addr {
                    let new_path_key = PeerPathKey((local_addr, *remote_addr));

                    if !udp_paths.pin().contains_key(&new_path_key) {
                        trace!("Add new path {new_path_key} to super peer");
                        let path = PeerPath::new();
                        udp_paths.pin().insert(new_path_key, path);
                    }
                }
            }
        }
    }
}

/// Error types for super peer URL parsing.
#[derive(Debug, Error)]
pub enum SuperPeerUrlError {
    /// No public key found in the URL.
    #[error("No public key")]
    NoPublicKey,

    /// No address found in the URL.
    #[error("No address")]
    NoAddr,

    /// Invalid URL format.
    #[error("Invalid url")]
    InvalidUrl,

    /// Invalid public key format.
    #[error("Invalid public key")]
    InvalidPubKey,
}

/// A parsed super peer URL containing connection information.
///
/// Super peer URLs follow the format:
/// `udp://host:port?publicKey=hex&tcpPort=port`
#[doc(hidden)]
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
pub struct SuperPeerUrl {
    /// Hostname or IP address of the super peer.
    pub addr: String,
    /// TCP port number for the super peer.
    pub tcp_port: u16,
    /// Public key of the super peer.
    pub pk: PubKey,
    /// Network ID to which the super peer belongs.
    pub network_id: i32,
}

impl SuperPeerUrl {
    /// Parse a list of super peer URLs from a whitespace-separated string.
    ///
    /// # Arguments
    /// * `peers_str` - String containing whitespace-separated super peer URLs
    ///
    /// # Returns
    /// A vector of parsed SuperPeerUrl instances
    ///
    /// # Errors
    /// Returns an error if any URL in the list is invalid
    pub fn parse_list(peers_str: &str) -> Result<Vec<SuperPeerUrl>, SuperPeerUrlError> {
        peers_str
            .split_whitespace()
            .map(SuperPeerUrl::from_str)
            .collect()
    }
}

impl FromStr for SuperPeerUrl {
    type Err = SuperPeerUrlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Format: udp://host:port?publicKey=hex&tcpPort=port
        if let Some(url_str) = s.strip_prefix("udp://") {
            // Trenne Host:Port von Query Parametern
            if let Some((addr, query)) = url_str.split_once('?') {
                let mut public_key = None;
                let mut tcp_port = 443;
                let mut network_id = 1i32;

                // Parse Query Parameter für Public Key, Network ID und TCP Port
                for param in query.split('&') {
                    if let Some((key, value)) = param.split_once('=') {
                        match key {
                            "publicKey" => {
                                public_key = Some(
                                    PubKey::from_str(value)
                                        .map_err(|_| SuperPeerUrlError::InvalidPubKey)?,
                                );
                            }
                            "tcpPort" => {
                                if let Ok(port) = value.parse::<u16>() {
                                    tcp_port = port;
                                }
                            }
                            "networkId" => {
                                if let Ok(id) = value.parse::<i32>() {
                                    network_id = id;
                                }
                            }
                            _ => {}
                        }
                    }
                }

                if let Some(pk) = public_key {
                    Ok(SuperPeerUrl {
                        addr: addr.to_string(),
                        pk,
                        tcp_port,
                        network_id,
                    })
                } else {
                    Err(SuperPeerUrlError::NoPublicKey)
                }
            } else {
                Err(SuperPeerUrlError::NoAddr)
            }
        } else {
            Err(SuperPeerUrlError::InvalidUrl)
        }
    }
}

impl TryFrom<String> for SuperPeerUrl {
    type Error = SuperPeerUrlError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(&value)
    }
}

impl fmt::Display for SuperPeerUrl {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "udp://{}?publicKey={}&networkId={}&tcpPort={}",
            self.addr, self.pk, self.network_id, self.tcp_port
        )
    }
}

impl From<SuperPeerUrl> for String {
    fn from(url: SuperPeerUrl) -> Self {
        url.to_string()
    }
}
