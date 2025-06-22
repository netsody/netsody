//! Node peer management for direct peer-to-peer connections.
//!
//! This module provides the NodePeer type which manages direct connections
//! to other nodes in the drasyl network, including path management,
//! session keys, and proof of work validation.

// Standard library imports
use std::net::SocketAddr;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::atomic::{AtomicI32, AtomicPtr, AtomicU8, AtomicU64};

// External crate imports
use papaya::{HashMap as PapayaHashMap, HashMapRef, LocalGuard, OwnedGuard};
use tokio::net::UdpSocket;
use tracing::trace;

// Crate-internal imports
use crate::crypto::{
    AgreementPubKey, AgreementSecKey, compute_kx_session_keys, convert_ed25519_pk_to_curve22519_pk,
    random_bytes,
};
// Crate-internal imports
use crate::crypto::SessionKey;
use crate::identity::{Pow, PubKey};
use crate::message::ShortId;
use crate::node::DIRECT_LINK_TIMEOUT;
use crate::node::NodeInner;
use crate::node::SendHandleState;
use crate::peer::error::Error;
use crate::peer::pow_status::PowStatus;
use crate::peer::{PeerPath, PeerPathKey, SessionKeys, SuperPeer};

/// A direct peer connection in the drasyl network.
///
/// NodePeer represents a direct connection to another node in the network.
/// It manages multiple network paths, session keys for encryption, proof of work
/// validation, and application traffic tracking.
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct NodePeer {
    /// Atomic storage for proof of work validation status.
    pow_store: AtomicU8,
    /// Session keys for message encryption/decryption.
    pub session_keys: Option<SessionKeys>,
    /// Timestamp when this peer connection was created.
    pub created_at: u64,
    /// Atomic counter for application message transmissions.
    pub app_tx: Arc<AtomicU64>,
    /// Atomic counter for application message receptions.
    pub app_rx: AtomicU64,
    /// Atomic pointer to the best path key.
    best_path_store: AtomicPtr<PeerPathKey>,
    /// Map of all known paths to this peer.
    pub paths: PapayaHashMap<PeerPathKey, PeerPath>,
    /// Short ID for receiving messages from this peer.
    pub rx_short_id: AtomicI32,
    /// Short ID for sending messages to this peer.
    tx_short_id: AtomicI32,
}

impl NodePeer {
    /// Create a new node peer connection.
    ///
    /// This method initializes a new peer connection with the given parameters,
    /// validates proof of work if provided, and generates session keys for
    /// message encryption if enabled.
    ///
    /// # Arguments
    /// * `pow` - Optional proof of work to validate
    /// * `pk` - Public key of the peer
    /// * `min_pow_difficulty` - Minimum proof of work difficulty required
    /// * `arm_messages` - Whether to enable message encryption
    /// * `my_agreement_sk` - Our agreement secret key for key exchange
    /// * `my_agreement_pk` - Our agreement public key for key exchange
    /// * `time` - Current timestamp
    ///
    /// # Returns
    /// A new NodePeer instance or an error if creation fails
    ///
    /// # Errors
    /// * [`Error::AgreementPkNotPresent`] - If agreement keys are missing when encryption is enabled
    /// * [`Error::Crypto`] - If cryptographic operations fail
    pub(crate) fn new(
        pow: Option<&Pow>,
        pk: &PubKey,
        min_pow_difficulty: u8,
        arm_messages: bool,
        my_agreement_sk: Option<AgreementSecKey>,
        my_agreement_pk: Option<AgreementPubKey>,
        time: u64,
    ) -> Result<Self, Error> {
        let pow = if let Some(pow) = pow {
            // PoW given, we can validate it
            if Pow::validate(pk, pow, min_pow_difficulty) {
                PowStatus::Ok
            } else {
                PowStatus::Nok
            }
        } else {
            // nothing to validate given
            PowStatus::Unknw
        };

        let session_keys = if arm_messages {
            if let PowStatus::Nok = pow {
                // invalid PoW, do not generate keys
                None
            } else {
                let agreement_pk = convert_ed25519_pk_to_curve22519_pk(&(*pk).into())?;
                Some(SessionKeys::new(compute_kx_session_keys(
                    &my_agreement_pk.ok_or(Error::AgreementPkNotPresent)?,
                    &my_agreement_sk.ok_or(Error::AgreementPkNotPresent)?,
                    &agreement_pk,
                )?))
            }
        } else {
            // arming disabled, session keys not needed
            None
        };

        let mut short_id = [0u8; 4];
        random_bytes(&mut short_id);

        Ok(Self {
            pow_store: AtomicU8::new(pow.into()),
            session_keys,
            created_at: time,
            rx_short_id: AtomicI32::new(i32::from_be_bytes(short_id)),
            ..Default::default()
        })
    }

    /// Validate the proof of work for this peer.
    ///
    /// This method validates the given proof of work against the peer's public key
    /// and updates the internal validation status accordingly.
    ///
    /// # Arguments
    /// * `pow` - The proof of work to validate
    /// * `pk` - The peer's public key
    /// * `min_pow_difficulty` - Minimum difficulty requirement
    ///
    /// # Returns
    /// `true` if the proof of work is valid, `false` otherwise
    ///
    /// # Errors
    /// Returns an error if cryptographic operations fail
    pub(crate) fn validate_pow(
        &self,
        pow: &Pow,
        pk: &PubKey,
        min_pow_difficulty: u8,
    ) -> Result<bool, Error> {
        match self.pow() {
            PowStatus::Ok => Ok(true),
            PowStatus::Nok => Ok(false),
            PowStatus::Unknw if Pow::validate(pk, pow, min_pow_difficulty) => {
                // PoW is ok
                self.set_pow(PowStatus::Ok);
                Ok(true)
            }
            PowStatus::Unknw => {
                // Pow is not ok
                self.set_pow(PowStatus::Nok);
                Ok(false)
            }
        }
    }

    /// Record that an application message was received from this peer.
    ///
    /// # Arguments
    /// * `time` - Timestamp when the message was received
    pub(crate) fn app_rx(&self, time: u64) {
        self.app_rx.store(time, SeqCst);
    }

    /// Record that an ACK message was received from this peer.
    ///
    /// This method updates the corresponding path with the ACK information
    /// and recalculates the best path to the peer.
    ///
    /// # Arguments
    /// * `time` - Timestamp when the ACK was received
    /// * `src` - Source address of the ACK
    /// * `hello_time` - Timestamp of the original HELLO message
    /// * `udp_socket` - UDP socket that received the ACK
    pub(crate) fn ack_rx(
        &self,
        time: u64,
        src: SocketAddr,
        hello_time: u64,
        udp_socket: Arc<UdpSocket>,
    ) {
        let key = Into::<PeerPathKey>::into((udp_socket.local_addr().unwrap(), src));
        if let Some(path) = self.paths.pin().get(&key) {
            path.ack_rx(time, src, hello_time);
            self.update_best_path();
        }
    }

    /// Update the best path to this peer based on current latency measurements.
    ///
    /// This method finds the path with the lowest median latency and updates
    /// the internal best path pointer accordingly.
    fn update_best_path(&self) {
        let best_path_ptr = if let Some(best_addr) = self
            .paths
            .pin()
            .iter()
            .filter_map(|(addr, candidate)| candidate.median_lat().map(|lat| (addr, lat)))
            .min_by_key(|&(_, lat)| lat)
            .map(|(addr, _)| addr)
        {
            trace!(path = %best_addr, "(New) best path");
            best_addr as *const PeerPathKey as *mut PeerPathKey
        } else {
            trace!("No best path");
            ptr::null_mut()
        };
        self.best_path_store.store(best_path_ptr, SeqCst);
    }

    /// Get the transmission session key for this peer.
    ///
    /// # Returns
    /// The session key for encrypting messages to this peer, or `None` if encryption is disabled
    pub(crate) fn tx_key(&self) -> Option<SessionKey> {
        self.session_keys.as_ref().map(|keys| keys.tx)
    }

    /// Get the reception session key for this peer.
    ///
    /// # Returns
    /// The session key for decrypting messages from this peer, or `None` if encryption is disabled
    pub(crate) fn rx_key(&self) -> Option<SessionKey> {
        self.session_keys.as_ref().map(|keys| keys.rx)
    }

    /// Remove stale paths that haven't received responses within the timeout period.
    ///
    /// # Arguments
    /// * `time` - Current timestamp
    /// * `hello_timeout` - Timeout period in seconds
    pub(crate) fn remove_stale_paths(&self, time: u64, hello_timeout: u64) {
        let guard = self.paths.guard();
        self.paths.retain(
            |key, candidate| {
                let valid = !candidate.stale(time, hello_timeout);
                if !valid {
                    trace!(path = %key, "Remove stale path");
                }
                valid
            },
            &guard,
        );
        self.update_best_path();
    }

    /// Clear all paths to this peer.
    pub(crate) fn clear_paths(&self) {
        trace!("Clear paths");
        let guard = self.paths.guard();
        self.paths.clear(&guard);
        self.update_best_path();
    }

    /// Clear application traffic counters.
    pub(crate) fn clear_app_tx_rx(&self) {
        trace!("Clear short ids");
        self.app_tx.store(0, SeqCst);
        self.app_rx.store(0, SeqCst);
    }

    /// Check if this peer is currently reachable.
    ///
    /// # Returns
    /// `true` if there are active paths to this peer, `false` otherwise
    pub fn is_reachable(&self, time: u64, hello_timeout: u64) -> bool {
        self.paths
            .pin()
            .values()
            .any(|path| path.is_reachable(time, hello_timeout))
    }

    /// Check if this peer connection is new.
    ///
    /// # Arguments
    /// * `time` - Current timestamp
    /// * `hello_timeout` - Timeout period in seconds
    ///
    /// # Returns
    /// `true` if the peer connection was created recently, `false` otherwise
    pub(crate) fn is_new(&self, time: u64, hello_timeout: u64) -> bool {
        time - self.created_at < (hello_timeout * 1_000)
    }

    /// Check if there has been recent application traffic with this peer.
    ///
    /// # Arguments
    /// * `time` - Current timestamp
    ///
    /// # Returns
    /// `true` if there has been recent application traffic, `false` otherwise
    pub(crate) fn has_app_traffic(&self, time: u64) -> bool {
        let mut no_app_since = std::cmp::max(self.app_tx.load(SeqCst), self.app_rx.load(SeqCst));
        if time < no_app_since {
            // TODO: This can be removed once we've switched to a monotonically increasing time source.
            no_app_since = time;
        }
        let no_app_time = time - no_app_since;

        no_app_time < (DIRECT_LINK_TIMEOUT * 1_000)
    }

    /// Get the key of the best path to this peer.
    ///
    /// # Returns
    /// Reference to the best path key, or `None` if no paths are available
    pub fn best_path_key(&self) -> Option<&PeerPathKey> {
        let ptr = self.best_path_store.load(SeqCst);
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &*ptr })
        }
    }

    /// Get the best path to this peer.
    ///
    /// # Arguments
    /// * `guard` - Local guard for accessing the paths map
    ///
    /// # Returns
    /// Tuple of (path_key, path) for the best path, or `None` if no paths are available
    pub(crate) fn best_path<'a>(
        &self,
        guard: &'a LocalGuard<'a>,
    ) -> Option<(&PeerPathKey, &'a PeerPath)> {
        match self.best_path_key() {
            Some(path_key) => self.paths.get(path_key, guard).map(|path| (path_key, path)),
            None => None,
        }
    }

    /// Get all paths to this peer.
    ///
    /// # Returns
    /// A pinned reference to the paths map
    pub(crate) fn paths(
        &self,
    ) -> HashMapRef<'_, PeerPathKey, PeerPath, std::hash::RandomState, OwnedGuard<'_>> {
        self.paths.pin_owned()
    }

    /// Set the proof of work validation status.
    ///
    /// # Arguments
    /// * `status` - The new proof of work status
    fn set_pow(&self, status: PowStatus) {
        self.pow_store.store(status.into(), SeqCst);
    }

    /// Get the current proof of work validation status.
    ///
    /// # Returns
    /// The current proof of work status
    pub fn pow(&self) -> PowStatus {
        PowStatus::try_from(self.pow_store.load(SeqCst)).unwrap()
    }

    /// Set the short ID for receiving messages from this peer.
    ///
    /// # Arguments
    /// * `new_short_id` - The new short ID to use
    pub(crate) fn set_rx_short_id(&self, new_short_id: ShortId) {
        trace!(short_id = %new_short_id, "Setting rx short id");
        self.rx_short_id
            .store(i32::from_be_bytes(new_short_id.to_bytes()), SeqCst);
    }

    /// Get the short ID for receiving messages from this peer.
    ///
    /// # Returns
    /// The current reception short ID
    pub fn rx_short_id(&self) -> ShortId {
        self.rx_short_id.load(SeqCst).to_be_bytes().into()
    }

    /// Set the short ID for sending messages to this peer.
    ///
    /// # Arguments
    /// * `new_short_id` - The new short ID to use
    pub(crate) fn set_tx_short_id(&self, new_short_id: ShortId) {
        trace!(short_id = %new_short_id, "Setting tx short id");
        self.tx_short_id
            .store(i32::from_be_bytes(new_short_id.to_bytes()), SeqCst);
    }

    /// Get the short ID for sending messages to this peer.
    ///
    /// # Returns
    /// The current transmission short ID, or `None` if not set
    pub fn tx_short_id(&self) -> Option<ShortId> {
        let short_id = self.tx_short_id.load(SeqCst);
        if short_id == 0 {
            None
        } else {
            Some(short_id.to_be_bytes().into())
        }
    }

    /// Get the age of the last application message transmission.
    ///
    /// # Arguments
    /// * `time` - Current timestamp
    ///
    /// # Returns
    /// Age of the last transmission in microseconds, or `None` if no messages have been sent
    pub(crate) fn app_tx_age(&self, time: u64) -> Option<u64> {
        let mut app_tx = self.app_tx.load(SeqCst);
        if app_tx != 0 {
            if time < app_tx {
                // TODO: This can be removed once we've switched to a monotonically increasing time source.
                app_tx = time;
            }
            Some(time - app_tx)
        } else {
            None
        }
    }

    /// Get the age of the last application message reception.
    ///
    /// # Arguments
    /// * `time` - Current timestamp
    ///
    /// # Returns
    /// Age of the last reception in microseconds, or `None` if no messages have been received
    pub(crate) fn app_rx_age(&self, time: u64) -> Option<u64> {
        let mut app_rx = self.app_rx.load(SeqCst);
        if app_rx != 0 {
            if time < app_rx {
                // TODO: This can be removed once we've switched to a monotonically increasing time source.
                app_rx = time;
            }
            Some(time - app_rx)
        } else {
            None
        }
    }

    /// Create a new send handle state for this peer.
    ///
    /// This method creates a snapshot of the current peer state that can be
    /// used for sending messages, including the best path and session keys.
    ///
    /// # Arguments
    /// * `inner` - Reference to the node's inner state
    /// * `super_peer` - Reference to the super peer for fallback routing
    ///
    /// # Returns
    /// A new SendHandleState configured for this peer
    pub(crate) fn new_send_handle_state(
        &self,
        inner: Arc<NodeInner>,
        super_peer: &SuperPeer,
    ) -> SendHandleState {
        let sp_udp_sockets = SendHandleState::sp_socket(super_peer, &inner.udp_bindings());
        let best_udp_path_key = self.best_path_key();
        let (best_addr, udp_socket) = if let Some(best_udp_path_key) = best_udp_path_key {
            let best_addr = Into::<SocketAddr>::into(*best_udp_path_key);
            let local_addr = best_udp_path_key.local_addr();
            let udp_socket = inner
                .udp_bindings()
                .iter()
                .find(|s| matches!(s.socket.local_addr(), Ok(a) if a == local_addr))
                .map(|b| b.socket.clone());

            (Some(best_addr), udp_socket)
        } else {
            (None, None)
        };

        let sp_tcp_stream = super_peer.tcp_connection().as_ref().and_then(|tcp| {
            tcp.stream_store
                .load()
                .as_ref()
                .map(std::clone::Clone::clone)
                .as_ref()
                .cloned()
        });

        SendHandleState {
            best_addr,
            udp_socket,
            app_tx: self.app_tx.clone(),
            tx_key: self.tx_key(),
            short_id: self.tx_short_id(),
            sp_tcp_stream,
            sp_udp_sockets,
        }
    }

    /// Get the median latency to this peer.
    ///
    /// # Returns
    /// The median latency in microseconds, or `None` if no latency data is available
    pub(crate) fn median_lat(&self) -> Option<u64> {
        let guard = self.paths.guard();
        self.best_path(&guard)
            .and_then(|(_, path)| path.median_lat())
    }
}
