//! Peer path management for network connections.
//!
//! This module provides types and functionality for managing network paths
//! to peers, including latency tracking and path state management.

// Standard library imports
use std::collections::VecDeque;
use std::fmt::{self, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;

// External crate imports
use arc_swap::ArcSwap;
use tracing::trace;

pub(crate) const RTT_WINDOW_SIZE: usize = 5;

/// Key identifying a specific network path between two endpoints.
///
/// A peer path key uniquely identifies a communication path by storing
/// both the local and remote socket addresses. This allows the system
/// to track multiple paths to the same peer (e.g., different network
/// interfaces or protocols).
#[derive(Debug, Hash, PartialEq, Eq, Copy, Clone)]
#[repr(transparent)]
pub struct PeerPathKey(pub (SocketAddr, SocketAddr));

#[cfg(feature = "serde")]
impl serde::Serialize for PeerPathKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{} -> {}", self.0.0, self.0.1))
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PeerPathKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let parts: Vec<&str> = s.split(" -> ").collect();
        if parts.len() != 2 {
            return Err(serde::de::Error::custom("Expected format 'addr1 -> addr2'"));
        }

        let local_addr: SocketAddr = parts[0]
            .parse()
            .map_err(|e| serde::de::Error::custom(format!("Invalid local address: {e}")))?;
        let remote_addr: SocketAddr = parts[1]
            .parse()
            .map_err(|e| serde::de::Error::custom(format!("Invalid remote address: {e}")))?;

        Ok(PeerPathKey((local_addr, remote_addr)))
    }
}

impl PeerPathKey {
    /// Get the local socket address for this path.
    ///
    /// # Returns
    /// The local socket address (source endpoint)
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.0.0
    }

    /// Get the remote socket address for this path.
    ///
    /// # Returns
    /// The remote socket address (destination endpoint)
    pub(crate) fn remote_addr(&self) -> SocketAddr {
        self.0.1
    }
}

impl From<(SocketAddr, SocketAddr)> for PeerPathKey {
    fn from(sockets: (SocketAddr, SocketAddr)) -> Self {
        Self(sockets)
    }
}

impl From<PeerPathKey> for SocketAddr {
    fn from(key: PeerPathKey) -> Self {
        key.0.1
    }
}

impl fmt::Display for PeerPathKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} -> {}", self.0.0, self.0.1)
    }
}

/// Internal state of a peer path.
///
/// This structure tracks the communication state and performance metrics
/// for a specific network path to a peer, including latency measurements
/// and reachability status.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PeerPathInner {
    /// Timestamp when the last unanswered HELLO was sent, if any.
    pub unanswered_hello_since: Option<u64>,
    /// Timestamp when the last ACK was received.
    pub last_ack_time: u64,
    /// Source address of the last received ACK.
    pub last_ack_src: Option<SocketAddr>,
    /// Rolling window of recent latency measurements.
    pub lats: VecDeque<u64>,
}

impl PeerPathInner {
    /// Check if the path is currently reachable.
    ///
    /// A path is considered reachable if an ACK has been received recently
    /// within the specified timeout period.
    ///
    /// # Arguments
    /// * `time` - Current timestamp in microseconds
    /// * `hello_timeout` - Timeout period in seconds
    ///
    /// # Returns
    /// `true` if the path is reachable, `false` otherwise
    pub fn is_reachable(&self, time: u64, hello_timeout: u64) -> bool {
        let mut last_ack_time = self.last_ack_time;
        if time < last_ack_time {
            // TODO: This can be removed once we've switched to a monotonically increasing time source.
            last_ack_time = time;
        }
        time - last_ack_time <= hello_timeout * 1_000
    }

    /// Check if the path is stale and should be removed.
    ///
    /// A path is considered stale if there has been an unanswered HELLO
    /// for longer than the timeout period.
    ///
    /// # Arguments
    /// * `time` - Current timestamp in microseconds
    /// * `hello_timeout` - Timeout period in seconds
    ///
    /// # Returns
    /// `true` if the path is stale, `false` otherwise
    pub fn is_stale(&self, time: u64, hello_timeout: u64) -> bool {
        match self.unanswered_hello_since {
            Some(unanswered_since) => {
                unanswered_since != 0 && time - unanswered_since > (hello_timeout * 1_000)
            }
            None => false,
        }
    }

    /// Calculate the median latency for this path.
    ///
    /// This method computes the median of recent latency measurements
    /// stored in the rolling window.
    ///
    /// # Returns
    /// The median latency in microseconds, or `None` if no measurements are available
    pub(crate) fn median_lat(&self) -> Option<u64> {
        if self.lats.is_empty() {
            return None;
        }

        let mut sorted_lats: Vec<u64> = self.lats.iter().copied().collect();
        sorted_lats.sort_unstable();

        let mid = sorted_lats.len() / 2;
        if sorted_lats.len().is_multiple_of(2) {
            Some((sorted_lats[mid - 1] + sorted_lats[mid]) / 2)
        } else {
            Some(sorted_lats[mid])
        }
    }

    /// Get the age of the last received ACK.
    ///
    /// # Arguments
    /// * `time` - Current timestamp in microseconds
    ///
    /// # Returns
    /// Age of the last ACK in microseconds, or `None` if no ACK has been received
    pub(crate) fn ack_age(&self, time: u64) -> Option<u64> {
        let mut ack_time = self.last_ack_time;
        if ack_time > 0 {
            if time < ack_time {
                // TODO: This can be removed once we've switched to a monotonically increasing time source.
                ack_time = time;
            }

            Some(time - ack_time)
        } else {
            None
        }
    }

    /// Record that a HELLO message was sent on this path.
    ///
    /// This method updates the path state to track unanswered HELLO messages,
    /// which is used for determining path staleness.
    ///
    /// # Arguments
    /// * `inner` - The atomic reference to the path state
    /// * `time` - Timestamp when the HELLO was sent
    pub(crate) fn hello_tx(inner: &ArcSwap<PeerPathInner>, time: u64) {
        let current_state = inner.load();
        if current_state.unanswered_hello_since.is_none()
            || current_state.unanswered_hello_since == Some(0)
        {
            trace!(unanswered_hello_since = %time, "hello_tx: update path");
            inner.store(Arc::new(PeerPathInner {
                unanswered_hello_since: Some(time),
                last_ack_time: current_state.last_ack_time,
                last_ack_src: current_state.last_ack_src,
                lats: current_state.lats.clone(),
            }));
        } else {
            trace!("hello_tx: do not update path");
        }
    }

    /// Record that an ACK message was received on this path.
    ///
    /// This method updates the path state with the new ACK information
    /// and calculates the round-trip time for latency tracking.
    ///
    /// # Arguments
    /// * `inner` - The atomic reference to the path state
    /// * `time` - Timestamp when the ACK was received
    /// * `src` - Source address of the ACK
    /// * `hello_time` - Timestamp of the original HELLO message
    pub(crate) fn ack_rx(
        inner: &ArcSwap<PeerPathInner>,
        time: u64,
        src: SocketAddr,
        hello_time: u64,
    ) {
        let mut lats = inner.load().lats.clone();
        if lats.len() == RTT_WINDOW_SIZE {
            lats.pop_back();
        }
        let lat = time - hello_time;
        lats.push_front(lat);

        trace!(
            unanswered_hello_since = 0,
            new_lat = lat,
            "ack_rx: update path"
        );

        inner.store(Arc::new(PeerPathInner {
            unanswered_hello_since: Some(0),
            last_ack_time: time,
            last_ack_src: Some(src),
            lats,
        }));
    }
}

/// A network path to a peer with atomic state management.
///
/// This structure represents a communication path to a peer and provides
/// thread-safe access to path state and performance metrics.
#[derive(Debug, Default)]
pub struct PeerPath {
    /// Atomic reference to the path's internal state.
    pub inner_store: ArcSwap<PeerPathInner>,
}

impl PeerPath {
    /// Create a new peer path.
    ///
    /// # Returns
    /// A new PeerPath instance with default state
    pub(crate) fn new() -> Self {
        Default::default()
    }

    /// Get the median latency for this path.
    ///
    /// # Returns
    /// The median latency in microseconds, or `None` if no measurements are available
    pub(crate) fn median_lat(&self) -> Option<u64> {
        self.inner_store.load().median_lat()
    }

    /// Check if the path is currently reachable.
    ///
    /// # Arguments
    /// * `time` - Current timestamp in microseconds
    /// * `hello_timeout` - Timeout period in seconds
    ///
    /// # Returns
    /// `true` if the path is reachable, `false` otherwise
    pub fn is_reachable(&self, time: u64, hello_timeout: u64) -> bool {
        self.inner_store.load().is_reachable(time, hello_timeout)
    }

    /// Check if the path is stale and should be removed.
    ///
    /// # Arguments
    /// * `time` - Current timestamp in microseconds
    /// * `hello_timeout` - Timeout period in seconds
    ///
    /// # Returns
    /// `true` if the path is stale, `false` otherwise
    pub fn stale(&self, time: u64, hello_timeout: u64) -> bool {
        self.inner_store.load().is_stale(time, hello_timeout)
    }

    /// Get the age of the last received ACK.
    ///
    /// # Arguments
    /// * `time` - Current timestamp in microseconds
    ///
    /// # Returns
    /// Age of the last ACK in microseconds, or `None` if no ACK has been received
    pub(crate) fn ack_age(&self, time: u64) -> Option<u64> {
        self.inner_store.load().ack_age(time)
    }

    /// Record that a HELLO message was sent on this path.
    ///
    /// # Arguments
    /// * `time` - Timestamp when the HELLO was sent
    pub(crate) fn hello_tx(&self, time: u64) {
        PeerPathInner::hello_tx(&self.inner_store, time);
    }

    /// Record that an ACK message was received on this path.
    ///
    /// # Arguments
    /// * `time` - Timestamp when the ACK was received
    /// * `src` - Source address of the ACK
    /// * `hello_time` - Timestamp of the original HELLO message
    pub(crate) fn ack_rx(&self, time: u64, src: SocketAddr, hello_time: u64) {
        PeerPathInner::ack_rx(&self.inner_store, time, src, hello_time);
    }
}
