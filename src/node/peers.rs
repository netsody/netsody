use crate::identity::validate_proof_of_work;
use crate::node::peers::TransportProt::{TCP, UDP};
use crate::node::{DIRECT_LINK_TIMEOUT, DNS_LOOKUP_TIMEOUT, NodeError, NodeInner, RTT_WINDOW_SIZE};
use crate::utils::crypto::{
    AEGIS_KEYBYTES, CURVE25519_PUBLICKEYBYTES, CURVE25519_SECRETKEYBYTES, CryptoError,
    ED25519_PUBLICKEYBYTES, compute_kx_session_keys, convert_ed25519_pk_to_curve22519_pk,
    random_bytes,
};
use crate::utils::hex::bytes_to_hex;
use crate::utils::net;
use ahash::RandomState;
use arc_swap::ArcSwap;
use core::sync::atomic::Ordering::SeqCst;
use log::error;
use net::IPV6_MAPPED_IPV4;
use papaya::{HashMap, HashMapRef, OwnedGuard};
use std::collections::VecDeque;
use std::net::{SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU8, AtomicU64};
use std::time::Duration;
use std::{fmt, ptr};
use thiserror::Error;
use tokio::io;
use tokio::io::AsyncWriteExt;
use tokio::net::lookup_host;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::timeout;

#[derive(Debug, Error)]
pub enum PeersError {
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),

    #[error("Agreement pk not present")]
    AgreementPkNotPresent,

    #[error("Agreement sk not present")]
    AgreementSkNotPresent,
}

#[derive(Debug)]
struct SessionKeys {
    tx: [u8; AEGIS_KEYBYTES],
    rx: [u8; AEGIS_KEYBYTES],
}

impl SessionKeys {
    pub(in crate::node) fn new(keys: ([u8; AEGIS_KEYBYTES], [u8; AEGIS_KEYBYTES])) -> Self {
        Self {
            tx: keys.1,
            rx: keys.0,
        }
    }
}

#[derive(Debug, Clone)]
struct LastAck {
    time: u64,
    src: SocketAddr,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Peer {
    SuperPeer(SuperPeer),
    NodePeer(NodePeer),
}

impl PartialEq for Peer {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

#[derive(Debug, Default)]
#[repr(u8)]
enum PowStatus {
    #[default]
    Unknw = 0,
    Ok = 1,
    Nok = 2,
}

impl From<PowStatus> for u8 {
    fn from(status: PowStatus) -> Self {
        status as u8
    }
}

impl TryFrom<u8> for PowStatus {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PowStatus::Unknw),
            1 => Ok(PowStatus::Ok),
            2 => Ok(PowStatus::Nok),
            _ => Err(()),
        }
    }
}

impl fmt::Display for PowStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Ok => "ok",
                Self::Nok => "nok",
                Self::Unknw => "",
            }
        )
    }
}

#[derive(Debug)]
pub(in crate::node) struct EndpointCandidate {
    latencies_val: ArcSwap<VecDeque<u64>>,
    unanswered_hello_since: AtomicU64,
    ack_time: AtomicU64,
}

impl EndpointCandidate {
    pub(in crate::node) fn new() -> Self {
        Self {
            latencies_val: ArcSwap::from_pointee(VecDeque::with_capacity(RTT_WINDOW_SIZE)),
            unanswered_hello_since: AtomicU64::new(0),
            ack_time: AtomicU64::new(0),
        }
    }

    pub(in crate::node) fn hello_tx(&self, time: u64) {
        let _ = self
            .unanswered_hello_since
            .compare_exchange(0, time, SeqCst, SeqCst);
    }

    fn ack_rx(&self, time: u64, hello_time: u64) {
        self.unanswered_hello_since.store(0, SeqCst);
        self.ack_time.store(time, SeqCst);
        let lat = time - hello_time;
        self.add_lat_sample(lat);
    }

    pub(in crate::node) fn add_lat_sample(&self, lat: u64) {
        let mut latencies = self.latencies().as_ref().clone();
        if latencies.len() == RTT_WINDOW_SIZE {
            latencies.pop_back();
        }
        latencies.push_front(lat);
        self.set_latencies(latencies);
    }

    pub(in crate::node) fn latencies(&self) -> arc_swap::Guard<Arc<VecDeque<u64>>> {
        self.latencies_val.load()
    }

    pub(in crate::node) fn set_latencies(&self, new_latencies: VecDeque<u64>) {
        self.latencies_val.swap(Arc::new(new_latencies));
    }

    fn median_lat(&self) -> Option<u64> {
        let latencies = self.latencies();
        if latencies.is_empty() {
            return None;
        }

        let mut sorted_latencies: Vec<u64> = latencies.iter().copied().collect();
        sorted_latencies.sort_unstable();

        let mid = sorted_latencies.len() / 2;
        if sorted_latencies.len() % 2 == 0 {
            Some((sorted_latencies[mid - 1] + sorted_latencies[mid]) / 2)
        } else {
            Some(sorted_latencies[mid])
        }
    }

    pub(in crate::node) fn is_stale(&self, time: u64, hello_timeout: u64) -> bool {
        let unanswered_hello_since = self.unanswered_hello_since.load(SeqCst);
        let elapsed_time = time.saturating_sub(unanswered_hello_since);
        unanswered_hello_since != 0 && elapsed_time > (hello_timeout * 1_000)
    }

    pub(in crate::node) fn ack_age(&self, time: u64) -> Option<u64> {
        let mut ack_time = self.ack_time.load(SeqCst);
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
}

#[derive(Debug, Default)]
pub struct NodePeer {
    pow_ptr: AtomicU8,
    session_keys: Option<SessionKeys>,
    created_at: u64,
    pub(in crate::node) app_tx: Arc<AtomicU64>,
    app_rx: AtomicU64,
    best_addr_ptr: AtomicPtr<SocketAddr>,
    endpoint_candidates: HashMap<SocketAddr, EndpointCandidate>,
    rx_short_id: AtomicI32,
    tx_short_id: AtomicI32,
}

impl NodePeer {
    pub(in crate::node) fn new(
        pow: Option<&[u8; 4]>,
        pk: &[u8; ED25519_PUBLICKEYBYTES],
        min_pow_difficulty: u8,
        arm_messages: bool,
        my_agreement_sk: Option<[u8; CURVE25519_SECRETKEYBYTES]>,
        my_agreement_pk: Option<[u8; CURVE25519_PUBLICKEYBYTES]>,
        time: u64,
    ) -> Result<Self, PeersError> {
        let pow = if let Some(pow) = pow {
            // PoW given, we can validate it
            if validate_proof_of_work(pk, pow, min_pow_difficulty) {
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
                let agreement_pk = convert_ed25519_pk_to_curve22519_pk(pk)?;
                Some(SessionKeys::new(compute_kx_session_keys(
                    &my_agreement_pk.ok_or(PeersError::AgreementPkNotPresent)?,
                    &my_agreement_sk.ok_or(PeersError::AgreementPkNotPresent)?,
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
            pow_ptr: AtomicU8::new(pow.into()),
            session_keys,
            created_at: time,
            rx_short_id: AtomicI32::new(i32::from_be_bytes(short_id)),
            ..Default::default()
        })
    }

    pub(in crate::node) fn validate_pow(
        &self,
        pow: &[u8; 4],
        pk: &[u8; ED25519_PUBLICKEYBYTES],
        min_pow_difficulty: u8,
    ) -> Result<bool, PeersError> {
        match self.pow() {
            PowStatus::Ok => Ok(true),
            PowStatus::Nok => Ok(false),
            PowStatus::Unknw if validate_proof_of_work(pk, pow, min_pow_difficulty) => {
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

    pub(in crate::node) fn app_rx(&self, time: u64) {
        self.app_rx.store(time, SeqCst);
    }

    pub(in crate::node) fn ack_rx(&self, time: u64, src: SocketAddr, hello_time: u64) {
        if let Some(candidate) = self.endpoint_candidates.pin().get(&src) {
            candidate.ack_rx(time, hello_time);

            if let Some(best_addr) = self
                .endpoint_candidates
                .pin()
                .iter()
                .filter_map(|(addr, candidate)| candidate.median_lat().map(|lat| (addr, lat)))
                .min_by_key(|&(_, lat)| lat)
                .map(|(addr, _)| addr)
            {
                self.best_addr_ptr
                    .store(best_addr as *const SocketAddr as *mut SocketAddr, SeqCst);
            }
        }
    }

    pub(in crate::node) fn tx_key(&self) -> Option<[u8; AEGIS_KEYBYTES]> {
        self.session_keys.as_ref().map(|keys| keys.tx)
    }

    pub(in crate::node) fn rx_key(&self) -> Option<[u8; AEGIS_KEYBYTES]> {
        self.session_keys.as_ref().map(|keys| keys.rx)
    }

    pub(in crate::node) fn remove_stale_endpoints(&self, time: u64, hello_timeout: u64) {
        let guard = self.endpoint_candidates.guard();
        self.endpoint_candidates.retain(
            |_, candidate| !candidate.is_stale(time, hello_timeout),
            &guard,
        );
        if let Some(best_addr) = self.best_addr() {
            if !&self.endpoint_candidates.contains_key(best_addr, &guard) {
                self.best_addr_ptr.store(ptr::null_mut(), SeqCst);
            }
        }
    }

    pub(in crate::node) fn is_reachable(&self) -> bool {
        !self.endpoint_candidates.pin().is_empty()
    }

    pub(in crate::node) fn is_new(&self, time: u64, hello_timeout: u64) -> bool {
        time - self.created_at < (hello_timeout * 1_000)
    }

    pub(in crate::node) fn has_app_traffic(&self, time: u64) -> bool {
        let mut no_app_since = std::cmp::max(self.app_tx.load(SeqCst), self.app_rx.load(SeqCst));
        if time < no_app_since {
            // TODO: This can be removed once we've switched to a monotonically increasing time source.
            no_app_since = time;
        }
        let no_app_time = time - no_app_since;

        no_app_time < (DIRECT_LINK_TIMEOUT * 1_000)
    }

    pub(in crate::node) fn best_addr(&self) -> Option<&SocketAddr> {
        let ptr = self.best_addr_ptr.load(SeqCst);
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &*ptr })
        }
    }

    pub(in crate::node) fn endpoint_candidates(
        &self,
    ) -> HashMapRef<'_, SocketAddr, EndpointCandidate, std::hash::RandomState, OwnedGuard<'_>> {
        self.endpoint_candidates.pin_owned()
    }

    fn set_pow(&self, status: PowStatus) {
        self.pow_ptr.store(status.into(), SeqCst);
    }

    fn pow(&self) -> PowStatus {
        PowStatus::try_from(self.pow_ptr.load(SeqCst)).unwrap()
    }

    pub(in crate::node) fn set_rx_short_id(&self, new_short_id: [u8; 4]) {
        self.rx_short_id
            .store(i32::from_be_bytes(new_short_id), SeqCst);
    }

    pub(in crate::node) fn rx_short_id(&self) -> [u8; 4] {
        self.rx_short_id.load(SeqCst).to_be_bytes()
    }

    pub(in crate::node) fn set_tx_short_id(&self, new_short_id: [u8; 4]) {
        self.tx_short_id
            .store(i32::from_be_bytes(new_short_id), SeqCst);
    }

    pub(in crate::node) fn tx_short_id(&self) -> Option<[u8; 4]> {
        let short_id = self.tx_short_id.load(SeqCst);
        if short_id == 0 {
            None
        } else {
            Some(short_id.to_be_bytes())
        }
    }
}

fn compute_session_keys(
    pk: &[u8; ED25519_PUBLICKEYBYTES],
    agreement_sk: Option<&[u8; CURVE25519_SECRETKEYBYTES]>,
    agreement_pk: Option<&[u8; CURVE25519_PUBLICKEYBYTES]>,
) -> Result<SessionKeys, PeersError> {
    Ok(SessionKeys::new(compute_kx_session_keys(
        agreement_pk.ok_or(PeersError::AgreementPkNotPresent)?,
        agreement_sk.ok_or(PeersError::AgreementSkNotPresent)?,
        &convert_ed25519_pk_to_curve22519_pk(pk)?,
    )?))
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TransportProt {
    TCP,
    UDP,
}

impl fmt::Display for TransportProt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                TCP => "tcp",
                UDP => "udp",
            }
        )
    }
}

pub(in crate::node) struct PeersList {
    pub(in crate::node) peers: HashMap<[u8; ED25519_PUBLICKEYBYTES], Peer, RandomState>,
    pub(in crate::node) default_route_ptr: AtomicPtr<[u8; ED25519_PUBLICKEYBYTES]>,
    pub(in crate::node) rx_short_ids: HashMap<[u8; 4], [u8; ED25519_PUBLICKEYBYTES], RandomState>,
}

impl PeersList {
    pub(in crate::node) fn new(
        peers: HashMap<[u8; ED25519_PUBLICKEYBYTES], Peer, RandomState>,
        default_route_ptr: AtomicPtr<[u8; ED25519_PUBLICKEYBYTES]>,
    ) -> Self {
        PeersList {
            peers,
            default_route_ptr,
            rx_short_ids: Default::default(),
        }
    }

    pub(in crate::node) fn default_route(&self) -> &[u8; ED25519_PUBLICKEYBYTES] {
        let ptr = self.default_route_ptr.load(SeqCst);
        unsafe { &*ptr }
    }
}

impl fmt::Display for PeersList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let now = NodeInner::clock();

        writeln!(
            f,
            "{:<64} {:<3} {:<4} {:<6} {:<7} {:<7} {:<7} Endpoint",
            "Peer", "PoW", "Role", "MedLat", "AckRx", "AppTx", "AppRx",
        )?;

        let guard = self.peers.guard();
        for (key, value) in self.peers.iter(&guard) {
            match (key, value) {
                (super_peer_pk, Peer::SuperPeer(super_peer)) => {
                    let default_route = self.default_route() == super_peer_pk;

                    let (ack_time, endpoint) =
                        if let Some((mut ack_time, ack_src, prot)) = super_peer.last_ack() {
                            if now < ack_time {
                                // TODO: This can be removed once we've switched to a monotonically increasing time source.
                                ack_time = now;
                            }
                            (
                                ((now - ack_time) / 1000).to_string(),
                                format!("{prot}://{ack_src}"),
                            )
                        } else {
                            (String::new(), String::new())
                        };

                    writeln!(
                        f,
                        "{:<64} {:<3} {:<4} {:<6} {:<7} {:<7} {:<7} {}",
                        bytes_to_hex(super_peer_pk),
                        "ign",
                        if default_route { "S*" } else { "S" },
                        if let Some(median_lat) = super_peer.median_lat() {
                            format!("{:<6.1}", median_lat as f64 / 1000.0)
                        } else {
                            String::new()
                        },
                        ack_time,
                        "",
                        "",
                        endpoint,
                    )?;
                }
                (node_peer_pk, Peer::NodePeer(node_peer)) => {
                    let best_addr = node_peer.best_addr();
                    let guard = node_peer.endpoint_candidates.guard();
                    let best_endpoint =
                        best_addr.and_then(|addr| node_peer.endpoint_candidates.get(addr, &guard));
                    writeln!(
                        f,
                        "{:<64} {:<3} {:<4} {:<6} {:<7} {:<7} {:<7} {}",
                        bytes_to_hex(node_peer_pk),
                        &node_peer.pow().to_string(),
                        "C",
                        best_endpoint
                            .and_then(EndpointCandidate::median_lat)
                            .map_or_else(String::new, |median_lat| format!(
                                "{:<6.1}",
                                median_lat as f64 / 1_000.0
                            )),
                        best_endpoint
                            .map(|candidate| candidate.ack_age(now))
                            .map_or_else(String::new, |ack_age| ack_age
                                .map_or_else(String::new, |ack_age| (ack_age / 1000).to_string())),
                        {
                            let mut app_tx = node_peer.app_tx.load(SeqCst);
                            if app_tx != 0 {
                                if now < app_tx {
                                    // TODO: This can be removed once we've switched to a monotonically increasing time source.
                                    app_tx = now;
                                }
                                ((now - app_tx) / 1_000).to_string()
                            } else {
                                String::new()
                            }
                        },
                        {
                            let mut app_rx = node_peer.app_rx.load(SeqCst);
                            if app_rx != 0 {
                                if now < app_rx {
                                    // TODO: This can be removed once we've switched to a monotonically increasing time source.
                                    app_rx = now;
                                }
                                ((now - app_rx) / 1_000).to_string()
                            } else {
                                String::new()
                            }
                        },
                        if let Some(best_addr) = best_addr {
                            format!("udp://{best_addr}")
                        } else {
                            String::new()
                        },
                    )?;
                    for (addr, candidate) in &node_peer.endpoint_candidates.pin() {
                        if matches!(best_addr, Some(best_addr) if best_addr != addr) {
                            writeln!(
                                f,
                                "{:<64} {:<3} {:<4} {:<6} {:<7} {:<7} {:<7} udp://{addr}",
                                "",
                                "",
                                "",
                                candidate.median_lat().map_or_else(
                                    String::new,
                                    |median_lat| format!("{:<6.1}", median_lat as f64 / 1_000.0)
                                ),
                                candidate
                                    .ack_age(now)
                                    .map_or_else(String::new, |ack_age| (ack_age / 1_000)
                                        .to_string()),
                                "",
                                "",
                            )?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Default, Debug)]
struct SuperPeerUdpState {
    unanswered_hello_since: u64,
    last_ack: Option<LastAck>,
}

#[derive(Default, Debug)]
struct SuperPeerTcpState {
    handle: Option<JoinHandle<()>>,
    stream: Option<Arc<Mutex<OwnedWriteHalf>>>,
    last_ack: Option<LastAck>,
}

#[derive(Debug)]
pub struct SuperPeer {
    addr: String,
    tcp_port: u16,
    tcp_state_ptr: ArcSwap<SuperPeerTcpState>,
    pub(in crate::node) tcp_shutdown_scheduled: AtomicBool,
    session_keys: Option<SessionKeys>,
    resolved_addr_val: ArcSwap<SocketAddr>,
    udp_state_val: ArcSwap<SuperPeerUdpState>,
    latencies_val: ArcSwap<VecDeque<u64>>,
}

impl SuperPeer {
    pub(in crate::node) fn new(
        arm_messages: bool,
        pk: &[u8; ED25519_PUBLICKEYBYTES],
        agreement_sk: Option<&[u8; CURVE25519_SECRETKEYBYTES]>,
        agreement_pk: Option<&[u8; CURVE25519_PUBLICKEYBYTES]>,
        addr: String,
        resolved_addr: SocketAddr,
        tcp_port: u16,
    ) -> Result<Self, PeersError> {
        let session_keys = if arm_messages {
            Some(compute_session_keys(pk, agreement_sk, agreement_pk)?)
        } else {
            None
        };

        Ok(Self {
            addr: addr.clone(),
            tcp_port,
            tcp_state_ptr: ArcSwap::from_pointee(SuperPeerTcpState::default()),
            tcp_shutdown_scheduled: AtomicBool::default(),
            session_keys,
            resolved_addr_val: ArcSwap::from_pointee(resolved_addr),
            udp_state_val: ArcSwap::from_pointee(SuperPeerUdpState::default()),
            latencies_val: ArcSwap::from_pointee(VecDeque::with_capacity(RTT_WINDOW_SIZE)),
        })
    }

    pub(in crate::node) fn addr(&self) -> &str {
        self.addr.as_str()
    }

    pub(in crate::node) fn hello_tx(&self, time: u64) {
        if self.tcp_state().stream.is_none() {
            let current = self.udp_state();
            if current.unanswered_hello_since == 0 {
                self.set_udp_state(SuperPeerUdpState {
                    unanswered_hello_since: time,
                    last_ack: current.last_ack.clone(),
                });
            }
        }
    }

    pub(in crate::node) fn ack_rx(
        &self,
        time: u64,
        src: SocketAddr,
        prot: TransportProt,
        ack_time: u64,
    ) {
        if prot == UDP {
            self.set_udp_state(SuperPeerUdpState {
                unanswered_hello_since: 0,
                last_ack: Some(LastAck { time, src }),
            });
        } else {
            let tcp_state = self.tcp_state();
            self.set_tcp_state(SuperPeerTcpState {
                handle: None,
                stream: tcp_state.stream.clone(),
                last_ack: Some(LastAck { time, src }),
            });
        }
        self.add_lat_sample(time - ack_time);
        if prot == UDP {
            self.schedule_tcp_connection_shutdown();
        }
    }

    pub(in crate::node) fn resolved_tcp_addr(&self) -> SocketAddr {
        SocketAddr::new(self.resolved_addr().ip(), self.tcp_port)
    }

    pub(in crate::node) fn tx_key(&self) -> Option<[u8; AEGIS_KEYBYTES]> {
        self.session_keys.as_ref().map(|keys| keys.tx)
    }

    pub(in crate::node) fn rx_key(&self) -> Option<[u8; AEGIS_KEYBYTES]> {
        self.session_keys.as_ref().map(|keys| keys.rx)
    }

    pub(in crate::node) fn reset_tcp_state(&self) {
        self.set_tcp_state(SuperPeerTcpState {
            handle: None,
            stream: None,
            last_ack: None,
        });
    }

    pub(in crate::node) fn do_tcp_fallback(&self, time: u64, hello_timeout: u64) -> bool {
        let unanswered_since = self.udp_state().unanswered_hello_since;
        let tcp_state = self.tcp_state();
        unanswered_since != 0
            && time - unanswered_since > (hello_timeout * 1_000)
            && tcp_state.handle.is_none()
            && self.tcp_state().stream.is_none()
    }

    fn last_ack(&self) -> Option<(u64, SocketAddr, TransportProt)> {
        if let Some(ack) = self.tcp_state().last_ack.as_ref() {
            Some((ack.time, ack.src, TCP))
        } else {
            self.udp_state()
                .last_ack
                .as_ref()
                .map(|ack| (ack.time, ack.src, UDP))
        }
    }

    pub(in crate::node) async fn resolve_addr(
        listen_addr: SocketAddr,
        addr: &str,
    ) -> Result<SocketAddr, NodeError> {
        // resolve hostname
        let addrs: Vec<SocketAddr> =
            match timeout(Duration::from_millis(DNS_LOOKUP_TIMEOUT), lookup_host(addr)).await {
                Ok(Ok(addrs)) => addrs.collect(),
                Ok(Err(e)) => return Err(NodeError::SuperPeerResolveFailed(e.to_string())),
                Err(_) => return Err(NodeError::SuperPeerResolveTimeout(DNS_LOOKUP_TIMEOUT)),
            };

        if addrs.is_empty() {
            // do nothing. keep previous (if present)
            return Err(NodeError::SuperPeerResolveEmpty);
        }

        match listen_addr {
            SocketAddr::V4(_) => addrs
                .iter()
                .find(|addr| addr.is_ipv4())
                .copied()
                .ok_or(NodeError::SuperPeerResolveWrongFamily),
            SocketAddr::V6(_) => {
                if IPV6_MAPPED_IPV4 {
                    if let Some(addr) = addrs.iter().find(|addr| addr.is_ipv6()) {
                        Ok(*addr)
                    } else if let Some(SocketAddr::V4(addr)) =
                        addrs.iter().find(|addr| addr.is_ipv4())
                    {
                        Ok(SocketAddr::V6(SocketAddrV6::new(
                            addr.ip().to_ipv6_mapped(),
                            addr.port(),
                            0,
                            0,
                        )))
                    } else {
                        Err(NodeError::SuperPeerResolveWrongFamily)
                    }
                } else {
                    addrs
                        .iter()
                        .find(|addr| addr.is_ipv6())
                        .copied()
                        .ok_or(NodeError::SuperPeerResolveWrongFamily)
                }
            }
        }
    }

    pub(in crate::node) fn median_lat(&self) -> Option<u64> {
        let latencies = self.latencies();
        if latencies.is_empty() {
            return None;
        }

        let mut sorted_latencies: Vec<u64> = latencies.iter().copied().collect();
        sorted_latencies.sort_unstable();

        let mid = sorted_latencies.len() / 2;
        if sorted_latencies.len() % 2 == 0 {
            Some((sorted_latencies[mid - 1] + sorted_latencies[mid]) / 2)
        } else {
            Some(sorted_latencies[mid])
        }
    }

    pub(in crate::node) fn resolved_addr(&self) -> Arc<SocketAddr> {
        self.resolved_addr_val.load_full()
    }

    pub(in crate::node) fn set_resolved_addr(&self, new_addr: SocketAddr) {
        self.resolved_addr_val.swap(Arc::new(new_addr));
    }

    fn udp_state(&self) -> arc_swap::Guard<Arc<SuperPeerUdpState>> {
        self.udp_state_val.load()
    }

    fn set_udp_state(&self, new_state: SuperPeerUdpState) {
        self.udp_state_val.swap(Arc::new(new_state));
    }

    fn tcp_state(&self) -> arc_swap::Guard<Arc<SuperPeerTcpState>> {
        self.tcp_state_ptr.load()
    }

    pub(in crate::node) fn tcp_stream(&self) -> Option<Arc<Mutex<OwnedWriteHalf>>> {
        self.tcp_state().stream.clone()
    }

    fn set_tcp_state(&self, new_state: SuperPeerTcpState) {
        self.tcp_state_ptr.swap(Arc::new(new_state));
    }

    pub(in crate::node) fn set_tcp_handle(&self, new_handle: JoinHandle<()>) {
        self.set_tcp_state(SuperPeerTcpState {
            handle: Some(new_handle),
            ..SuperPeerTcpState::default()
        });
    }

    pub(in crate::node) fn set_tcp_stream(&self, new_stream: OwnedWriteHalf) {
        self.set_tcp_state(SuperPeerTcpState {
            stream: Some(Arc::new(Mutex::new(new_stream))),
            ..SuperPeerTcpState::default()
        });
    }

    pub(in crate::node) fn add_lat_sample(&self, lat: u64) {
        let mut latencies = self.latencies().as_ref().clone();
        if latencies.len() == RTT_WINDOW_SIZE {
            latencies.pop_back();
        }
        latencies.push_front(lat);
        self.set_latencies(latencies);
    }

    pub(in crate::node) fn latencies(&self) -> arc_swap::Guard<Arc<VecDeque<u64>>> {
        self.latencies_val.load()
    }

    pub(in crate::node) fn set_latencies(&self, new_latencies: VecDeque<u64>) {
        self.latencies_val.swap(Arc::new(new_latencies));
    }

    pub(in crate::node) async fn shutdown_tcp_connection(&self) -> io::Result<()> {
        if let Some(tcp_stream) = self.tcp_stream() {
            self.tcp_shutdown_scheduled.store(false, SeqCst);
            tcp_stream.lock().await.shutdown().await?;
        }
        Ok(())
    }

    pub(in crate::node) fn schedule_tcp_connection_shutdown(&self) {
        if self.tcp_state().stream.is_some() {
            let _ = self
                .tcp_shutdown_scheduled
                .compare_exchange(false, true, SeqCst, SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {

    // #[test]
    // fn test_best_ip() {
    //     let ipv4_peer = SuperPeer {
    //         addr: "127.0.0.1:22527".into(),
    //         session_keys: None,
    //         resolved_addr: None,
    //         last_ack: None,
    //     };
    //     let ipv6_peer = SuperPeer {
    //         addr: "[::1]:22527".into(),
    //         session_keys: None,
    //         last_ack: None,
    //     };
    //     let dual_peer = SuperPeer {
    //         addr: "localhost:22527".into(), // Resolves to both IPv4 and IPv6
    //         session_keys: None,
    //         resolved_addr: None,
    //         last_ack: None,
    //     };
    //
    //     // Test mit ipv4_enabled = true
    //     let addr = ipv4_peer
    //         .best_ip(true)
    //         .expect("Should return address for IPv4");
    //     assert!(addr.is_ipv4(), "Should prefer IPv4 when enabled");
    //
    //     // Test mit ipv4_enabled = false
    //     assert!(
    //         ipv4_peer.best_ip(false).is_none(),
    //         "Should not return IPv4 when disabled"
    //     );
    //
    //     // Test mit IPv6 Adresse
    //     let addr = ipv6_peer
    //         .best_ip(true)
    //         .expect("Should return address for IPv6");
    //     assert!(addr.is_ipv6(), "Should return IPv6");
    //     let addr = ipv6_peer
    //         .best_ip(false)
    //         .expect("Should return address for IPv6");
    //     assert!(addr.is_ipv6(), "Should return IPv6");
    //
    //     // Test mit dual-stack
    //     let addr = dual_peer
    //         .best_ip(true)
    //         .expect("Should return address for dual-stack");
    //     assert!(addr.is_ipv4(), "Should prefer IPv4 when enabled");
    //     let addr = dual_peer
    //         .best_ip(false)
    //         .expect("Should return address for dual-stack");
    //     assert!(addr.is_ipv6(), "Should only return IPv6 when IPv4 disabled");
    // }
    //
    // #[test]
    // fn test_best_ip_invalid_addr() {
    //     let invalid_peer = SuperPeer {
    //         addr: "invalid:22527".into(),
    //         session_keys: None,
    //         last_ack: None,
    //     };
    //
    //     assert!(
    //         invalid_peer.best_ip(true).is_none(),
    //         "Should return None for invalid address"
    //     );
    //     assert!(
    //         invalid_peer.best_ip(false).is_none(),
    //         "Should return None for invalid address"
    //     );
    // }
    //
    // #[test]
    // fn test_parse_list_invalid() {
    //     // Test mit leerer Liste
    //     assert!(
    //         SuperPeer::parse_list("").is_empty(),
    //         "Empty string should return empty list"
    //     );
    //
    //     // Test mit ungültigem Schema
    //     let invalid_schema = "tcp://sp1.example.com:22527?publicKey=c0900bcfabc493d062ecd293265f571edb70b85313ba4cdda96c9f77163ba62d";
    //     assert!(
    //         SuperPeer::parse_list(invalid_schema).is_empty(),
    //         "Invalid schema should be ignored"
    //     );
    //
    //     // Test ohne publicKey Parameter
    //     let no_key = "udp://sp1.example.com:22527?param=value";
    //     assert!(
    //         SuperPeer::parse_list(no_key).is_empty(),
    //         "Missing publicKey should be ignored"
    //     );
    //
    //     // Test mit ungültigem publicKey
    //     let invalid_key = "udp://sp1.example.com:22527?publicKey=invalid";
    //     assert!(
    //         SuperPeer::parse_list(invalid_key).is_empty(),
    //         "Invalid publicKey should be ignored"
    //     );
    // }
}
