mod peers;

use crate::identity::Identity;
use crate::messages::SHORT_ID_NONE;
use crate::messages::{
    AckMessage, AppMessage, EndpointsList, HELLO_MAX_ENDPOINTS, HelloNodePeerMessage,
    HelloSuperPeerMessage, LONG_HEADER_NETWORK_ID_LEN, LongHeader, MessageError, MessageType,
    SHORT_HEADER_ID_LEN, ShortHeader, UniteMessage,
};
use crate::node::peers::TransportProt::{TCP, UDP};
use crate::node::peers::{
    EndpointCandidate, NodePeer, Peer, PeersError, PeersList, SuperPeer, TransportProt,
};
use crate::utils::crypto::{
    AEGIS_KEYBYTES, CURVE25519_PUBLICKEYBYTES, CURVE25519_SECRETKEYBYTES, CryptoError,
    ED25519_PUBLICKEYBYTES, convert_ed25519_pk_to_curve22519_pk,
    convert_ed25519_sk_to_curve25519_sk, random_bytes,
};
use crate::utils::hex::{bytes_to_hex, hex_to_bytes};
use crate::utils::net;
use crate::utils::net::get_addrs;
use ahash::RandomState;
use arc_swap::{ArcSwap, Guard};
use core::sync::atomic::Ordering::SeqCst;
use derive_builder::Builder;
use flume::{Receiver, Sender, TrySendError};
use log::{Level, debug, error, info, log_enabled, trace, warn};
use lz4_flex::block::{compress_prepend_size, decompress_size_prepended};
use murmur3::murmur3_32;
use net::listening_addrs;
use papaya::HashMap;
use std::collections::{HashMap as StdHashMap, HashSet};
use std::io;
use std::io::Cursor;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::str::FromStr;
use std::string::ToString;
use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, AtomicU64};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::task::JoinError;

pub const NETWORK_ID_DEFAULT: i32 = 1;
pub const UDP_LISTEN_DEFAULT: &str = "0.0.0.0:-1";
pub const ARM_MESSAGES_DEFAULT: bool = true;
pub const MAX_PEERS_DEFAULT: u64 = 10_000; // set to 0 removes peers limit
pub const MIN_POW_DIFFICULTY_DEFAULT: u8 = 24;
pub const HELLO_TIMEOUT_DEFAULT: u64 = 30 * 1_000; // milliseconds
pub const HELLO_MAX_AGE_DEFAULT: u64 = 60 * 1_000; // milliseconds
pub const SUPER_PEERS_DEFAULT: &str = "udp://sp-fkb1.drasyl.org:22527?publicKey=c0900bcfabc493d062ecd293265f571edb70b85313ba4cdda96c9f77163ba62d&networkId=1 udp://sp-rjl1.drasyl.org:22527?publicKey=5b4578909bf0ad3565bb5faf843a9f68b325dd87451f6cb747e49d82f6ce5f4c&networkId=1 udp://sp-nyc1.drasyl.org:22527?publicKey=bf3572dba7ebb6c5ccd037f3a978707b5d7c5a9b9b01b56b4b9bf059af56a4e0&networkId=1 udp://sp-sgp1.drasyl.org:22527?publicKey=ab7a1654d463f9986530bed00569cc895697827b802153b8ef1598579713045f&networkId=1";
pub const RECV_BUF_CAP_DEFAULT: usize = 64; // messages
pub const MTU_DEFAULT: usize = 1472; // Ethernet MTU (1500) - IPv4 header (20) - UDP header (8)
pub const PROCESS_UNITES_DEFAULT: bool = true;
pub const HOUSEKEEPING_DELAY_DEFAULT: u64 = 5 * 1_000; // milliseconds
pub(in crate::node) const DIRECT_LINK_TIMEOUT: u64 = 60_000; // milliseconds
pub(in crate::node) const RTT_WINDOW_SIZE: usize = 5;
pub(in crate::node) const DNS_LOOKUP_TIMEOUT: u64 = 2_000; // milliseconds

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("Send via {0} failed: {1}")]
    SendFailed(TransportProt, io::Error),

    #[error("Message error: {0}")]
    MessageError(#[from] MessageError),

    #[error("Peers manager error: {0}")]
    PeersError(#[from] PeersError),

    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),

    #[error("Bind error: {0}")]
    BindError(io::Error),

    #[error("Message from other network: {}", i32::from_be_bytes(*.0))]
    NetworkIdInvalid([u8; LONG_HEADER_NETWORK_ID_LEN]),

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

    #[error("UDP send_to {1} error: {0}")]
    UdpSendToError(io::Error, SocketAddr),

    #[error("UDP local_addr error: {0}")]
    UdpLocalAddrError(io::Error),

    #[error("Peer not present")]
    PeerNotPresent,

    #[error("TCP peer_addr error: {0}")]
    TcpPeerAddrError(io::Error),

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

    #[error("Failed to resolve super peer host: {0}")]
    SuperPeerResolveFailed(String),

    #[error("Timeout of {0} ms exceeded while attempting to resolve super peer host")]
    SuperPeerResolveTimeout(u64),

    #[error("Empty result on super peer host resolve")]
    SuperPeerResolveEmpty,

    #[error("Super peer host lookup returned no usable address matching node's listen addr")]
    SuperPeerResolveWrongFamily,

    #[error("Send handle for peer already exist")]
    SendHandleAlreadyCreated,
}

#[derive(Clone, Builder)]
pub struct NodeOpts {
    pub id: Identity,
    #[builder(default = "NETWORK_ID_DEFAULT.to_be_bytes()")]
    pub network_id: [u8; 4],
    #[builder(default = "UDP_LISTEN_DEFAULT.to_string()")]
    pub udp_listen: String,
    #[builder(default = "ARM_MESSAGES_DEFAULT")]
    pub arm_messages: bool,
    #[builder(default = "MAX_PEERS_DEFAULT")]
    pub max_peers: u64,
    #[builder(default = "MIN_POW_DIFFICULTY_DEFAULT")]
    pub min_pow_difficulty: u8,
    #[builder(default = "HELLO_TIMEOUT_DEFAULT")]
    pub hello_timeout: u64,
    #[builder(default = "HELLO_MAX_AGE_DEFAULT")]
    pub hello_max_age: u64,
    #[builder(default = "SUPER_PEERS_DEFAULT.to_string()")]
    pub super_peers: String,
    #[builder(default = "RECV_BUF_CAP_DEFAULT")]
    pub recv_buf_cap: usize,
    #[builder(default = "MTU_DEFAULT")]
    pub mtu: usize,
    #[builder(default = "PROCESS_UNITES_DEFAULT")]
    pub process_unites: bool,
    #[builder(default = "String::new()")]
    pub hello_endpoints: String,
    #[builder(default = "String::new()")]
    pub hello_addresses_excluded: String,
    #[builder(default = "HOUSEKEEPING_DELAY_DEFAULT")]
    pub housekeeping_delay: u64,
}

pub struct NodeInner {
    pub(in crate::node) opts: NodeOpts,
    coarse_timer: AtomicU64,
    peers_list: PeersList,
    udp_socket: UdpSocket,
    udp_socket_addr: SocketAddr,
    recv_buf_tx: Sender<([u8; ED25519_PUBLICKEYBYTES], Vec<u8>)>,
    agreement_sk: Option<[u8; CURVE25519_SECRETKEYBYTES]>,
    agreement_pk: Option<[u8; CURVE25519_PUBLICKEYBYTES]>,
    send_handles: HashMap<[u8; ED25519_PUBLICKEYBYTES], Arc<SendHandle>, RandomState>,
}

const COMPRESSION: bool = false;

impl NodeInner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        opts: NodeOpts,
        peers: HashMap<[u8; ED25519_PUBLICKEYBYTES], Peer, RandomState>,
        agreement_sk: Option<[u8; CURVE25519_SECRETKEYBYTES]>,
        agreement_pk: Option<[u8; CURVE25519_PUBLICKEYBYTES]>,
        default_route: AtomicPtr<[u8; ED25519_PUBLICKEYBYTES]>,
        udp_socket: UdpSocket,
        udp_socket_addr: SocketAddr,
        recv_buf_tx: Sender<([u8; ED25519_PUBLICKEYBYTES], Vec<u8>)>,
    ) -> Self {
        let peers = PeersList::new(peers, default_route);

        NodeInner {
            opts,
            coarse_timer: AtomicU64::new(Self::clock()),
            peers_list: peers,
            udp_socket,
            udp_socket_addr,
            recv_buf_tx,
            agreement_sk,
            agreement_pk,
            send_handles: Default::default(),
        }
    }

    pub async fn on_udp_datagram(
        &self,
        src: SocketAddr,
        buf: &mut [u8],
        response_buf: &mut [u8],
    ) -> Result<(), NodeError> {
        self.on_packet(src, UDP, buf, response_buf).await
    }

    pub async fn on_tcp_segment(
        &self,
        src: SocketAddr,
        buf: &mut [u8],
        response_buf: &mut [u8],
    ) -> Result<(), NodeError> {
        self.on_packet(src, TCP, buf, response_buf).await
    }

    pub(in crate::node) async fn on_packet(
        &self,
        src: SocketAddr,
        prot: TransportProt,
        buf: &mut [u8],
        response_buf: &mut [u8],
    ) -> Result<(), NodeError> {
        trace!("Got packet from src {}://{}", prot, src);

        {
            // short header
            let rx_short_ids = self.peers_list.rx_short_ids.pin();
            if let Some(sender) = rx_short_ids.get(&buf[..SHORT_HEADER_ID_LEN]) {
                if let Some(Peer::NodePeer(node_peer)) = self.peers_list.peers.pin().get(sender) {
                    let payload = ShortHeader::parse(buf, node_peer.rx_key().as_ref())?;

                    // update peer information
                    let time = self.cached_time();
                    node_peer.app_rx(time);

                    return self.add_to_recv_buf(*sender, payload);
                } else {
                    unreachable!()
                }
            }
        }

        // long header
        let (long_header, body_slice) = LongHeader::parse(buf)?;
        trace!("< {}", long_header);

        if long_header.network_id != self.opts.network_id {
            return Err(NodeError::NetworkIdInvalid(long_header.network_id));
        }

        // recipient
        if long_header.recipient == self.opts.id.pk {
            let mut send_queue: Vec<(Vec<u8>, SocketAddr)> = Vec::new();
            {
                let peers = self.peers_list.peers.pin();
                let peer = if let Some(peer) = peers.get(&long_header.sender) {
                    if let Peer::NodePeer(node_peer) = peer {
                        if !node_peer.validate_pow(
                            &long_header.pow,
                            &long_header.sender,
                            self.opts.min_pow_difficulty,
                        )? {
                            return Err(NodeError::PowInvalid);
                        }
                    }
                    peer
                } else {
                    if peers.len() >= self.opts.max_peers as usize {
                        return Err(NodeError::PeersListCapacityExceeded(self.opts.max_peers));
                    }

                    let node_peer = NodePeer::new(
                        Some(&long_header.pow),
                        &long_header.sender,
                        self.opts.min_pow_difficulty,
                        self.opts.arm_messages,
                        self.agreement_sk,
                        self.agreement_pk,
                        self.cached_time(),
                    )?;
                    self.peers_list
                        .rx_short_ids
                        .pin()
                        .insert(node_peer.rx_short_id(), long_header.sender);

                    peers.get_or_insert(long_header.sender, Peer::NodePeer(node_peer))
                };

                match peer {
                    Peer::SuperPeer(super_peer) => {
                        // process packet from super peer
                        let rx_key = super_peer.rx_key();
                        match long_header.message_type.try_into() {
                            Ok(MessageType::ACK) => {
                                // process ACK
                                let ack =
                                    AckMessage::parse(body_slice, long_header, rx_key.as_ref())?;
                                trace!("< {}", ack);

                                // update peer information
                                let time = self.current_time();
                                super_peer.ack_rx(time, src, prot, ack.time.into());
                            }
                            Ok(MessageType::UNITE) => {
                                if self.opts.process_unites {
                                    // process UNITE
                                    let unite = UniteMessage::parse(
                                        body_slice,
                                        long_header,
                                        rx_key.as_ref(),
                                    )?;
                                    trace!("< {}", unite);

                                    if let Some(Peer::NodePeer(node_peer)) =
                                        self.peers_list.peers.pin().get(&unite.address)
                                    {
                                        let unite_endpoints: HashSet<SocketAddr> =
                                            <&[u8] as Into<EndpointsList>>::into(&unite.endpoints)
                                                .0;

                                        // remove all endpoints in unite_endpoints whose ip addr is not in the same ip family as socket_ip
                                        let unite_endpoints = unite_endpoints
                                            .into_iter()
                                            .filter(|endpoint| {
                                                endpoint.ip().is_ipv4()
                                                    == self.udp_socket_addr.ip().is_ipv4()
                                            })
                                            .collect::<HashSet<_>>();

                                        let existing_addrs: HashSet<SocketAddr> = node_peer
                                            .endpoint_candidates()
                                            .keys()
                                            .copied()
                                            .collect();
                                        let new_addrs: HashSet<SocketAddr> = unite_endpoints
                                            .difference(&existing_addrs)
                                            .copied()
                                            .collect();

                                        let mut new_endpoints: StdHashMap<
                                            SocketAddr,
                                            EndpointCandidate,
                                        > = new_addrs
                                            .iter()
                                            .map(|&addr| (addr, EndpointCandidate::new()))
                                            .collect();

                                        for (endpoint_addr, candidate) in &mut new_endpoints {
                                            trace!(
                                                "Try to reach peer via new endpoint retrieved from UNITE: {}",
                                                endpoint_addr
                                            );
                                            let time = self.current_time();
                                            let hello = HelloNodePeerMessage::build(
                                                &self.opts.network_id,
                                                &self.opts.id.pk,
                                                &self.opts.id.pow,
                                                node_peer.tx_key().as_ref(),
                                                &unite.address,
                                                time,
                                                node_peer.rx_short_id(),
                                            )?;

                                            // queue HELLO and sent it later, otherwise entry lock is held across an async call
                                            send_queue.push((hello, *endpoint_addr));

                                            candidate.hello_tx(time);
                                        }
                                        for (addr, candidate) in new_endpoints {
                                            node_peer.endpoint_candidates().insert(addr, candidate);
                                        }
                                    }
                                } else {
                                    trace!("Ignoring unite message");
                                }
                            }
                            Ok(message_type @ (MessageType::APP | MessageType::HELLO)) => {
                                return Err(NodeError::MessageTypeUnexpected(message_type));
                            }
                            Err(_) => return Err(NodeError::MessageTypeInvalid),
                        }
                    }
                    Peer::NodePeer(node_peer) => {
                        // process packet from node peer
                        let rx_key = node_peer.rx_key();
                        match long_header.message_type.try_into() {
                            Ok(MessageType::ACK) => {
                                // process ACK
                                let ack =
                                    AckMessage::parse(body_slice, long_header, rx_key.as_ref())?;
                                self.on_node_peer_ack(src, node_peer, long_header.sender, ack)?;
                            }
                            Ok(MessageType::APP) => {
                                // process APP
                                let app =
                                    AppMessage::parse(body_slice, long_header, rx_key.as_ref())?;
                                self.on_app(node_peer, long_header.sender, &app)?;
                            }
                            Ok(MessageType::HELLO) => {
                                // process HELLO
                                let hello = HelloNodePeerMessage::parse(
                                    body_slice,
                                    long_header,
                                    rx_key.as_ref(),
                                )?;
                                trace!("< {}", hello);

                                // time
                                let time = self.current_time();
                                let hello_time = hello.time.into();

                                let time_diff = time.saturating_sub(hello_time);
                                if time_diff > (self.opts.hello_max_age * 1_000) {
                                    if log_enabled!(Level::Warn) {
                                        warn!(
                                            "Got too old HELLO from {}",
                                            bytes_to_hex(&long_header.sender)
                                        );
                                    }
                                    return Err(NodeError::HelloTooOld(time_diff));
                                }

                                // short id
                                if hello.short_id != SHORT_ID_NONE {
                                    node_peer.set_tx_short_id(hello.short_id);
                                }

                                // reply with ACK
                                let ack_len = AckMessage::build(
                                    response_buf,
                                    &self.opts.network_id,
                                    &self.opts.id.pk,
                                    &self.opts.id.pow,
                                    node_peer.tx_key().as_ref(),
                                    &long_header.sender,
                                    hello_time,
                                )?;

                                let hello_from_unknown_endpoint =
                                    !node_peer.endpoint_candidates().contains_key(&src);
                                let tx_key = if hello_from_unknown_endpoint {
                                    let candidate = EndpointCandidate::new();
                                    candidate.hello_tx(time);
                                    node_peer.endpoint_candidates().insert(src, candidate);

                                    node_peer.tx_key()
                                } else {
                                    None
                                };

                                // queue HELLO and sent it later, otherwise entry lock is held across an async call
                                // TODO: avoid to_vec clone!
                                send_queue.push((response_buf[..ack_len].to_vec(), src));

                                // HELLO from unknown endpoint? peer might be behind symmetric NAT
                                #[allow(clippy::map_entry)]
                                if hello_from_unknown_endpoint {
                                    trace!(
                                        "Try to reach peer via new endpoint observed from received HELLO: {}",
                                        src
                                    );

                                    let time = self.current_time();
                                    let hello = HelloNodePeerMessage::build(
                                        &self.opts.network_id,
                                        &self.opts.id.pk,
                                        &self.opts.id.pow,
                                        tx_key.as_ref(),
                                        &long_header.sender,
                                        time,
                                        node_peer.rx_short_id(),
                                    )?;
                                    send_queue.push((hello, src));
                                }
                            }
                            Ok(MessageType::UNITE) => {
                                // node peers not sending UNITEs
                                return Err(NodeError::MessageTypeUnexpected(MessageType::UNITE));
                            }
                            Err(_) => return Err(NodeError::MessageTypeInvalid),
                        }
                    }
                }
            }

            // process send queue
            for (msg, dst) in send_queue {
                if let Err(e) = self.udp_socket.send_to(&msg, dst).await {
                    debug!("Failed to send msg to udp://{}: {}", dst, e);
                    continue;
                } else if log_enabled!(Level::Trace) {
                    trace!("Sent msg to udp://{}.", dst);
                }
            }

            Ok(())
        } else {
            Err(NodeError::MessageInvalidRecipient)
        }
    }

    pub fn cached_time(&self) -> u64 {
        self.coarse_timer.load(SeqCst)
    }

    pub(in crate::node) fn current_time(&self) -> u64 {
        self.coarse_timer.store(Self::clock(), SeqCst);
        self.cached_time()
    }

    fn on_node_peer_ack(
        &self,
        src: SocketAddr,
        node_peer: &NodePeer,
        sender: [u8; ED25519_PUBLICKEYBYTES],
        ack: &AckMessage,
    ) -> Result<(), NodeError> {
        trace!("< {}", ack);

        // time
        let time = self.current_time();
        let mut hello_time = ack.time.into();

        if time < hello_time {
            // TODO: This can be removed once we've switched to a monotonically increasing time source.
            hello_time = time;
        }

        let message_age = time - hello_time;
        if message_age > (self.opts.hello_max_age * 1_000) {
            if log_enabled!(Level::Warn) {
                warn!("Got too old ACK from {}", bytes_to_hex(&sender));
            }
            return Err(NodeError::AckTooOld(message_age));
        }

        // update peer information
        node_peer.ack_rx(time, src, hello_time);

        Ok(())
    }

    fn on_app(
        &self,
        node_peer: &NodePeer,
        sender: [u8; ED25519_PUBLICKEYBYTES],
        app: &AppMessage,
    ) -> Result<(), NodeError> {
        trace!("< {}", app);

        // update peer information
        let time = self.cached_time();
        node_peer.app_rx(time);

        self.add_to_recv_buf(sender, &app.payload)
    }

    fn add_to_recv_buf(&self, sender: [u8; 32], payload: &[u8]) -> Result<(), NodeError> {
        if log_enabled!(Level::Debug) {
            debug!("Received APP from {}", bytes_to_hex(&sender));
        }

        let payload = if COMPRESSION {
            decompress_size_prepended(payload).unwrap()
        } else {
            payload.to_vec()
        };

        let tx = &self.recv_buf_tx;
        // TODO: `to_vec` allocates new memory. Using something like an MPSC ring buffer would allow us to reuse the same memory, potentially improving performance.
        match tx.try_send((sender, payload)) {
            Ok(_) => {}
            Err(TrySendError::Full(_)) => warn!("Received APP dropped: recv buf full."),
            Err(TrySendError::Disconnected(_)) => return Err(NodeError::RecvBufDisconnected),
        }

        Ok(())
    }

    async fn housekeeping(&self, inner: &Arc<NodeInner>) -> Result<(), NodeError> {
        let time = inner.current_time();

        {
            // remove stale rx short ids
            // running this first ensures that short IDs remain available until the next housekeeping cycle, even after the peer has been removed from the peers list.
            let guard = self.peers_list.peers.guard();
            self.peers_list
                .rx_short_ids
                .pin()
                .retain(|_, peer_key| self.peers_list.peers.contains_key(peer_key, &guard));

            // remove stale peers
            let peers_guard = self.peers_list.peers.guard();
            let send_handles_guard = self.send_handles.guard();
            self.peers_list.peers.retain(
                |key, peer| match &peer {
                    Peer::SuperPeer(_) => true,
                    Peer::NodePeer(node_peer) => {
                        let is_new = node_peer.is_new(time, inner.opts.hello_timeout);
                        let is_active = node_peer.is_reachable()
                            && (node_peer.has_app_traffic(time)
                                || self.send_handles.contains_key(key, &send_handles_guard));
                        is_new || is_active
                    }
                },
                &peers_guard,
            );
        }

        // get local addresses
        let my_addrs = self.my_addrs(&inner.opts.hello_addresses_excluded)?;

        // endpoints
        let endpoints: Vec<u8> =
            self.my_endpoint_candidates(&inner.opts.hello_endpoints, &my_addrs)?;

        let mut best_median_lat = u64::MAX;
        let mut best_sp = self.peers_list.default_route_ptr.load(SeqCst) as usize;

        for (peer_key, peer) in &inner.peers_list.peers.pin_owned() {
            let peer_key_ptr = peer_key as *const [u8; ED25519_PUBLICKEYBYTES];
            match (*peer_key, peer) {
                (peer_key, Peer::SuperPeer(super_peer)) => {
                    let time = inner.current_time();

                    // best super peer?
                    if let Some(median_lat) = super_peer.median_lat() {
                        if median_lat < best_median_lat {
                            best_median_lat = median_lat;
                            best_sp = peer_key_ptr as usize;
                        }
                    }

                    // tcp connection scheduled for shutdown?
                    let tcp_shutdown_scheduled = super_peer.tcp_shutdown_scheduled.load(SeqCst);
                    if tcp_shutdown_scheduled {
                        super_peer
                            .shutdown_tcp_connection()
                            .await
                            .map_err(NodeError::TcpShutdownError)?;
                    }

                    // tcp connection required?
                    if super_peer.do_tcp_fallback(time, inner.opts.hello_timeout) {
                        // get tcp socketaddr
                        let tcp_addr = super_peer.resolved_tcp_addr();
                        let tcp_inner = inner.clone();
                        let tx_key = super_peer.tx_key();

                        super_peer.set_tcp_handle(tokio::spawn(async move {
                            if let Ok(stream) = TcpStream::connect(tcp_addr).await {
                                if let Err(e) = Self::handle_tcp_stream(
                                    peer_key, time, tcp_addr, &tcp_inner, tx_key, stream,
                                )
                                .await
                                {
                                    error!("Failed to handle TCP stream: {}", e);
                                }
                            }
                        }));
                    }

                    // send HELLO
                    match SuperPeer::resolve_addr(self.udp_socket_addr, super_peer.addr()).await {
                        Ok(resolved_addr) => super_peer.set_resolved_addr(resolved_addr),
                        Err(e) => warn!(
                            "Failed to update resolved super peer address {}: {}",
                            super_peer.addr(),
                            e
                        ),
                    }

                    if log_enabled!(Level::Trace) {
                        trace!("Send HELLO to super peer {}", bytes_to_hex(&peer_key));
                    }

                    let hello = HelloSuperPeerMessage::build(
                        &inner.opts.network_id,
                        &inner.opts.id.pk,
                        &inner.opts.id.pow,
                        super_peer.tx_key().as_ref(),
                        &peer_key,
                        time,
                        &endpoints,
                    )?;

                    // First try TCP if available
                    if let Some(stream) = super_peer.tcp_stream() {
                        self.send_super_peer_tcp(&stream, &hello).await?;
                        super_peer.hello_tx(time);
                    } else {
                        // Fallback to UDP
                        // queue HELLO and sent it later, otherwise entry lock is held across an async call
                        super_peer.hello_tx(time);
                        let dst = *super_peer.resolved_addr();

                        if let Err(e) = inner.udp_socket.send_to(&hello, dst).await {
                            debug!("Failed to send HELLO to super peer udp://{}: {}", dst, e);
                            continue;
                        } else if log_enabled!(Level::Trace) {
                            trace!("Sent HELLO to super peer udp://{}.", dst);
                        }
                    };
                }
                (peer_key, Peer::NodePeer(node_peer)) => {
                    // remove stale endpoints
                    node_peer.remove_stale_endpoints(time, inner.opts.hello_timeout);

                    // ensure peer has unique short id
                    {
                        let guard = self.peers_list.rx_short_ids.guard();
                        loop {
                            if self
                                .peers_list
                                .rx_short_ids
                                .try_insert(node_peer.rx_short_id(), peer_key, &guard)
                                .is_ok()
                            {
                                break;
                            }

                            let mut short_id = [0u8; 4];
                            random_bytes(&mut short_id);
                            node_peer.set_rx_short_id(short_id);
                        }
                    }

                    if node_peer.has_app_traffic(time) {
                        let time = inner.current_time();
                        let tx_key = node_peer.tx_key();
                        for (endpoint_addr, candidate) in &node_peer.endpoint_candidates() {
                            trace!(
                                "Contact peer via endpoint to test reachability/maintain link: {}",
                                endpoint_addr
                            );
                            let hello = HelloNodePeerMessage::build(
                                &inner.opts.network_id,
                                &inner.opts.id.pk,
                                &inner.opts.id.pow,
                                tx_key.as_ref(),
                                &peer_key,
                                time,
                                node_peer.rx_short_id(),
                            )?;

                            let dst = *endpoint_addr;
                            candidate.hello_tx(time);

                            if let Err(e) = inner.udp_socket.send_to(&hello, dst).await {
                                debug!("Failed to send HELLO to node peer udp://{}: {}", dst, e);
                                continue;
                            } else if log_enabled!(Level::Trace) {
                                trace!("Sent HELLO to node peer udp://{}.", dst);
                            }
                        }
                    }

                    if !node_peer.is_reachable() {
                        node_peer.set_tx_short_id(SHORT_ID_NONE);
                    }
                }
            }
        }

        self.peers_list.default_route_ptr.store(
            best_sp as *const [u8; ED25519_PUBLICKEYBYTES] as *mut [u8; ED25519_PUBLICKEYBYTES],
            SeqCst,
        );

        // remove stale peers
        self.peers_list.peers.pin().retain(|_, peer| {
            let hello_timeout = inner.opts.hello_timeout;
            !(match &peer {
                Peer::SuperPeer(_) => false,
                Peer::NodePeer(node_peer) => {
                    !node_peer.is_new(time, hello_timeout)
                        && (!node_peer.is_reachable() || !node_peer.has_app_traffic(time))
                }
            })
        });

        info!("\n{}", self.peers_list);

        // update send handles
        let peers = self.peers_list.peers.pin();

        let default_route = self.peers_list.default_route();
        let Peer::SuperPeer(super_peer) = peers.get(default_route).unwrap() else {
            unreachable!()
        };
        let sp_tcp_stream = super_peer.tcp_stream();
        let sp_resolved_addr = *super_peer.resolved_addr();

        for (peer_key, handle) in &inner.send_handles.pin_owned() {
            let peer = peers.get(peer_key);
            if let Some(Peer::NodePeer(node_peer)) = peer {
                handle.update_state(SendHandleState {
                    best_addr: node_peer.best_addr().copied(),
                    app_tx: node_peer.app_tx.clone(),
                    tx_key: node_peer.tx_key(),
                    short_id: node_peer.tx_short_id(),
                    sp_tcp_stream: sp_tcp_stream.clone(),
                    sp_resolved_addr,
                });
            } else {
                handle.update_state(SendHandleState {
                    best_addr: None,
                    app_tx: Default::default(),
                    tx_key: None,
                    short_id: None,
                    sp_tcp_stream: sp_tcp_stream.clone(),
                    sp_resolved_addr,
                });
            }
        }

        Ok(())
    }

    async fn send_super_peer_tcp(
        &self,
        stream: &Arc<Mutex<OwnedWriteHalf>>,
        msg: &[u8],
    ) -> Result<TransportProt, NodeError> {
        if (stream.lock().await.write_all(msg).await).is_err() {
            if let Err(e) = stream.lock().await.shutdown().await {
                error!("Error shutting down connection: {}", e);
            }
        }

        if log_enabled!(Level::Trace) {
            trace!("Sent to super peer via TCP.");
        }
        Ok(TCP)
    }

    async fn handle_tcp_stream(
        peer_key: [u8; ED25519_PUBLICKEYBYTES],
        time: u64,
        tcp_addr: SocketAddr,
        inner: &Arc<NodeInner>,
        tx_key: Option<[u8; AEGIS_KEYBYTES]>,
        stream: TcpStream,
    ) -> Result<(), NodeError> {
        trace!("New TCP connection to {}", tcp_addr);
        let src = stream.peer_addr().map_err(NodeError::TcpPeerAddrError)?;
        let (mut read_half, mut write_half) = stream.into_split();

        // immediately after connection establishment send HELLO
        // get local addresses
        let my_addrs = inner.my_addrs(&inner.opts.hello_addresses_excluded)?;

        // endpoints
        let endpoints: Vec<u8> =
            inner.my_endpoint_candidates(&inner.opts.hello_endpoints, &my_addrs)?;

        let hello = HelloSuperPeerMessage::build(
            &inner.opts.network_id,
            &inner.opts.id.pk,
            &inner.opts.id.pow,
            tx_key.as_ref(),
            &peer_key,
            time,
            &endpoints,
        )
        .map_err(NodeError::MessageError)?;

        write_half
            .write_all(&hello)
            .await
            .map_err(|e| NodeError::SendFailed(TCP, e))?;

        if log_enabled!(Level::Trace) {
            trace!(
                "Sent HELLO to node peer {} via tcp://{}.",
                bytes_to_hex(&peer_key),
                tcp_addr
            );
        }

        if let Some(Peer::SuperPeer(super_peer)) = inner.peers_list.peers.pin().get(&peer_key) {
            super_peer.hello_tx(time);
            super_peer.set_tcp_stream(write_half);
        }

        let tcp_inner = inner.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; tcp_inner.opts.mtu];
            let mut response_buf = vec![0u8; tcp_inner.opts.mtu];
            loop {
                // read segment
                let size = match read_half.read(&mut buf).await {
                    Ok(0) => {
                        trace!("TCP connection closed by peer {}", src);
                        if let Some(Peer::SuperPeer(super_peer)) =
                            tcp_inner.peers_list.peers.pin().get(&peer_key)
                        {
                            super_peer.reset_tcp_state();
                        }
                        break;
                    }
                    Ok(result) => result,
                    Err(e) => {
                        error!("Error receiving segment: {}", e);
                        if let Some(Peer::SuperPeer(super_peer)) =
                            tcp_inner.peers_list.peers.pin().get(&peer_key)
                        {
                            super_peer.reset_tcp_state();
                        }
                        break;
                    }
                };

                // process segment
                if let Err(e) = tcp_inner
                    .on_tcp_segment(src, &mut buf[..size], &mut response_buf)
                    .await
                {
                    error!("Error processing segment: {}", e);
                    if let Some(Peer::SuperPeer(super_peer)) =
                        tcp_inner.peers_list.peers.pin_owned().get(&peer_key)
                    {
                        if let Some(stream) = super_peer.tcp_stream() {
                            if let Err(e) = stream.lock().await.shutdown().await {
                                error!("Error shutting down connection: {}", e);
                            }
                        }
                    }
                    break;
                }
            }
        });

        Ok(())
    }

    fn my_endpoint_candidates(
        &self,
        hello_endpoints: &str,
        my_addrs: &[IpAddr],
    ) -> Result<Vec<u8>, NodeError> {
        Ok(if hello_endpoints.is_empty() {
            let endpoints = listening_addrs(&self.udp_socket_addr.ip(), my_addrs)
                .iter()
                .take(HELLO_MAX_ENDPOINTS)
                .map(|ip| SocketAddr::new(*ip, self.udp_socket_addr.port()))
                .collect::<HashSet<_>>();
            <EndpointsList as Into<Vec<u8>>>::into(EndpointsList(endpoints))
        } else {
            let endpoints: HashSet<SocketAddr> = hello_endpoints
                .split_whitespace()
                .map(|endpoint_str| {
                    endpoint_str
                        .parse()
                        .map_err(|_| NodeError::HelloEndpointInvalid(endpoint_str.to_string()))
                })
                .collect::<Result<HashSet<_>, _>>()?;
            <EndpointsList as Into<Vec<u8>>>::into(EndpointsList(endpoints.clone()))
        })
    }

    fn my_addrs(&self, hello_addresses_excluded: &str) -> Result<Vec<IpAddr>, NodeError> {
        let mut my_addrs = get_addrs().map_err(NodeError::GetAddrsFailed)?;
        let exclude: HashSet<IpAddr> = hello_addresses_excluded
            .split_whitespace()
            .map(|address_str| {
                address_str
                    .parse()
                    .map_err(|_| NodeError::HelloAddressInvalid(address_str.to_string()))
            })
            .collect::<Result<HashSet<_>, _>>()?;
        my_addrs.retain(|ip| !exclude.contains(ip));

        Ok(my_addrs)
    }

    pub(in crate::node) fn clock() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64
    }
}

const MIN_DERIVED_PORT: u16 = 22528;

struct SendHandleState {
    best_addr: Option<SocketAddr>,
    app_tx: Arc<AtomicU64>,
    tx_key: Option<[u8; AEGIS_KEYBYTES]>,
    short_id: Option<[u8; 4]>,
    sp_tcp_stream: Option<Arc<Mutex<OwnedWriteHalf>>>,
    sp_resolved_addr: SocketAddr,
}

pub struct SendHandleGuard(Arc<SendHandle>);

impl Drop for SendHandleGuard {
    fn drop(&mut self) {
        self.inner.send_handles.pin().remove(&self.recipient);
    }
}

impl Deref for SendHandleGuard {
    type Target = SendHandle;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct SendHandle {
    inner: Arc<NodeInner>,
    recipient: [u8; ED25519_PUBLICKEYBYTES],
    state_ptr: ArcSwap<SendHandleState>,
}

impl SendHandle {
    pub fn new(
        inner: Arc<NodeInner>,
        recipient: [u8; ED25519_PUBLICKEYBYTES],
    ) -> Result<Self, NodeError> {
        let peers = inner.peers_list.peers.pin();
        let peer = if let Some(peer) = peers.get(&recipient) {
            peer
        } else {
            if peers.len() >= inner.opts.max_peers as usize {
                return Err(NodeError::PeersListCapacityExceeded(inner.opts.max_peers));
            }

            let node_peer = NodePeer::new(
                None,
                &recipient,
                inner.opts.min_pow_difficulty,
                inner.opts.arm_messages,
                inner.agreement_sk,
                inner.agreement_pk,
                inner.cached_time(),
            )?;
            inner
                .peers_list
                .rx_short_ids
                .pin()
                .insert(node_peer.rx_short_id(), recipient);

            peers.get_or_insert(recipient, Peer::NodePeer(node_peer))
        };

        let default_route = inner.peers_list.default_route();
        let Peer::SuperPeer(super_peer) = peers.get(default_route).unwrap() else {
            unreachable!()
        };
        let sp_tcp_stream = super_peer.tcp_stream();
        let sp_resolved_addr = *super_peer.resolved_addr();

        if let Peer::NodePeer(node_peer) = peer {
            Ok(Self {
                inner: inner.clone(),
                recipient,
                state_ptr: ArcSwap::from_pointee(SendHandleState {
                    best_addr: node_peer.best_addr().copied(),
                    app_tx: node_peer.app_tx.clone(),
                    tx_key: node_peer.tx_key(),
                    short_id: node_peer.tx_short_id(),
                    sp_tcp_stream,
                    sp_resolved_addr,
                }),
            })
        } else {
            unreachable!()
        }
    }

    fn state(&self) -> Guard<Arc<SendHandleState>> {
        self.state_ptr.load()
    }

    fn update_state(&self, new_state: SendHandleState) {
        self.state_ptr.swap(Arc::new(new_state));
    }

    pub async fn send(&self, bytes: &[u8]) -> Result<(), NodeError> {
        let bytes = if COMPRESSION {
            &compress_prepend_size(bytes)
        } else {
            bytes
        };

        let state = self.state();
        let best_addr = state.best_addr;
        let short_id = state.short_id;
        let sp_tcp_stream = &state.sp_tcp_stream;
        let sp_resolved_addr = state.sp_resolved_addr;

        // TODO: Consider using a buffer pool to avoid repeated allocations.
        let app = if best_addr.is_none() || short_id.is_none() {
            AppMessage::build(
                &self.inner.opts.network_id,
                &self.inner.opts.id.pk,
                &self.inner.opts.id.pow,
                state.tx_key.as_ref(),
                &self.recipient,
                bytes,
            )?
        } else {
            ShortHeader::build(short_id.unwrap(), state.tx_key.as_ref(), bytes)?
        };

        if app.len() > self.inner.opts.mtu {
            return Err(NodeError::AppLenInvalid(app.len(), self.inner.opts.mtu));
        }

        let time = self.inner.cached_time();
        state.app_tx.store(time, SeqCst);

        // TODO: Instead of writing directly to the network, consider writing to a send buffer that a separate thread sends to the network.

        // direct link?
        if let Some(my_addr) = state.best_addr {
            self.inner
                .udp_socket
                .send_to(&app, my_addr)
                .await
                .map_err(|e| NodeError::UdpSendToError(e, my_addr))?;

            if log_enabled!(Level::Debug) {
                debug!(
                    "Sent APP to node peer {} via udp://{}.",
                    bytes_to_hex(&self.recipient),
                    my_addr
                );
            }

            return Ok(());
        }

        // forward
        // get best super peer
        let default_route = self.inner.peers_list.default_route();

        // First try TCP if available
        let prot = if let Some(stream) = sp_tcp_stream {
            self.inner.send_super_peer_tcp(stream, &app).await?;
            TCP
        } else {
            // Fallback to UDP
            self.inner
                .udp_socket
                .send_to(&app, sp_resolved_addr)
                .await
                .map_err(|e| NodeError::UdpSendToError(e, sp_resolved_addr))?;

            UDP
        };

        if log_enabled!(Level::Debug) {
            debug!(
                "Sent APP to node peer {} via super peer {} via {}.",
                bytes_to_hex(&self.recipient),
                bytes_to_hex(default_route),
                prot,
            );
        }

        Ok(())
    }
}

pub struct Node {
    inner: Arc<NodeInner>,
    #[allow(clippy::type_complexity)]
    recv_buf_rx: Arc<Receiver<([u8; ED25519_PUBLICKEYBYTES], Vec<u8>)>>,
}

impl Node {
    pub async fn bind(opts: NodeOpts) -> Result<Node, NodeError> {
        // generate agreement keys
        let (agreement_sk, agreement_pk) = if opts.arm_messages {
            (
                Some(convert_ed25519_sk_to_curve25519_sk(&opts.id.sk)?),
                Some(convert_ed25519_pk_to_curve22519_pk(&opts.id.pk)?),
            )
        } else {
            (None, None)
        };

        // start udp server
        let udp_socket = UdpSocket::bind(Self::derive_udp_port(&opts.udp_listen, &opts.id.pk))
            .await
            .map_err(NodeError::BindError)?;
        let udp_socket_addr = udp_socket
            .local_addr()
            .map_err(NodeError::UdpLocalAddrError)?;
        info!("Bound UDP server to {}", udp_socket_addr);

        // peers
        let peers = HashMap::builder()
            .capacity(opts.max_peers as usize)
            .hasher(RandomState::new())
            .build();
        for (peer_pk, (addr, tcp_port)) in SuperPeerUrl::parse_list(opts.super_peers.as_str()) {
            let resolved_addr = SuperPeer::resolve_addr(udp_socket_addr, &addr).await?;
            peers.pin().insert(
                peer_pk,
                Peer::SuperPeer(SuperPeer::new(
                    opts.arm_messages,
                    &peer_pk,
                    agreement_sk.as_ref(),
                    agreement_pk.as_ref(),
                    addr,
                    resolved_addr,
                    tcp_port,
                )?),
            );
        }

        if opts.super_peers.is_empty() {
            return Err(NodeError::NoSuperPeers);
        }

        // make first peer default route
        let default_key = peers.pin().keys().next().unwrap() as *const [u8; ED25519_PUBLICKEYBYTES]
            as *mut [u8; ED25519_PUBLICKEYBYTES];
        let default_route = AtomicPtr::new(default_key);

        let (recv_buf_tx, recv_buf_rx) = flume::bounded(opts.recv_buf_cap);
        let inner = Arc::new(NodeInner::new(
            opts,
            peers,
            agreement_sk,
            agreement_pk,
            default_route,
            udp_socket,
            udp_socket_addr,
            recv_buf_tx,
        ));

        // housekeeping task
        let housekeeping_inner = inner.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(
                housekeeping_inner.opts.housekeeping_delay,
            ));

            loop {
                interval.tick().await;
                if let Err(e) = housekeeping_inner.housekeeping(&housekeeping_inner).await {
                    error!("Error in housekeeping: {}", e);
                }
                tokio::time::sleep(Duration::from_millis(
                    housekeeping_inner.opts.housekeeping_delay,
                ))
                .await;
            }
        });

        // udp server
        let udp_inner = inner.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; udp_inner.opts.mtu];
            let mut response_buf = vec![0u8; udp_inner.opts.mtu];
            loop {
                // read datagram
                let (size, src) = match udp_inner.udp_socket.recv_from(&mut buf).await {
                    Ok(result) => result,
                    Err(e) => {
                        error!("Error receiving datagram: {}", e);
                        continue;
                    }
                };

                // process datagram
                if let Err(e) = udp_inner
                    .on_udp_datagram(src, &mut buf[..size], &mut response_buf)
                    .await
                {
                    error!("Error processing packet: {}", e);
                    continue;
                }
            }
        });

        Ok(Self {
            inner,
            recv_buf_rx: Arc::new(recv_buf_rx),
        })
    }

    pub fn recv_buf_len(&self) -> usize {
        self.recv_buf_rx.len()
    }

    pub async fn recv_from(&self) -> Result<(Vec<u8>, [u8; ED25519_PUBLICKEYBYTES]), NodeError> {
        match self.recv_buf_rx.recv_async().await {
            Ok((sender, message)) => Ok((message, sender)),
            Err(_) => Err(NodeError::RecvBufDisconnected),
        }
    }

    pub async fn send_to<'a>(
        &self,
        recipient: &'a [u8; ED25519_PUBLICKEYBYTES],
        bytes: &'a [u8],
    ) -> Result<(), NodeError> {
        self.send_handle(recipient)?.send(bytes).await
    }

    pub fn send_handle(
        &self,
        recipient: &[u8; ED25519_PUBLICKEYBYTES],
    ) -> Result<SendHandleGuard, NodeError> {
        let guard = self.inner.send_handles.guard();
        let handle = self
            .inner
            .send_handles
            .try_insert(
                *recipient,
                Arc::new(SendHandle::new(self.inner.clone(), *recipient)?),
                &guard,
            )
            .map_err(|_| NodeError::SendHandleAlreadyCreated)?;
        Ok(SendHandleGuard(handle.clone()))
    }

    fn derive_udp_port(udp_listen: &str, id_pk: &[u8; ED25519_PUBLICKEYBYTES]) -> String {
        let mut parts = udp_listen.rsplitn(2, ':');

        match (parts.next(), parts.next()) {
            (Some(port_str), Some(addr)) => {
                match port_str.parse::<i32>() {
                    Ok(-1) => {
                        // derive a port in the range between MIN_DERIVED_PORT and {MAX_PORT_NUMBER from its
                        // own identity. this is done because we also expose this port via
                        // UPnP-IGD/NAT-PMP/PCP and some NAT devices behave unexpectedly when multiple nodes
                        // in the local network try to expose the same local port.
                        // a completely random port would have the disadvantage that every time the node is
                        // started it would use a new port and this would make discovery more difficult
                        let identity_hash = murmur3_32(&mut Cursor::new(id_pk), 0).unwrap().to_be();
                        let identity_port = MIN_DERIVED_PORT
                            + (identity_hash % (u16::MAX - MIN_DERIVED_PORT) as u32) as u16;
                        format!("{addr}:{identity_port}")
                    }
                    _ => udp_listen.to_owned(),
                }
            }
            _ => udp_listen.to_owned(),
        }
    }
}

#[derive(Debug, Error)]
pub enum SuperPeerUrlError {
    #[error("So public key")]
    NoPublicKey,

    #[error("No address")]
    NoAddr,

    #[error("Invalid url")]
    InvalidUrl,
}

struct SuperPeerUrl {
    addr: String,
    tcp_port: u16,
    pk: [u8; ED25519_PUBLICKEYBYTES],
}

impl SuperPeerUrl {
    pub fn parse_list(peers_str: &str) -> StdHashMap<[u8; ED25519_PUBLICKEYBYTES], (String, u16)> {
        let mut peers = StdHashMap::new();

        peers_str.split_whitespace().for_each(|url_str| {
            if let Ok(url) = SuperPeerUrl::from_str(url_str) {
                peers.insert(url.pk, (url.addr, url.tcp_port));
            }
        });

        peers
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

                // Parse Query Parameter für Public Key und TCP Port
                for param in query.split('&') {
                    if let Some((key, value)) = param.split_once('=') {
                        match key {
                            "publicKey" => {
                                public_key = Some(hex_to_bytes::<ED25519_PUBLICKEYBYTES>(value));
                            }
                            "tcpPort" => {
                                if let Ok(port) = value.parse::<u16>() {
                                    tcp_port = port;
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
