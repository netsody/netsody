mod peers;

use crate::identity::Identity;
use crate::messages::{
    AckMessage, HelloMessageSigned, MessageError, MessageType, PRIVATE_HEADER_ARMED_LEN,
    PRIVATE_HEADER_UNARMED_LEN, PUBLIC_HEADER_NETWORK_ID_LEN, PrivateHeader, PublicHeader,
    UniteMessage,
};
use crate::super_peer::peers::{PeersError, PeersList, TransportProt};
use crate::utils::crypto::{
    CURVE25519_PUBLICKEYBYTES, CURVE25519_SECRETKEYBYTES, CryptoError, ED25519_PUBLICKEYBYTES,
    convert_ed25519_pk_to_curve22519_pk, convert_ed25519_sk_to_curve25519_sk,
};
use crate::utils::hex::bytes_to_hex;
use TransportProt::{TCP, UDP};
use derive_builder::Builder;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use log::{Level, debug, error, info, log_enabled, trace};
use papaya::HashMap;

use core::sync::atomic::Ordering::SeqCst;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::task::{JoinError, JoinHandle};

pub const MAX_HOP_COUNT: u8 = 7u8;
pub const NETWORK_ID_DEFAULT: i32 = 1;
pub const UDP4_LISTEN_DEFAULT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 22527);
pub const UDP6_LISTEN_DEFAULT: SocketAddrV6 =
    SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 22527, 0, 0);
pub const TCP4_LISTEN_DEFAULT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8443);
pub const TCP6_LISTEN_DEFAULT: SocketAddrV6 =
    SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 8443, 0, 0);
pub const ARM_MESSAGES_DEFAULT: bool = true;
pub const SEND_UNITS_DEFAULT: i32 = 5 * 1_000; // milliseconds, set to -1 disables UNITE sending
pub const MAX_PEERS_DEFAULT: u64 = 10_000; // set to 0 removes peers limit
pub const MIN_POW_DIFFICULTY_DEFAULT: u8 = 24;
pub const HELLO_TIMEOUT_DEFAULT: u64 = 30 * 1_000; // milliseconds
pub const HELLO_MAX_AGE_DEFAULT: u64 = 60 * 1_000; // milliseconds
pub const MTU_DEFAULT: usize = 1472; // Ethernet MTU (1500) - IPv4 header (20) - UDP header (8)
pub const HOUSEKEEPING_DELAY_DEFAULT: u64 = 5 * 1_000; // milliseconds

#[derive(Debug, Error)]
pub enum SuperPeerError {
    #[error("Send failed: {0}")]
    SendFailed(#[from] io::Error),

    #[error("Message error: {0}")]
    MessageError(#[from] MessageError),

    #[error("Peers manager error: {0}")]
    PeersError(#[from] PeersError),

    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),

    #[error("UDP4 bind error: {0}")]
    Udp4BindError(io::Error),

    #[error("UDP6 bind error: {0}")]
    Udp6BindError(io::Error),

    #[error("TCP4 bind error: {0}")]
    Tcp4BindError(io::Error),

    #[error("TCP6 bind error: {0}")]
    Tcp6BindError(io::Error),

    #[error("Message from other network: {}", i32::from_be_bytes(*.0))]
    NetworkIdInvalid([u8; PUBLIC_HEADER_NETWORK_ID_LEN]),

    #[error("Invalid proof of work")]
    PowInvalid,

    #[error("Unarmed message")]
    MessageUnarmed,

    #[error("Armed message")]
    MessageArmed,

    #[error("Packet too short to contain a private header")]
    PrivateHeaderInvalid,

    #[error("Unexpected message type {0}")]
    MessageTypeUnexpected(MessageType),

    #[error("HELLO time diff too large: {0} ms")]
    HelloTimeInvalid(u64),

    #[error("Loopback forwarding not allowed")]
    LoopbackForwarding,

    #[error("Task error: {0}")]
    TaskError(#[from] JoinError),

    #[error("UDP4 failed: {0}")]
    Udp4Failed(JoinError),

    #[error("UDP6 failed: {0}")]
    Udp6Failed(JoinError),

    #[error("TCP4 failed: {0}")]
    Tcp4Failed(JoinError),

    #[error("TCP6 failed: {0}")]
    Tcp6Failed(JoinError),

    #[error("Neither UDP nor TCP servers has been started")]
    NeitherUdpNorTcpServers,

    #[error("No route to peer: {}", bytes_to_hex(&[0]))]
    NoRouteToPeer([u8; ED25519_PUBLICKEYBYTES]),
}

struct TcpConnection {
    stream: Arc<Mutex<OwnedWriteHalf>>,
    last_activity: AtomicU64,
}

impl TcpConnection {
    fn set_last_activity(&self, time: u64) {
        self.last_activity.store(time, SeqCst);
    }

    fn is_inactive(&self, time: u64, hello_timeout: u64) -> bool {
        time - self.last_activity.load(SeqCst) > hello_timeout
    }
}

#[derive(Builder)]
pub struct SuperPeerOpts {
    pub id: Identity,
    #[builder(default = "NETWORK_ID_DEFAULT.to_be_bytes()")]
    pub network_id: [u8; 4],
    #[builder(default = "Some(UDP4_LISTEN_DEFAULT)")]
    pub udp4_listen: Option<SocketAddrV4>,
    #[builder(default = "Some(UDP6_LISTEN_DEFAULT)")]
    pub udp6_listen: Option<SocketAddrV6>,
    #[builder(default = "Some(TCP4_LISTEN_DEFAULT)")]
    pub tcp4_listen: Option<SocketAddrV4>,
    #[builder(default = "Some(TCP6_LISTEN_DEFAULT)")]
    pub tcp6_listen: Option<SocketAddrV6>,
    #[builder(default = "ARM_MESSAGES_DEFAULT")]
    pub arm_messages: bool,
    #[builder(default = "SEND_UNITS_DEFAULT")]
    pub send_unites: i32,
    #[builder(default = "MAX_PEERS_DEFAULT")]
    pub max_peers: u64,
    #[builder(default = "MIN_POW_DIFFICULTY_DEFAULT")]
    pub min_pow_difficulty: u8,
    #[builder(default = "HELLO_TIMEOUT_DEFAULT")]
    pub hello_timeout: u64,
    #[builder(default = "HELLO_MAX_AGE_DEFAULT")]
    pub hello_max_age: u64,
    #[builder(default = "MTU_DEFAULT")]
    pub mtu: usize,
    #[builder(default = "HOUSEKEEPING_DELAY_DEFAULT")]
    pub housekeeping_delay: u64,
}

pub struct SuperPeerInner {
    pub(in crate::super_peer) opts: SuperPeerOpts,
    coarse_timer: AtomicU64,
    peers_list: PeersList,
    udp4_socket: Option<UdpSocket>,
    udp6_socket: Option<UdpSocket>,
    tcp4_listener: Option<TcpListener>,
    tcp6_listener: Option<TcpListener>,
    tcp_connections: HashMap<SocketAddr, TcpConnection>,
    pub(in crate::super_peer) agreement_sk: Option<[u8; CURVE25519_SECRETKEYBYTES]>,
    pub(in crate::super_peer) agreement_pk: Option<[u8; CURVE25519_PUBLICKEYBYTES]>,
}

impl SuperPeerInner {
    pub fn new(
        opts: SuperPeerOpts,
        udp4_socket: Option<UdpSocket>,
        udp6_socket: Option<UdpSocket>,
        tcp4_listener: Option<TcpListener>,
        tcp6_listener: Option<TcpListener>,
        agreement_sk: Option<[u8; CURVE25519_SECRETKEYBYTES]>,
        agreement_pk: Option<[u8; CURVE25519_PUBLICKEYBYTES]>,
    ) -> Self {
        let peers_list = PeersList::new(opts.max_peers);
        Self {
            opts,
            coarse_timer: AtomicU64::new(Self::clock()),
            peers_list,
            udp4_socket,
            udp6_socket,
            tcp4_listener,
            tcp6_listener,
            tcp_connections: HashMap::new(),
            agreement_sk,
            agreement_pk,
        }
    }

    pub async fn on_udp_datagram(
        &self,
        src: SocketAddr,
        buf: &mut [u8],
        response_buf: &mut [u8],
    ) -> Result<(), SuperPeerError> {
        self.on_packet(src, UDP, buf, response_buf).await
    }

    pub async fn on_tcp_segment(
        &self,
        src: SocketAddr,
        buf: &mut [u8],
        response_buf: &mut [u8],
    ) -> Result<(), SuperPeerError> {
        self.on_packet(src, TCP, buf, response_buf).await
    }

    pub(in crate::super_peer) async fn on_packet(
        &self,
        src: SocketAddr,
        prot: TransportProt,
        buf: &mut [u8],
        response_buf: &mut [u8],
    ) -> Result<(), SuperPeerError> {
        trace!("Got packet from src {}://{}", prot, src);

        // public header
        let (public_header, private_header_and_body_slice) = PublicHeader::parse(buf)?;
        trace!("{}", public_header);

        // network id
        if public_header.network_id != self.opts.network_id {
            return Err(SuperPeerError::NetworkIdInvalid(public_header.network_id));
        }

        // recipient
        if public_header.recipient == self.opts.id.pk {
            let private_header_len = if public_header.is_armed() {
                if !self.opts.arm_messages {
                    return Err(SuperPeerError::MessageArmed);
                }
                PRIVATE_HEADER_ARMED_LEN
            } else {
                if self.opts.arm_messages {
                    return Err(SuperPeerError::MessageUnarmed);
                }
                PRIVATE_HEADER_UNARMED_LEN
            };

            if private_header_and_body_slice.len() < private_header_len {
                return Err(SuperPeerError::PrivateHeaderInvalid);
            }

            // the guard makes it necessary to but the following in a separate scope
            let ack_len = {
                let guard = self.peers_list.peers_guard();
                let peer = self.peers_list.get_or_insert_peer(
                    &public_header.sender,
                    &public_header.pow,
                    self,
                    &guard,
                )?;

                // pow
                if peer.has_invalid_pow() {
                    return Err(SuperPeerError::PowInvalid);
                }

                // private header
                let (private_header, body_slice) = PrivateHeader::parse(
                    private_header_and_body_slice,
                    public_header,
                    peer.rx_key(),
                )?;
                trace!("{}", private_header);

                // only HELLO is allowed
                if private_header.message_type != MessageType::HELLO.into() {
                    return Err(SuperPeerError::MessageTypeUnexpected(
                        private_header.message_type.try_into()?,
                    ));
                }

                // HELLO body
                let hello = HelloMessageSigned::parse(
                    body_slice,
                    public_header,
                    private_header,
                    peer.rx_key(),
                )?;

                // process HELLO
                trace!("{}", hello);

                // time
                let time = self.current_time();

                let hello_time = hello.time.get();
                let time_diff = if time > hello_time {
                    time - hello_time
                } else {
                    hello_time - time
                };
                if time_diff > self.opts.hello_max_age {
                    return Err(SuperPeerError::HelloTimeInvalid(time_diff));
                }

                // update peer information
                peer.hello_tx(time, src, prot, &hello.endpoints);

                // reply with ACK

                AckMessage::build(
                    response_buf,
                    &self.opts.network_id,
                    &self.opts.id.pk,
                    &self.opts.id.pow,
                    peer.tx_key(),
                    &public_header.sender,
                    hello_time,
                )?
            };

            self.send(public_header.sender, prot, src, &response_buf[..ack_len])
                .await?;

            Ok(())
        } else {
            // try forwarding
            trace!("Not for us, try forwarding.");

            // sender wants to forward to themselves :)
            if public_header.recipient == public_header.sender {
                return Err(SuperPeerError::LoopbackForwarding);
            }

            // verify if hop count is exceeded
            if public_header.hop_count() > MAX_HOP_COUNT {
                if log_enabled!(Level::Debug) {
                    debug!(
                        "Forwarding failed as hop count limit exceeded from peer {} to {}.",
                        bytes_to_hex(&public_header.sender),
                        bytes_to_hex(&public_header.recipient)
                    );
                }
                return Ok(());
            }

            let sender_key = public_header.sender;
            let recipient_key = public_header.recipient;

            // the guard makes it necessary to but the following in a separate scope
            let result = {
                // search recipient
                let guard = self.peers_list.peers_guard();
                if let Some(recipient) = self.peers_list.get_peer(&recipient_key, &guard) {
                    public_header.increment_hop_count();

                    // forward message
                    if let Some((prot, addr)) = recipient.endpoint() {
                        Some((recipient_key, prot, addr, buf))
                    } else {
                        None
                    }
                } else {
                    trace!("Recipient unknown. Discard packet.");
                    None
                }
            };

            if let Some((recipient_key, prot, dst, buf)) = result {
                self.send(recipient_key, prot, dst, buf).await?;

                if log_enabled!(Level::Debug) {
                    debug!(
                        "Forwarded message from {} to {}",
                        bytes_to_hex(&sender_key),
                        bytes_to_hex(&recipient_key)
                    );
                }

                return self.try_unite(&sender_key, &recipient_key).await;
            }

            Ok(())
        }
    }

    async fn try_unite(
        &self,
        sender_key: &[u8; ED25519_PUBLICKEYBYTES],
        recipient_key: &[u8; ED25519_PUBLICKEYBYTES],
    ) -> Result<(), SuperPeerError> {
        let time = self.cached_time();

        // check if we want (and can) help both peers to communicate directly
        if !self
            .peers_list
            .send_unites(sender_key, recipient_key, time, self.opts.send_unites)
        {
            return Ok(());
        }

        // the guard makes it necessary to but the following in a separate scope
        let (sender_send, recipient_send) = {
            // check if sender is known
            let guard = self.peers_list.peers_guard();
            if let (Some(sender), Some(recipient)) = (
                self.peers_list.get_peer(sender_key, &guard),
                self.peers_list.get_peer(recipient_key, &guard),
            ) {
                if let (Some((sender_prot, sender_addr)), Some((recipient_prot, recipient_addr))) =
                    (sender.endpoint(), recipient.endpoint())
                {
                    // send sender all information we have to reach recipient
                    let recipient_candidates: &[u8] = &recipient.contact_candidates();
                    let sender_unite = UniteMessage::build(
                        &self.opts.network_id,
                        &self.opts.id.pk,
                        &self.opts.id.pow,
                        sender.tx_key(),
                        sender_key,
                        recipient_key,
                        recipient_candidates,
                    )?;

                    // send recipient all information we have to reach sender
                    let sender_candidates: &[u8] = &sender.contact_candidates();
                    let recipient_unite = UniteMessage::build(
                        &self.opts.network_id,
                        &self.opts.id.pk,
                        &self.opts.id.pow,
                        recipient.tx_key(),
                        recipient_key,
                        sender_key,
                        sender_candidates,
                    )?;

                    let sender_send = (sender_prot, sender_addr, sender_unite);
                    let recipient_send = (recipient_prot, recipient_addr, recipient_unite);

                    (Some(sender_send), Some(recipient_send))
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            }
        };

        if let (Some(sender_send), Some(recipient_send)) = (sender_send, recipient_send) {
            self.send(*sender_key, sender_send.0, sender_send.1, &sender_send.2)
                .await?;
            self.send(
                *recipient_key,
                recipient_send.0,
                recipient_send.1,
                &recipient_send.2,
            )
            .await?;

            if log_enabled!(Level::Debug) {
                debug!(
                    "United {} and {}",
                    bytes_to_hex(sender_key),
                    bytes_to_hex(recipient_key)
                );
            }
        }

        Ok(())
    }

    async fn send(
        &self,
        recipient_key: [u8; ED25519_PUBLICKEYBYTES],
        prot: TransportProt,
        dst: SocketAddr,
        buf: &[u8],
    ) -> Result<(), SuperPeerError> {
        match (prot, dst) {
            (UDP, SocketAddr::V4(dst)) => self.send_udp4(recipient_key, buf, &dst).await,
            (UDP, SocketAddr::V6(dst)) => self.send_udp6(recipient_key, buf, &dst).await,
            (TCP, dst) => self.send_tcp(recipient_key, buf, &dst).await,
        }
    }

    async fn send_udp4(
        &self,
        recipient_key: [u8; ED25519_PUBLICKEYBYTES],
        buf: &[u8],
        dst: &SocketAddrV4,
    ) -> Result<(), SuperPeerError> {
        if let Some(udp4_socket) = &self.udp4_socket {
            udp4_socket
                .send_to(buf, dst)
                .await
                .map_err(SuperPeerError::SendFailed)?;
            if log_enabled!(Level::Trace) {
                trace!(
                    "Sent to peer {} to dst udp://{}.",
                    bytes_to_hex(&recipient_key),
                    dst
                );
            }
        }

        Ok(())
    }

    async fn send_udp6(
        &self,
        recipient_key: [u8; ED25519_PUBLICKEYBYTES],
        buf: &[u8],
        dst: &SocketAddrV6,
    ) -> Result<(), SuperPeerError> {
        if let Some(udp6_socket) = &self.udp6_socket {
            udp6_socket
                .send_to(buf, dst)
                .await
                .map_err(SuperPeerError::SendFailed)?;
            if log_enabled!(Level::Trace) {
                trace!(
                    "Sent to peer {} to dst udp://{}.",
                    bytes_to_hex(&recipient_key),
                    dst
                );
            }
        }

        Ok(())
    }

    async fn send_tcp(
        &self,
        recipient_key: [u8; ED25519_PUBLICKEYBYTES],
        buf: &[u8],
        dst: &SocketAddr,
    ) -> Result<(), SuperPeerError> {
        if let Some(tcp_connection) = self.tcp_connections.pin_owned().get(dst) {
            tcp_connection
                .stream
                .lock()
                .await
                .write_all(buf)
                .await
                .map_err(SuperPeerError::SendFailed)?;
            tcp_connection.set_last_activity(self.cached_time());
            if log_enabled!(Level::Trace) {
                trace!(
                    "Sent to peer {} to dst tcp://{}.",
                    bytes_to_hex(&recipient_key),
                    dst
                );
            }
        }

        Ok(())
    }

    async fn housekeeping(&self) -> Result<(), SuperPeerError> {
        self.peers_list.housekeeping(self);

        self.close_inactive_tcp_connections().await;

        info!("\n{}", self.peers_list);

        Ok(())
    }

    async fn close_inactive_tcp_connections(&self) {
        let time = self.current_time();

        let guard = self.tcp_connections.owned_guard();
        for (key, connection) in self.tcp_connections.iter(&guard) {
            if connection.is_inactive(time, self.opts.hello_timeout) {
                if let Some(connection) = self.tcp_connections.remove(key, &guard) {
                    if let Err(e) = connection.stream.lock().await.shutdown().await {
                        error!("Error shutting down connection: {}", e);
                    }
                }
            }
        }
    }

    pub fn cached_time(&self) -> u64 {
        self.coarse_timer.load(SeqCst)
    }

    fn current_time(&self) -> u64 {
        self.coarse_timer.store(Self::clock(), SeqCst);
        self.cached_time()
    }

    pub(in crate::super_peer) fn clock() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }
}

pub struct SuperPeer {}

impl SuperPeer {
    pub async fn bind(opts: SuperPeerOpts) -> Result<(), SuperPeerError> {
        if opts.udp4_listen.is_none()
            && opts.udp6_listen.is_none()
            && opts.tcp4_listen.is_none()
            && opts.tcp6_listen.is_none()
        {
            return Err(SuperPeerError::NeitherUdpNorTcpServers);
        }

        // generate agreement keys
        let (agreement_sk, agreement_pk) = if opts.arm_messages {
            (
                Some(convert_ed25519_sk_to_curve25519_sk(&opts.id.sk)?),
                Some(convert_ed25519_pk_to_curve22519_pk(&opts.id.pk)?),
            )
        } else {
            (None, None)
        };

        // start udp4 server
        let udp4_socket = if let Some(udp4_listen) = opts.udp4_listen {
            let udp4_socket = UdpSocket::bind(udp4_listen)
                .await
                .map_err(SuperPeerError::Udp4BindError)?;
            info!("Bound UDP4 server to {}", udp4_socket.local_addr()?);
            Some(udp4_socket)
        } else {
            None
        };

        // start udp6 server
        let udp6_socket = if let Some(udp6_listen) = opts.udp6_listen {
            let udp6_socket = UdpSocket::bind(udp6_listen)
                .await
                .map_err(SuperPeerError::Udp6BindError)?;
            info!("Bound UDP6 server to {}", udp6_socket.local_addr()?);
            Some(udp6_socket)
        } else {
            None
        };

        // start tcp4 server
        let tcp4_listener = if let Some(tcp4_listen) = opts.tcp4_listen {
            let tcp4_listener = TcpListener::bind(tcp4_listen)
                .await
                .map_err(SuperPeerError::Tcp4BindError)?;
            info!("Bound TCP4 server to {}", tcp4_listener.local_addr()?);
            Some(tcp4_listener)
        } else {
            None
        };

        // start tcp6 server
        let tcp6_listener = if let Some(tcp6_listen) = opts.tcp6_listen {
            let tcp6_listener = TcpListener::bind(tcp6_listen)
                .await
                .map_err(SuperPeerError::Tcp6BindError)?;
            info!("Bound TCP6 server to {}", tcp6_listener.local_addr()?);
            Some(tcp6_listener)
        } else {
            None
        };

        let inner = Arc::new(SuperPeerInner::new(
            opts,
            udp4_socket,
            udp6_socket,
            tcp4_listener,
            tcp6_listener,
            agreement_sk,
            agreement_pk,
        ));

        let mut tasks: FuturesUnordered<JoinHandle<Result<(), JoinError>>> =
            FuturesUnordered::<JoinHandle<Result<(), JoinError>>>::new();

        // housekeeping task
        let housekeeping_inner = inner.clone();
        tasks.push(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(
                housekeeping_inner.opts.housekeeping_delay,
            ));

            loop {
                interval.tick().await;
                if let Err(e) = housekeeping_inner.housekeeping().await {
                    error!("Error in housekeeping: {}", e);
                }
            }
        }));

        // udp4 server
        let udp4_inner = inner.clone();
        tasks.push(tokio::spawn(async move {
            if let Some(udp4_socket) = &udp4_inner.udp4_socket {
                let mut buf = vec![0u8; udp4_inner.opts.mtu];
                let mut response_buf = vec![0u8; udp4_inner.opts.mtu];
                loop {
                    // read datagram
                    let (size, src) = match udp4_socket.recv_from(&mut buf).await {
                        Ok(result) => result,
                        Err(e) => {
                            error!("Error receiving datagram: {}", e);
                            continue;
                        }
                    };

                    // process datagram
                    if let Err(e) = udp4_inner
                        .on_udp_datagram(src, &mut buf[..size], &mut response_buf)
                        .await
                    {
                        error!("Error processing packet: {}", e);
                        continue;
                    }
                }
            }
            Ok(())
        }));

        // udp6 server
        let udp6_inner = inner.clone();
        tasks.push(tokio::spawn(async move {
            if let Some(udp6_socket) = &udp6_inner.udp6_socket {
                let mut buf = vec![0u8; udp6_inner.opts.mtu];
                let mut response_buf = vec![0u8; udp6_inner.opts.mtu];
                loop {
                    // read datagram
                    let (size, src) = match udp6_socket.recv_from(&mut buf).await {
                        Ok(result) => result,
                        Err(e) => {
                            error!("Error receiving datagram: {}", e);
                            continue;
                        }
                    };

                    // process datagram
                    if let Err(e) = udp6_inner
                        .on_udp_datagram(src, &mut buf[..size], &mut response_buf)
                        .await
                    {
                        error!("Error processing packet: {}", e);
                        continue;
                    }
                }
            }
            Ok(())
        }));

        // tcp4 server
        let tcp4_inner = inner.clone();
        tasks.push(tokio::spawn(async move {
            if let Some(tcp4_listener) = &tcp4_inner.tcp4_listener {
                loop {
                    while let Ok((stream, src)) = tcp4_listener.accept().await {
                        if let Err(e) = Self::handle_tcp_stream(&tcp4_inner, stream, src).await {
                            error!("Failed to handle TCP stream: {}", e);
                        }
                    }
                }
            }
            Ok(())
        }));

        // tcp6 server
        let tcp6_inner = inner.clone();
        tasks.push(tokio::spawn(async move {
            if let Some(tcp6_listener) = &inner.tcp6_listener {
                loop {
                    while let Ok((stream, src)) = tcp6_listener.accept().await {
                        if let Err(e) = Self::handle_tcp_stream(&tcp6_inner, stream, src).await {
                            error!("Failed to handle TCP stream: {}", e);
                        }
                    }
                }
            }
            Ok(())
        }));

        while let Some(result) = tasks.next().await {
            let _ = result.map_err(SuperPeerError::TaskError)?;
        }

        Ok(())
    }

    async fn handle_tcp_stream(
        inner: &Arc<SuperPeerInner>,
        stream: TcpStream,
        src: SocketAddr,
    ) -> Result<(), SuperPeerError> {
        trace!("New TCP connection from {}", src);
        let (mut read_half, mut write_half) = stream.into_split();

        // Check if we already have N active connections
        if inner.tcp_connections.len() >= inner.opts.max_peers as usize {
            // Too many connections - reject this one
            if let Err(e) = write_half.shutdown().await {
                error!("Error shutting down connection: {}", e);
            }
        }

        let write_half = Arc::new(Mutex::new(write_half));
        let reader_write_half = write_half.clone();

        let _ = inner.tcp_connections.pin().insert(
            src,
            TcpConnection {
                stream: write_half,
                last_activity: AtomicU64::new(inner.cached_time()),
            },
        );

        let tcp_inner = inner.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; tcp_inner.opts.mtu];
            let mut response_buf = vec![0u8; tcp_inner.opts.mtu];
            loop {
                // read segment
                let size = match read_half.read(&mut buf).await {
                    Ok(0) => {
                        trace!("TCP connection closed by peer {}", src);
                        tcp_inner.tcp_connections.pin().remove(&src);
                        break;
                    }
                    Ok(result) => result,
                    Err(e) => {
                        error!("Error receiving segment: {}", e);
                        tcp_inner.tcp_connections.pin().remove(&src);
                        break;
                    }
                };

                // process segment
                if let Err(e) = tcp_inner
                    .on_tcp_segment(src, &mut buf[..size], &mut response_buf)
                    .await
                {
                    match e {
                        SuperPeerError::MessageError(MessageError::MagicNumberInvalid(_))
                        | SuperPeerError::MessageError(
                            MessageError::PublicHeaderConversionFailed(_),
                        ) => {
                            let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                            if let Err(e) = reader_write_half
                                .lock()
                                .await
                                .write_all(response.as_bytes())
                                .await
                            {
                                error!("Error sending HTTP response: {}", e);
                            } else if log_enabled!(Level::Trace) {
                                trace!("Sent HTTP response.");
                            }
                        }
                        _ => error!("Error processing packet: {}", e),
                    }
                    if let Err(e) = reader_write_half.lock().await.shutdown().await {
                        error!("Error shutting down connection: {}", e);
                    }
                    break;
                }

                // Update activity time after successful read
                if let Some(connection) = tcp_inner.tcp_connections.pin().get(&src) {
                    connection.set_last_activity(tcp_inner.cached_time());
                }
            }
        });

        Ok(())
    }
}
