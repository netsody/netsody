use crate::crypto::{AgreementPubKey, AgreementSecKey};
use crate::identity::PubKey;
use crate::message::{
    AckMessage, AppMessage, Endpoint, EndpointsList, HELLO_MAX_ENDPOINTS, HelloNodePeerMessage,
    LongHeader, MessageType, SHORT_HEADER_ID_LEN, SHORT_ID_NONE, ShortHeader, ShortId,
    UniteMessage, log_ack_message, log_app_message, log_hello_node_peer_message, log_unite_message,
};
use crate::node::{COMPRESSION, Error, NodeOpts, SendHandlesList, UdpBinding};
use crate::peer::{NodePeer, Peer, PeerPath, PeerPathKey, PeersList, SuperPeer};
use ahash::RandomState;
use arc_swap::{ArcSwap, Guard};
use lz4_flex::decompress_size_prepended;
use papaya::HashMap as PapayaHashMap;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::atomic::{AtomicPtr, AtomicU64};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tracing::{debug, instrument, trace, warn};

#[doc(hidden)]
pub struct NodeInner {
    pub(crate) opts: NodeOpts,
    coarse_timer: AtomicU64,
    pub(crate) peers_list: PeersList,
    pub(crate) udp_bindings: ArcSwap<Vec<Arc<UdpBinding>>>,
    pub(crate) agreement_sk: Option<AgreementSecKey>,
    pub(crate) agreement_pk: Option<AgreementPubKey>,
    pub(crate) send_handles: SendHandlesList,
    pub(crate) udp_port: u16,
    pub(crate) cancellation_token: CancellationToken,
}

impl NodeInner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        opts: NodeOpts,
        peers: PapayaHashMap<PubKey, Peer, RandomState>,
        agreement_sk: Option<AgreementSecKey>,
        agreement_pk: Option<AgreementPubKey>,
        default_route: AtomicPtr<PubKey>,
        udp_bindings: Vec<Arc<UdpBinding>>,
        udp_port: u16,
        cancellation_token: CancellationToken,
    ) -> Self {
        assert!(opts.max_peers.is_power_of_two());

        let peers = PeersList::new(peers, default_route);

        Self {
            opts,
            coarse_timer: AtomicU64::new(Self::clock()),
            peers_list: peers,
            udp_bindings: ArcSwap::new(Arc::new(udp_bindings)),
            agreement_sk,
            agreement_pk,
            send_handles: Default::default(),
            udp_port,
            cancellation_token,
        }
    }

    pub(crate) async fn on_packet(
        &self,
        src: SocketAddr,
        buf: &mut [u8],
        response_buf: &mut [u8],
        udp_binding: Option<Arc<UdpBinding>>,
    ) -> Result<(), Error> {
        {
            // short header shortcut
            let rx_short_ids = self.peers_list.rx_short_ids.pin();
            if let Some(sender) = rx_short_ids.get(&ShortId::try_from(&buf[..SHORT_HEADER_ID_LEN])?)
            {
                if let Some(Peer::NodePeer(node_peer)) = self.peers_list.peers.pin().get(sender) {
                    let payload = ShortHeader::parse(buf, node_peer.rx_key().as_ref())?;

                    #[cfg(feature = "prometheus")]
                    NodeInner::on_app_prometheus(sender, payload.len(), "direct".to_string());

                    // update peer information
                    let time = self.cached_time();
                    node_peer.app_rx(time);

                    return {
                        self.add_to_recv_buf(*sender, payload);
                        Ok(())
                    };
                } else {
                    warn!("Drop package with short header we no longer can match to a peer");
                    return Err(Error::ShortIdOutdated);
                }
            }
        }

        // long header
        let (long_header, body_slice) = LongHeader::parse(buf)?;

        if long_header.network_id != self.opts.network_id {
            return Err(Error::NetworkIdInvalid(long_header.network_id));
        }

        // recipient
        if long_header.recipient == self.opts.id.pk {
            let mut send_queue: Vec<(Vec<u8>, SocketAddr, Arc<UdpSocket>)> = Vec::new();
            {
                let peers = self.peers_list.peers.pin();
                let peer = if let Some(peer) = peers.get(&long_header.sender) {
                    if let Peer::NodePeer(node_peer) = peer {
                        if !node_peer.validate_pow(
                            &long_header.pow,
                            &long_header.sender,
                            self.opts.min_pow_difficulty,
                        )? {
                            return Err(Error::PowInvalid);
                        }
                    }
                    peer
                } else {
                    if peers.len() >= self.opts.max_peers as usize {
                        return Err(Error::PeersListCapacityExceeded(self.opts.max_peers));
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
                        match long_header.message_type {
                            MessageType::ACK => {
                                // process ACK
                                let ack =
                                    AckMessage::parse(body_slice, long_header, rx_key.as_ref())?;
                                self.on_super_peer_ack(
                                    src,
                                    udp_binding,
                                    long_header,
                                    super_peer,
                                    ack,
                                );
                            }
                            MessageType::UNITE => {
                                if self.opts.process_unites {
                                    // process UNITE
                                    let unite = UniteMessage::parse(
                                        body_slice,
                                        long_header,
                                        rx_key.as_ref(),
                                    )?;
                                    self.on_unite(&mut send_queue, long_header, unite)?;
                                } else {
                                    trace!("Ignoring unite message");
                                }
                            }
                            message_type @ (MessageType::APP | MessageType::HELLO) => {
                                return Err(Error::MessageTypeUnexpected(message_type));
                            }
                            _ => return Err(Error::MessageTypeInvalid),
                        }
                    }
                    Peer::NodePeer(node_peer) => {
                        // process packet from node peer
                        let rx_key = node_peer.rx_key();
                        match long_header.message_type {
                            MessageType::ACK => {
                                // process ACK
                                let ack =
                                    AckMessage::parse(body_slice, long_header, rx_key.as_ref())?;
                                self.on_node_peer_ack(
                                    src,
                                    node_peer,
                                    long_header,
                                    ack,
                                    udp_binding.clone().unwrap().socket.clone(),
                                )?;
                            }
                            MessageType::APP => {
                                // process APP
                                let app =
                                    AppMessage::parse(body_slice, long_header, rx_key.as_ref())?;
                                self.on_app(node_peer, long_header, &app);
                            }
                            MessageType::HELLO => {
                                // process HELLO
                                let hello = HelloNodePeerMessage::parse(
                                    body_slice,
                                    long_header,
                                    rx_key.as_ref(),
                                )?;
                                self.on_node_peer_hello(
                                    src,
                                    response_buf,
                                    udp_binding,
                                    long_header,
                                    &mut send_queue,
                                    node_peer,
                                    hello,
                                )?;
                            }
                            MessageType::UNITE => {
                                // node peers not sending UNITEs
                                return Err(Error::MessageTypeUnexpected(MessageType::UNITE));
                            }
                            _ => return Err(Error::MessageTypeInvalid),
                        }
                    }
                }
            }

            // process send queue
            for (msg, dst, udp_socket) in send_queue {
                if let Err(e) = udp_socket.send_to(&msg, dst).await {
                    debug!("Failed to send msg to udp://{dst}: {e}");
                    continue;
                }
                trace!("Sent msg to udp://{dst}.");
            }

            Ok(())
        } else {
            Err(Error::MessageInvalidRecipient)
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[instrument(fields(peer = %long_header.sender, %src), skip_all)]
    fn on_node_peer_hello(
        &self,
        src: SocketAddr,
        response_buf: &mut [u8],
        udp_binding: Option<Arc<UdpBinding>>,
        long_header: &LongHeader,
        send_queue: &mut Vec<(Vec<u8>, SocketAddr, Arc<UdpSocket>)>,
        node_peer: &NodePeer,
        hello: &HelloNodePeerMessage,
    ) -> Result<(), Error> {
        log_hello_node_peer_message(long_header, hello);

        #[cfg(feature = "prometheus")]
        {
            use crate::prometheus::{
                PROMETHEUS_LABEL_HELLO, PROMETHEUS_LABEL_RX, PROMETHEUS_MESSAGES,
            };
            PROMETHEUS_MESSAGES
                .with_label_values(&[
                    PROMETHEUS_LABEL_HELLO,
                    &long_header.sender.to_string(),
                    PROMETHEUS_LABEL_RX,
                ])
                .inc();
        }

        // time
        let time = self.current_time();
        let hello_time = hello.time.into();

        let time_diff = time.saturating_sub(hello_time);
        if time_diff > (self.opts.hello_max_age * 1_000) {
            warn!("Got too old HELLO");
            return Err(Error::HelloTooOld(time_diff));
        }

        // short id
        if hello.short_id != SHORT_ID_NONE {
            node_peer.set_tx_short_id(hello.short_id);
        }

        #[cfg(feature = "prometheus")]
        {
            use crate::prometheus::{
                PROMETHEUS_LABEL_ACK, PROMETHEUS_LABEL_TX, PROMETHEUS_MESSAGES,
            };
            PROMETHEUS_MESSAGES
                .with_label_values(&[
                    PROMETHEUS_LABEL_ACK,
                    &long_header.sender.to_string(),
                    PROMETHEUS_LABEL_TX,
                ])
                .inc();
        }

        // reply with ACK
        trace!("Got HELLO. Reply with ACK");
        let ack_len = AckMessage::build(
            response_buf,
            &self.opts.network_id,
            &self.opts.id.pk,
            &self.opts.id.pow,
            node_peer.tx_key().as_ref(),
            &long_header.sender,
            hello_time,
        )?;

        // queue HELLO and sent it later, otherwise entry lock is held across an async call
        // TODO: avoid to_vec clone!
        send_queue.push((
            response_buf[..ack_len].to_vec(),
            src,
            udp_binding.clone().unwrap().socket.clone(),
        ));

        // HELLO from unknown endpoint? peer might be behind symmetric NAT
        let key = (udp_binding.clone().unwrap().local_addr, src).into();
        let hello_from_unknown_endpoint = !node_peer.paths().contains_key(&key);
        if hello_from_unknown_endpoint {
            let candidate = PeerPath::new();
            candidate.hello_tx(time);
            node_peer.paths().insert(key, candidate);

            #[cfg(feature = "prometheus")]
            {
                use crate::prometheus::{
                    PROMETHEUS_LABEL_HELLO, PROMETHEUS_LABEL_TX, PROMETHEUS_MESSAGES,
                };
                PROMETHEUS_MESSAGES
                    .with_label_values(&[
                        PROMETHEUS_LABEL_HELLO,
                        &long_header.sender.to_string(),
                        PROMETHEUS_LABEL_TX,
                    ])
                    .inc();
            }

            trace!(%src, "Try to reach peer via new endpoint observed from received HELLO");

            let time = self.current_time();
            let hello = HelloNodePeerMessage::build(
                &self.opts.network_id,
                &self.opts.id.pk,
                &self.opts.id.pow,
                node_peer.tx_key().as_ref(),
                &long_header.sender,
                time,
                node_peer.rx_short_id(),
            )?;
            send_queue.push((hello, src, udp_binding.clone().unwrap().socket.clone()));
        }

        Ok(())
    }

    #[instrument(fields(peer = %unite.address), skip_all)]
    fn on_unite(
        &self,
        send_queue: &mut Vec<(Vec<u8>, SocketAddr, Arc<UdpSocket>)>,
        long_header: &LongHeader,
        unite: &UniteMessage,
    ) -> Result<(), Error> {
        log_unite_message(long_header, unite);

        #[cfg(feature = "prometheus")]
        {
            use crate::prometheus::{
                PROMETHEUS_LABEL_RX, PROMETHEUS_LABEL_UNITE, PROMETHEUS_MESSAGES,
            };
            PROMETHEUS_MESSAGES
                .with_label_values(&[
                    PROMETHEUS_LABEL_UNITE,
                    &long_header.sender.to_string(),
                    PROMETHEUS_LABEL_RX,
                ])
                .inc();
        }

        if let Some(Peer::NodePeer(node_peer)) = self.peers_list.peers.pin().get(&unite.address) {
            let unite_endpoints: EndpointsList = unite.endpoints.into();
            let unite_endpoints: HashSet<Endpoint> = unite_endpoints.0;
            let unite_endpoints = unite_endpoints
                .into_iter()
                .map(Endpoint::into)
                .collect::<HashSet<_>>();

            let existing_addrs: HashSet<SocketAddr> = node_peer
                .paths()
                .keys()
                .map(|key| Into::<SocketAddr>::into(*key))
                .collect();
            let new_addrs: HashSet<SocketAddr> = unite_endpoints
                .difference(&existing_addrs)
                .copied()
                .collect();

            for new_addr in &new_addrs {
                for udp_binding in self.udp_bindings().iter() {
                    // skip all endpoints in unite_endpoints whose ip addr is not in the same ip family as socket_ip
                    let local_addr = udp_binding.local_addr;
                    if new_addr.is_ipv4() != local_addr.is_ipv4() {
                        continue;
                    }

                    let new_path_key = PeerPathKey((local_addr, *new_addr));

                    if !node_peer.paths().contains_key(&new_path_key) {
                        #[cfg(feature = "prometheus")]
                        {
                            use crate::prometheus::{
                                PROMETHEUS_LABEL_HELLO, PROMETHEUS_LABEL_TX, PROMETHEUS_MESSAGES,
                            };
                            PROMETHEUS_MESSAGES
                                .with_label_values(&[
                                    PROMETHEUS_LABEL_HELLO,
                                    &unite.address.to_string(),
                                    PROMETHEUS_LABEL_TX,
                                ])
                                .inc();
                        }

                        trace!(
                            "Try to reach peer via new endpoint retrieved from UNITE: {new_addr}"
                        );
                        let path = PeerPath::new();
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
                        send_queue.push((hello, *new_addr, udp_binding.socket.clone()));

                        path.hello_tx(time);

                        node_peer.paths().insert(new_path_key, path);
                    }
                }
            }
        }
        Ok(())
    }

    #[instrument(fields(peer = %long_header.sender), skip_all)]
    fn on_super_peer_ack(
        &self,
        src: SocketAddr,
        udp_binding: Option<Arc<UdpBinding>>,
        long_header: &LongHeader,
        super_peer: &SuperPeer,
        ack: &AckMessage,
    ) {
        log_ack_message(long_header, ack);

        #[cfg(feature = "prometheus")]
        {
            use crate::prometheus::{
                PROMETHEUS_LABEL_ACK, PROMETHEUS_LABEL_RX, PROMETHEUS_MESSAGES,
            };
            PROMETHEUS_MESSAGES
                .with_label_values(&[
                    PROMETHEUS_LABEL_ACK,
                    &long_header.sender.to_string(),
                    PROMETHEUS_LABEL_RX,
                ])
                .inc();
        }

        // update peer information
        let time = self.current_time();
        let ack_time = ack.time.into();
        let local_addr = udp_binding.map(|binding| binding.local_addr);

        super_peer.ack_rx(local_addr, src, time, ack_time, self.opts.enforce_tcp);
    }

    pub fn cached_time(&self) -> u64 {
        self.coarse_timer.load(SeqCst)
    }

    pub(crate) fn current_time(&self) -> u64 {
        self.coarse_timer.store(Self::clock(), SeqCst);
        self.cached_time()
    }

    #[instrument(fields(peer = %long_header.sender, %src), skip_all)]
    fn on_node_peer_ack(
        &self,
        src: SocketAddr,
        node_peer: &NodePeer,
        long_header: &LongHeader,
        ack: &AckMessage,
        udp_socket: Arc<UdpSocket>,
    ) -> Result<(), Error> {
        log_ack_message(long_header, ack);

        #[cfg(feature = "prometheus")]
        {
            use crate::prometheus::{
                PROMETHEUS_LABEL_ACK, PROMETHEUS_LABEL_RX, PROMETHEUS_MESSAGES,
            };
            PROMETHEUS_MESSAGES
                .with_label_values(&[
                    PROMETHEUS_LABEL_ACK,
                    &long_header.sender.to_string(),
                    PROMETHEUS_LABEL_RX,
                ])
                .inc();
        }

        // time
        let time = self.current_time();
        let mut hello_time = ack.time.into();

        if time < hello_time {
            // TODO: This can be removed once we've switched to a monotonically increasing time source.
            hello_time = time;
        }

        let message_age = time - hello_time;
        if message_age > (self.opts.hello_max_age * 1_000) {
            warn!("Got too old ACK");
            return Err(Error::AckTooOld(message_age));
        }

        // update peer information
        node_peer.ack_rx(time, src, hello_time, udp_socket);

        Ok(())
    }

    #[instrument(fields(peer = %long_header.sender), skip_all)]
    fn on_app(&self, node_peer: &NodePeer, long_header: &LongHeader, app: &AppMessage) {
        log_app_message(long_header, app);

        #[cfg(feature = "prometheus")]
        NodeInner::on_app_prometheus(
            &long_header.sender,
            app.payload.len(),
            if long_header.hop_count == 0u8 {
                "direct".to_string()
            } else {
                "relayed".to_string()
            },
        );

        // update peer information
        let time = self.cached_time();
        node_peer.app_rx(time);

        self.add_to_recv_buf(long_header.sender, &app.payload);
    }

    fn add_to_recv_buf(&self, sender: PubKey, payload: &[u8]) {
        debug!("Received APP from {sender}");

        let payload = if COMPRESSION {
            decompress_size_prepended(payload).unwrap()
        } else {
            // TODO: `to_vec` allocates new memory. Using something like an MPSC ring buffer would allow us to reuse the same memory, potentially improving performance.
            payload.to_vec()
        };

        self.opts.message_sink.accept(sender, payload);
    }

    pub(crate) fn udp_bindings(&self) -> Guard<Arc<Vec<Arc<UdpBinding>>>> {
        self.udp_bindings.load()
    }

    fn udp_binding_for(&self, local_addr: &SocketAddr) -> Option<Arc<UdpBinding>> {
        self.udp_bindings()
            .iter()
            .find(|binding| binding.local_addr.eq(local_addr))
            .cloned()
    }

    pub(crate) fn udp_socket_for(&self, local_addr: &SocketAddr) -> Option<Arc<UdpSocket>> {
        self.udp_binding_for(local_addr)
            .map(|binding| binding.socket.clone())
    }

    pub(crate) fn my_endpoint_candidates(&self, my_addrs: &[IpAddr]) -> Result<Vec<u8>, Error> {
        Ok({
            let endpoints = my_addrs
                .iter()
                .take(HELLO_MAX_ENDPOINTS)
                .map(|ip| Endpoint {
                    addr: (*ip).into(),
                    port: self.udp_port.into(),
                })
                .collect::<HashSet<_>>();
            let endpoints: HashSet<Endpoint> = endpoints.into_iter().collect();
            EndpointsList(endpoints).into()
        })
    }

    pub(crate) fn clock() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64
    }
}
