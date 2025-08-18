use crate::crypto::random_bytes;
use crate::identity::PubKey;
use crate::message::{HelloNodePeerMessage, HelloSuperPeerMessage};
use crate::message::{SHORT_HEADER_ID_LEN, SHORT_ID_NONE};
use crate::node::SendHandleState;
use crate::node::UdpBinding;
use crate::node::inner::NodeInner;
use crate::node::{Error, Node};
use crate::peer::{NodePeer, Peer, SuperPeer};
use crate::util::get_addrs;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{error, instrument, trace, trace_span, warn};

pub struct UdpBindingGuard {
    pub(crate) inner: Arc<NodeInner>,
    pub(crate) udp_binding: Arc<UdpBinding>,
}

impl Drop for UdpBindingGuard {
    fn drop(&mut self) {
        trace!(
            "UdpBindingGuard dropped. Mark binding for {} as died",
            self.udp_binding.local_addr
        );
        self.udp_binding.reader_task_died.store(true, SeqCst);
    }
}

pub struct TcpPathGuard {
    pub(crate) inner: Arc<NodeInner>,
    pub(crate) pub_key: PubKey,
}

impl Drop for TcpPathGuard {
    fn drop(&mut self) {
        trace!("TcpPathGuard dropped. Remove TCP path for {}", self.pub_key);
        if let Some(Peer::SuperPeer(super_peer)) =
            self.inner.peers_list.peers.pin().get(&self.pub_key)
        {
            super_peer.reset_tcp_path();
        }
    }
}

impl NodeInner {
    pub(crate) async fn housekeeping_runner(
        inner: Arc<NodeInner>,
        cancellation_token: CancellationToken,
    ) {
        let mut interval =
            tokio::time::interval(Duration::from_millis(inner.opts.housekeeping_interval));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = inner.housekeeping(&inner).await {
                        error!("Error in housekeeping: {e}");
                    }
                }
                _ = cancellation_token.cancelled() => {
                    break;
                }
            }
        }
    }

    #[instrument(skip_all)]
    async fn housekeeping(&self, inner: &Arc<NodeInner>) -> Result<(), Error> {
        self.remove_stale_peers_housekeeping();

        let my_addrs = Node::my_addrs()?;
        let my_addrs: Vec<IpAddr> = my_addrs.into_iter().map(|(_, ip)| ip).collect();

        self.udp_bindings_housekeeping(inner)?;
        self.peers_housekeeping(inner, &my_addrs).await?;
        self.default_route_housekeeping();
        self.send_handles_housekeeping(inner);

        #[cfg(feature = "prometheus")]
        self.housekeeping_prometheus(inner);

        Ok(())
    }

    fn udp_bindings_housekeeping(&self, inner: &Arc<NodeInner>) -> Result<(), Error> {
        // ensure udp sockets are up to date
        // collect addresses we bind to
        if self.opts.udp_addrs.is_empty() {
            let my_addrs = get_addrs().map_err(Error::GetAddrsFailed)?;
            let my_addrs_only: Vec<IpAddr> =
                my_addrs.clone().into_iter().map(|(_, ip)| ip).collect();

            // remove
            let mut new_udp_bindings: Vec<Arc<UdpBinding>> = Vec::new();
            for udp_binding in self.udp_bindings().iter() {
                let ip_addr = udp_binding.local_addr.ip();

                if udp_binding.reader_task_died.load(SeqCst) {
                    trace!(
                        "Reader task has died for binding {}",
                        udp_binding.local_addr
                    );
                    udp_binding.cancel_binding();
                } else if my_addrs_only.contains(&ip_addr) {
                    if udp_binding.cancellation_token.is_cancelled() {
                        error!("binding {:?} has been cancelled?!?!?!", udp_binding);
                        continue;
                    }
                    new_udp_bindings.push(udp_binding.clone());
                } else {
                    trace!(
                        "{ip_addr} does not belong longer to my addresses. Cancel corresponding binding for {0}",
                        udp_binding.local_addr
                    );
                    udp_binding.cancel_binding();
                }
            }

            // add
            for (my_iface, my_addr) in &my_addrs {
                let has_socket = new_udp_bindings
                    .iter()
                    .any(|socket| socket.local_addr.ip() == *my_addr);

                if !has_socket {
                    for i in 0..self.opts.udp_sockets {
                        let addr = SocketAddr::new(*my_addr, self.udp_port);
                        trace!(%addr, "Bind new UDP server");
                        match NodeInner::new_udp_reuseport(addr, my_iface.clone()) {
                            Ok(socket) => {
                                if i == 0 {
                                    trace!(%addr, "Bound UDP server");
                                }
                                let udp_binding = Arc::new(UdpBinding::new(
                                    inner.cancellation_token.child_token(),
                                    socket,
                                ));
                                new_udp_bindings.push(udp_binding.clone());

                                tokio::spawn(NodeInner::udp_reader(UdpBindingGuard {
                                    inner: inner.clone(),
                                    udp_binding: udp_binding.clone(),
                                }));
                            }
                            Err(e) => warn!(%addr, "Failed to bind new UDP server: {e}"),
                        }
                    }
                }
            }

            // update udp sockets
            let udp_bindings = Arc::new(new_udp_bindings);
            self.udp_bindings.store(udp_bindings.clone());

            // add paths
            for (_, peer) in &inner.peers_list.peers.pin_owned() {
                if let Peer::SuperPeer(super_peer) = peer {
                    let resolved_addrs = super_peer.resolved_addrs().clone();
                    SuperPeer::add_paths_for_resolved_addrs(
                        &self.udp_bindings.load(),
                        resolved_addrs.as_deref(),
                        &super_peer.udp_paths,
                    );
                }
            }
        }
        Ok(())
    }

    fn remove_stale_peers_housekeeping(&self) {
        let time = self.current_time();

        // remove stale rx short ids
        // running this first ensures that short IDs remain available until the next housekeeping cycle, even after the peer has been removed from the peers list.
        let guard = self.peers_list.peers.guard();
        self.peers_list.rx_short_ids.pin().retain(|_, peer_key| {
            let valid = self.peers_list.peers.contains_key(peer_key, &guard);
            if !valid {
                trace!(
                    "Remove rx short id from peer {peer_key} that is not longer in my peer list"
                );
            }
            valid
        });

        // remove stale peers
        let peers_guard = self.peers_list.peers.guard();
        self.peers_list.peers.retain(
            |key, peer| match &peer {
                Peer::SuperPeer(_) => true,
                Peer::NodePeer(node_peer) => {
                    let is_new = node_peer.is_new(time, self.opts.hello_timeout);
                    let has_handle = self.send_handles.contains_key(key);
                    let is_active = node_peer.is_reachable(time, self.opts.hello_timeout)
                        && (node_peer.has_app_traffic(time) || self.send_handles.contains_key(key));
                    is_new || is_active || has_handle
                }
            },
            &peers_guard,
        );
    }

    fn default_route_housekeeping(&self) {
        // best super peer
        let mut best_median_lat = u64::MAX;
        let mut best_sp = self.peers_list.default_route_ptr.load(SeqCst) as usize;

        for (peer_key, peer) in &self.peers_list.peers.pin_owned() {
            let span = trace_span!("peer", peer = %peer_key);
            let _guard = span.enter();

            let peer_key_ptr = peer_key as *const PubKey;
            if let Peer::SuperPeer(super_peer) = peer {
                // best super peer?
                if let Some(median_lat) = super_peer.median_lat()
                    && median_lat < best_median_lat
                {
                    best_median_lat = median_lat;
                    best_sp = peer_key_ptr as usize;
                }
            }
        }

        self.peers_list
            .default_route_ptr
            .store(best_sp as *const PubKey as *mut PubKey, SeqCst);
    }

    fn send_handles_housekeeping(&self, inner: &Arc<NodeInner>) {
        // update send handles
        let peers = self.peers_list.peers.pin();

        let default_route = self.peers_list.default_route();
        let Peer::SuperPeer(super_peer) = peers.get(default_route).unwrap() else {
            unreachable!()
        };
        let sp_tcp_stream = super_peer.tcp_connection().as_ref().and_then(|tcp| {
            tcp.stream_store
                .load()
                .as_ref()
                .map(std::clone::Clone::clone)
                .as_ref()
                .cloned()
        });

        self.send_handles.garbage_collect();
        self.send_handles.for_each(|peer_key, handle| {
            let peer = peers.get(&peer_key);

            if let Some(Peer::NodePeer(node_peer)) = peer {
                handle.update_state(node_peer.new_send_handle_state(inner.clone(), super_peer));
            } else {
                handle.update_state(SendHandleState {
                    best_addr: Default::default(),
                    udp_socket: None,
                    app_tx: Default::default(),
                    tx_key: Default::default(),
                    short_id: Default::default(),
                    sp_tcp_stream: sp_tcp_stream.clone(),
                    sp_udp_sockets: SendHandleState::sp_socket(super_peer, &inner.udp_bindings()),
                });
            }
        });
    }

    async fn peers_housekeeping(
        &self,
        inner: &Arc<NodeInner>,
        my_addrs: &[IpAddr],
    ) -> Result<(), Error> {
        // endpoints
        let endpoints: Vec<u8> = self.my_endpoint_candidates(my_addrs)?;
        for (peer_key, peer) in &self.peers_list.peers.pin_owned() {
            let time = self.current_time();
            match peer {
                Peer::SuperPeer(super_peer) => {
                    self.super_peer_housekeeping(inner, &endpoints, *peer_key, super_peer, time)
                        .await?;
                }
                Peer::NodePeer(node_peer) => {
                    self.node_peer_housekeeping(time, *peer_key, node_peer)
                        .await?;
                }
            }
        }
        Ok(())
    }

    #[instrument(fields(peer = %peer_key), skip_all)]
    async fn node_peer_housekeeping(
        &self,
        time: u64,
        peer_key: PubKey,
        node_peer: &NodePeer,
    ) -> Result<(), Error> {
        // ensure peer has unique short id
        if node_peer.rx_short_id() == SHORT_ID_NONE {
            let guard = self.peers_list.rx_short_ids.guard();
            loop {
                let mut short_id = [0u8; SHORT_HEADER_ID_LEN];
                random_bytes(&mut short_id);

                if self
                    .peers_list
                    .rx_short_ids
                    .try_insert(node_peer.rx_short_id(), peer_key, &guard)
                    .is_ok()
                {
                    node_peer.set_rx_short_id(short_id.into());
                    break;
                }
            }
        }

        // check paths up to date
        node_peer.paths.pin().retain(|key, _| {
            let valid = self
                .udp_bindings
                .load()
                .iter()
                .any(|b| b.local_addr.eq(&key.local_addr()));
            if !valid {
                trace!(path = %key, "Remove UDP path without corresponding binding");
            }
            valid
        });

        if node_peer.has_app_traffic(time) {
            trace!("We have app traffic");
            let time = self.current_time();

            // remove stale endpoints
            node_peer.remove_stale_paths(time, self.opts.hello_timeout);

            let tx_key = node_peer.tx_key();
            for (path_key, path) in &node_peer.paths() {
                #[cfg(feature = "prometheus")]
                {
                    use crate::prometheus::{
                        PROMETHEUS_LABEL_HELLO, PROMETHEUS_LABEL_TX, PROMETHEUS_MESSAGES,
                    };
                    PROMETHEUS_MESSAGES
                        .with_label_values(&[
                            PROMETHEUS_LABEL_HELLO,
                            &peer_key.to_string(),
                            PROMETHEUS_LABEL_TX,
                        ])
                        .inc();
                }

                trace!("Contact peer via endpoint to test reachability/maintain link: {path_key}");
                let hello = HelloNodePeerMessage::build(
                    &self.network_id,
                    &self.opts.id.pk,
                    &self.opts.id.pow,
                    tx_key.as_ref(),
                    &peer_key,
                    time,
                    node_peer.rx_short_id(),
                )?;

                let src = path_key.local_addr();
                let dst = path_key.remote_addr();
                path.hello_tx(time);

                match self.udp_socket_for(&src) {
                    Some(udp_socket) => {
                        if let Err(e) = udp_socket.send_to(&hello, dst).await {
                            warn!("Failed to send HELLO to node peer via {}: {}", path_key, e);
                        } else {
                            trace!("Sent HELLO to node peer via {}.", path_key);
                        }
                    }
                    None => {
                        warn!("No udp socket found for path {}", path_key);
                    }
                }
            }
        } else {
            trace!("No app traffic");
            node_peer.clear_paths();
            node_peer.clear_app_tx_rx();
        }

        if !node_peer.is_reachable(time, self.opts.hello_timeout) {
            trace!("Node is not directly reachable.");
            if node_peer.tx_short_id().is_some() {
                node_peer.set_tx_short_id(SHORT_ID_NONE);
            }
        }

        Ok(())
    }

    #[instrument(fields(peer = %peer_key), skip_all)]
    async fn super_peer_housekeeping(
        &self,
        inner: &Arc<NodeInner>,
        endpoints: &[u8],
        peer_key: PubKey,
        super_peer: &SuperPeer,
        time: u64,
    ) -> Result<(), Error> {
        // tcp connection required?
        if super_peer.establish_tcp_connection(time, self.opts.hello_timeout, self.opts.enforce_tcp)
        {
            trace!("Establish TCP connection");

            // get tcp socketaddr
            let tcp_addr = super_peer.tcp_addr();
            let tx_key = super_peer.tx_key();
            let cancellation_token = super_peer.new_tcp_path();

            let guard = TcpPathGuard {
                inner: inner.clone(),
                pub_key: peer_key,
            };
            tokio::spawn(Self::tcp_connector(
                time,
                tcp_addr,
                tx_key,
                cancellation_token,
                guard,
            ));
        } else {
            trace!("No TCP connection establishment condition met (it might exist already)");
        }

        let time = self.current_time();

        // check paths up to date
        super_peer.udp_paths.pin().retain(|key, _| {
            self.udp_bindings
                .load()
                .iter()
                .any(|b| b.local_addr.eq(&key.local_addr()))
        });

        // remove stale endpoints
        super_peer.remove_stale_udp_paths(time, self.opts.hello_timeout);

        match SuperPeer::lookup_host(super_peer.addr()).await {
            Ok(resolved_addrs) => super_peer.update_resolved_addrs(resolved_addrs),
            Err(e) => warn!(
                "Failed to update resolved super peer addresses for super peer {}: {}",
                super_peer.addr(),
                e
            ),
        }

        let resolved_addrs = super_peer.resolved_addrs();
        SuperPeer::add_paths_for_resolved_addrs(
            &self.udp_bindings.load(),
            resolved_addrs.as_deref(),
            &super_peer.udp_paths,
        );

        #[cfg(feature = "prometheus")]
        {
            use crate::prometheus::{
                PROMETHEUS_LABEL_HELLO, PROMETHEUS_LABEL_TX, PROMETHEUS_MESSAGES,
            };
            PROMETHEUS_MESSAGES
                .with_label_values(&[
                    PROMETHEUS_LABEL_HELLO,
                    &peer_key.to_string(),
                    PROMETHEUS_LABEL_TX,
                ])
                .inc();
        }

        // send HELLO
        trace!("Send HELLO to super peer");
        let hello = HelloSuperPeerMessage::build(
            &self.network_id,
            &self.opts.id.pk,
            &self.opts.id.pow,
            super_peer.tx_key().as_ref(),
            &peer_key,
            time,
            endpoints,
        )?;

        trace!("Try to reach super peer via UDP");
        for (path_key, path) in &super_peer.udp_paths.pin_owned() {
            let local_addr = path_key.local_addr();
            let remote_addr = path_key.remote_addr();

            // find proper udp_socket
            trace!(path = %path_key,
                "Send via path",
            );
            match self.udp_socket_for(&local_addr) {
                Some(udp_socket) => {
                    path.hello_tx(time);
                    if let Err(e) = udp_socket.send_to(&hello, remote_addr).await {
                        trace!(path = %path_key,
                            "UDP send error: {e}",
                        );
                    } else {
                        trace!(path = %path_key,
                            "UDP send successful",
                        );
                    }
                }
                None => {
                    warn!(path = %path_key, "No UDP socket found");
                }
            }
        }

        // If there is a TCP connection, send HELLO via TCP as well
        if let Some(stream) = super_peer.tcp_connection().as_ref().and_then(|tcp| {
            tcp.stream_store
                .load()
                .as_ref()
                .map(std::clone::Clone::clone)
                .as_ref()
                .cloned()
        }) {
            trace!("TCP path present. Send HELLO via TCP");
            self.send_super_peer_tcp(&stream, hello, &peer_key).await?;
        } else {
            trace!("No TCP path present. Do not send HELLO via TCP");
        }
        Ok(())
    }
}
