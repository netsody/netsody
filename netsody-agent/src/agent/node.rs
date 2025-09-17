use crate::agent::{AgentConfig, AgentInner, ChannelSink, Error, is_netsody_control_packet};
use etherparse::Ipv4HeaderSlice;
use flume::Receiver;
use ipnet::IpNet;
use p2p::identity::PubKey;
use p2p::node::{Node, NodeOptsBuilder, SUPER_PEERS_DEFAULT};
use p2p::util;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{Level, enabled, error, trace, warn};

impl AgentInner {
    pub(crate) async fn bind_node(
        config: &AgentConfig,
    ) -> Result<(Arc<Node>, Arc<Receiver<(PubKey, Vec<u8>)>>), Error> {
        // options
        let super_peers = config
            .super_peers
            .clone()
            .unwrap_or(SUPER_PEERS_DEFAULT.clone()); /*SuperPeerUrl::parse_list(&util::get_env(
        "SUPER_PEERS",
        SUPER_PEERS_DEFAULT
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" "),
        ))
        .expect("Invalid super peer urls");*/
        let min_pow_difficulty = util::get_env("MIN_POW_DIFFICULTY", 24);
        let arm_messages = util::get_env("ARM_MESSAGES", true);
        let udp_addrs = util::get_env("UDP_ADDRS", String::new());
        let udp_port = util::get_env("UDP_PORT", String::new());
        let max_peers = util::get_env("MAX_PEERS", 8192); // set to 0 removes peers limit
        let hello_timeout = util::get_env("HELLO_TIMEOUT", 30 * 1000); // milliseconds
        let hello_max_age = util::get_env("HELLO_MAX_AGE", 60_000); // milliseconds
        let recv_buf_cap = util::get_env("RECV_BUF_CAP", 512); // messages
        let process_unites = util::get_env("PROCESS_UNITES", true);
        let housekeeping_interval = util::get_env("HOUSEKEEPING_INTERVAL", 5 * 1000); // milliseconds
        let enforce_tcp = util::get_env("ENFORCE_TCP", false);
        let udp_sockets = if !cfg!(target_os = "windows") {
            util::get_env("UDP_SOCKETS", 3)
        } else {
            // only one udp socket is allowed on Windows
            1
        };

        // build node
        let (recv_buf_tx, recv_buf_rx) = flume::bounded::<(PubKey, Vec<u8>)>(recv_buf_cap);
        let mut builder = NodeOptsBuilder::default();
        builder
            .id(config.id.clone())
            .arm_messages(arm_messages)
            .udp_addrs(
                udp_addrs
                    .split_whitespace()
                    .map(str::parse::<IpAddr>)
                    .collect::<Result<Vec<_>, _>>()
                    .expect("Invalid udp addresses"),
            )
            .udp_port(if udp_port.trim().is_empty() {
                None
            } else {
                udp_port.parse::<u16>().ok()
            })
            .max_peers(max_peers)
            .min_pow_difficulty(min_pow_difficulty)
            .hello_timeout(hello_timeout)
            .hello_max_age(hello_max_age)
            .super_peers(super_peers)
            .process_unites(process_unites)
            .housekeeping_interval(housekeeping_interval)
            .udp_sockets(udp_sockets)
            .message_sink(Arc::new(ChannelSink(recv_buf_tx)))
            .enforce_tcp(enforce_tcp);
        #[cfg(feature = "prometheus")]
        builder
            .prometheus_url(
                config
                    .prometheus
                    .as_ref()
                    .map(|prometheus| prometheus.url.clone()),
            )
            .prometheus_user(
                config
                    .prometheus
                    .as_ref()
                    .map(|prometheus| prometheus.user.clone()),
            )
            .prometheus_pass(
                config
                    .prometheus
                    .as_ref()
                    .map(|prometheus| prometheus.pass.clone()),
            );
        let opts = builder.build().expect("Failed to build node opts");

        // bind node
        let node = Arc::new(Node::bind(opts).await.expect("Failed to bind node"));

        Ok((node, Arc::new(recv_buf_rx)))
    }

    pub(crate) async fn node_runner(
        inner: Arc<AgentInner>,
        node_shutdown: CancellationToken,
    ) -> Result<(), String> {
        let recv_buf_rx = inner.recv_buf_rx.clone();
        let netsody_rx = inner.netsody_rx.clone();

        // options
        let c2d_threads = util::get_env("C2D_THREADS", 3);
        let tun_threads = util::get_env("TUN_THREADS", 3);

        let mut join_set: JoinSet<Result<(), String>> = JoinSet::new();

        // Netsody <-> tun packet processing
        #[allow(unused_variables)]
        for i in 0..tun_threads {
            // Netsody -> tun
            let recv_buf_rx = recv_buf_rx.clone();
            let token_clone = node_shutdown.clone();
            let inner_clone = inner.clone();
            join_set.spawn(async move {
                tokio::select! {
                    biased;
                    _ = token_clone.cancelled() => {
                        trace!("Token cancelled. Exiting Netsody <-> tun packet processing task ({}/{}).", i + 1, tun_threads);
                        Ok(())
                    }
                    result = async move {
                        trace!("Netsody <-> tun packet processing task started ({}/{}).", i + 1, tun_threads);
                        loop {
                            match recv_buf_rx.recv_async().await {
                                Ok((sender_key, buf)) => {
                                    match Ipv4HeaderSlice::from_slice(&buf) {
                                        Ok(ip_hdr) => {
                                            if enabled!(Level::TRACE) {
                                                trace!(
                                                    peer=?sender_key,
                                                    src=?ip_hdr.source_addr(),
                                                    dst=?ip_hdr.destination_addr(),
                                                    payload_len=?buf.len(),
                                                    "Forwarding packet from Netsody to TUN device: {} -> {} ({} bytes)",
                                                    ip_hdr.source_addr(),
                                                    ip_hdr.destination_addr(),
                                                    buf.len()
                                                );
                                            }

                                            // filter Netsody control plane messages
                                            if is_netsody_control_packet(&buf) {
                                                trace!(
                                                    peer=?sender_key,
                                                    src=?ip_hdr.source_addr(),
                                                    dst=?ip_hdr.destination_addr(),
                                                    "Dropping Netsody control plane packet: {} -> {} (control traffic filtered)",
                                                    ip_hdr.source_addr(),
                                                    ip_hdr.destination_addr()
                                                );
                                                continue;
                                            }

                                            let source = IpNet::from(IpAddr::V4(ip_hdr.source_addr()));
                                            if let Some((_, source_trie)) = inner_clone.trie_rx.load().longest_match(&source) {
                                                let dest = IpNet::from(IpAddr::V4(ip_hdr.destination_addr()));
                                                if let Some((_, expected_key)) = source_trie.longest_match(&dest)
                                                {
                                                    if !sender_key.eq(expected_key) {
                                                        warn!(
                                                            peer=?sender_key,
                                                            expected_peer=?expected_key,
                                                            src=?ip_hdr.source_addr(),
                                                            dst=?ip_hdr.destination_addr(),
                                                            "Security violation: packet source mismatch - received from peer {} with source IP {} but expected peer {} for this route",
                                                            sender_key,
                                                            ip_hdr.source_addr(),
                                                            expected_key
                                                        );
                                                    }
                                                    else if let Err(e) = inner_clone.tun_device.send(&buf).await {
                                                        warn!(
                                                            peer=?sender_key,
                                                            src=?ip_hdr.source_addr(),
                                                            dst=?ip_hdr.destination_addr(),
                                                            error=?e,
                                                            "Failed to forward packet to TUN device: {}", e
                                                        );
                                                    }
                                                    else {
                                                        trace!(
                                                            peer=?sender_key,
                                                            src=?ip_hdr.source_addr(),
                                                            dst=?ip_hdr.destination_addr(),
                                                            "Successfully forwarded packet to TUN device: {} -> {}",
                                                            ip_hdr.source_addr(),
                                                            ip_hdr.destination_addr()
                                                        );
                                                    }
                                                } else {
                                                    warn!(
                                                        peer=?sender_key,
                                                        src=?ip_hdr.source_addr(),
                                                        dst=?ip_hdr.destination_addr(),
                                                        "No inbound route found for destination: {} -> {} (missing destination route in routing table)",
                                                        ip_hdr.source_addr(),
                                                        ip_hdr.destination_addr()
                                                    );
                                                }
                                            }
                                            else {
                                                warn!(
                                                    peer=?sender_key,
                                                    src=?ip_hdr.source_addr(),
                                                    dst=?ip_hdr.destination_addr(),
                                                    "No inbound route found for source: {} -> {} (source IP not in routing table)",
                                                    ip_hdr.source_addr(),
                                                    ip_hdr.destination_addr()
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            error!(
                                                peer=?sender_key,
                                                error=?e,
                                                "Failed to decode IP packet from peer {}: {}",
                                                sender_key,
                                                e
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to receive packet from Netsody: {}", e);
                                    return Err(format!("Failed to receive packet from Netsody: {}", e));
                                }
                            }
                        }
                    } => {
                        result
                    }
                }
            });
        }

        #[allow(unused_variables)]
        for i in 0..c2d_threads {
            // channel -> Netsody processing
            let netsody_rx = netsody_rx.clone();
            let token_close = node_shutdown.clone();
            join_set.spawn(async move {
                tokio::select! {
                    biased;
                    _ = token_close.cancelled() => {
                        trace!("Token cancelled. Exiting channel -> Netsody processing task ({}/{}).", i + 1, c2d_threads);
                        Ok(())
                    }
                    result = async move {
                        trace!("channel -> Netsody processing task started ({}/{}).", i + 1, c2d_threads);
                        loop {
                            match netsody_rx.recv_async().await {
                                Ok((buf, send_handle)) => {
                                    if let Err(e) = send_handle.send(&buf).await {
                                        warn!(
                                            packet_size=?buf.len(),
                                            recipient=?send_handle.recipient,
                                            error=?e,
                                            "Failed to send packet to Netsody network: recipient={}, packet_size={} bytes, error={}",
                                            send_handle.recipient,
                                            buf.len(),
                                            e
                                        );
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to receive packet from channel: {}", e);
                                    return Err(format!("Failed to receive packet from channel: {}", e));
                                }
                            }
                        }
                    } => {
                        result
                    }
                }
            });
        }

        while let Some(result) = join_set.join_next().await {
            if let Err(e) = result {
                return Err(format!("Node task failed: {}", e));
            }
        }

        trace!("Node runner done.");
        Ok(())
    }
}
