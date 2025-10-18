use crate::agent::netif::AgentNetifInterface;
use crate::agent::{AgentConfig, AgentInner, ChannelSink, Error, is_netsody_control_packet};
use etherparse::{Icmpv4Type, Ipv4HeaderSlice, PacketBuilder};
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

    pub(crate) async fn node_runner(inner: Arc<AgentInner>, node_shutdown: CancellationToken) {
        let recv_buf_rx = inner.recv_buf_rx.clone();
        let netsody_rx = inner.netsody_rx.clone();

        // options
        let c2d_threads = util::get_env("C2D_THREADS", 3);
        let tun_threads = util::get_env("TUN_THREADS", 3);

        let mut join_set = JoinSet::new();

        // monitor node still running
        let token_clone = inner.cancellation_token.clone();
        let node_clone = inner.node.clone();
        join_set.spawn(async move {
            tokio::select! {
                biased;
                _ = token_clone.cancelled() => {
                    trace!("Node token cancelled.");
                },
                _ = node_clone.cancelled() => {
                    trace!("Node has cancelled prematurely.");
                },
            }
        });

        // Netsody -> tun packet processing
        #[allow(unused_variables)]
        for i in 0..tun_threads {
            // Netsody -> tun
            let recv_buf_rx = recv_buf_rx.clone();
            let token_clone = node_shutdown.clone();
            let inner_clone = inner.clone();
            let token_clone2 = node_shutdown.clone();
            join_set.spawn(async move {
                tokio::select! {
                    biased;
                    _ = token_clone.cancelled() => {
                        trace!("Token cancelled. Exiting Netsody -> tun packet processing task ({}/{}).", i + 1, tun_threads);
                    }
                    result = async move {
                        trace!("Netsody -> tun packet processing task started ({}/{}).", i + 1, tun_threads);
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

                                            // Check for packets that exceed MTU with Don't Fragment flag set
                                            // Don't Fragment flag is bit 1 in the flags field (0x4000 in the fragment_offset field)
                                            let mtu = inner_clone.mtu as usize;
                                            if buf.len() > mtu && ip_hdr.dont_fragment() {
                                                trace!(
                                                    peer=?sender_key,
                                                    src=?ip_hdr.source_addr(),
                                                    dst=?ip_hdr.destination_addr(),
                                                    packet_size=?buf.len(),
                                                    mtu=?mtu,
                                                    "Packet size {} bytes exceeds MTU {} bytes with Don't Fragment flag set, sending ICMP Fragmentation Needed",
                                                    buf.len(),
                                                    mtu
                                                );

                                                // Create and send ICMP Fragmentation Needed response
                                                let icmp_response = create_icmp_fragmentation_needed(&buf, &ip_hdr, inner_clone.mtu);

                                                // Send ICMP response back through Netsody
                                                if let Ok(send_handle) = inner_clone.node.send_handle(&sender_key) {
                                                    if let Err(e) = send_handle.send(&icmp_response).await {
                                                        warn!(
                                                            peer=?sender_key,
                                                            error=?e,
                                                            "Failed to send ICMP Fragmentation Needed response to peer: {}", e
                                                        );
                                                    } else {
                                                        trace!(
                                                            peer=?sender_key,
                                                            "Successfully sent ICMP Fragmentation Needed response to peer"
                                                        );
                                                    }
                                                }

                                                // Drop the original packet
                                                continue;
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
                                                    else if let Err(e) = inner_clone.netif.send(&buf).await {
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
                                    error!("Failed to receive packet from Netsody. Cancel token: {}", e);
                                    token_clone2.cancel();
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
            let token_close2 = node_shutdown.clone();
            join_set.spawn(async move {
                tokio::select! {
                    biased;
                    _ = token_close.cancelled() => {
                        trace!("Token cancelled. Exiting channel -> Netsody processing task ({}/{}).", i + 1, c2d_threads);
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
                                    error!("Failed to receive packet from channel. Cancel token: {}", e);
                                    token_close2.cancel();
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
                error!("Task failed. Cancel token: {}", e);
                node_shutdown.clone().cancel();
            } else if !node_shutdown.is_cancelled() {
                trace!("Task prematurely finished. Cancel token.");
                node_shutdown.cancel();
            }
        }

        trace!("Node runner done.");
    }
}

/// Create an ICMP "Fragmentation Needed" response (Type 3, Code 4)
///
/// # Arguments
/// * `original_packet` - The original packet that exceeded MTU
/// * `ip_hdr` - Parsed IPv4 header from the original packet
/// * `mtu` - The MTU value to include in the ICMP response
///
/// # Returns
/// ICMP packet with swapped source/destination and original IP header + 8 bytes of payload (RFC 792)
fn create_icmp_fragmentation_needed(
    original_packet: &[u8],
    ip_hdr: &Ipv4HeaderSlice,
    mtu: u16,
) -> Vec<u8> {
    // Include original IP header + first 8 bytes of payload (RFC 792)
    let data_len = (ip_hdr.slice().len() + 8).min(original_packet.len());
    let icmp_data = &original_packet[..data_len];

    // Build packet with swapped source/destination addresses
    let builder = PacketBuilder::ipv4(
        ip_hdr.destination_addr().octets(), // source (swapped)
        ip_hdr.source_addr().octets(),      // destination (swapped)
        64,                                 // TTL
    )
    .icmpv4(Icmpv4Type::DestinationUnreachable(
        etherparse::icmpv4::DestUnreachableHeader::FragmentationNeeded { next_hop_mtu: mtu },
    ));

    // Write to buffer (never fails for Vec<u8>)
    let mut buf = Vec::with_capacity(data_len + 40); // IP header (20) + ICMP header (8) + data
    builder.write(&mut buf, icmp_data).unwrap();

    buf
}
