use crate::network::Network;
use crate::network::config::{EffectiveRoutingList, NetworkConfig};
use crate::node::{ChannelSink, Error, SdnNodeConfig};
use arc_swap::ArcSwap;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use drasyl::identity::{Identity, PubKey};
use drasyl::message::LONG_HEADER_MAGIC_NUMBER;
use drasyl::node::{Node, NodeOptsBuilder, SUPER_PEERS_DEFAULT, SendHandle};
use drasyl::peer::SuperPeerUrl;
use drasyl::util;
use drasyl::util::bytes_to_hex;
use etherparse::Ipv4HeaderSlice;
use flume::{Receiver, Sender};
use http::Request;
use http_body_util::{BodyExt, Empty};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use ipnet::IpNet;
use ipnet_trie::IpnetTrie;
use net_route::Handle;
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{Level, enabled, error, trace, warn};
use tun_rs::AsyncDevice as TunDevice;
use url::Url;

type TrieRx = IpnetTrie<IpnetTrie<(PubKey, Arc<TunDevice>)>>;

pub struct SdnNodeInner {
    pub(crate) id: Identity,
    pub(crate) networks: Arc<Mutex<HashMap<Url, Network>>>,
    pub(crate) cancellation_token: CancellationToken,
    pub(crate) node: Arc<Node>,
    recv_buf_rx: Arc<Receiver<(PubKey, Vec<u8>)>>,
    pub(crate) routes_handle: Arc<Handle>,
    pub(crate) trie_rx: ArcSwap<TrieRx>,
    pub(crate) tun_tx: Arc<Sender<(Vec<u8>, Arc<SendHandle>)>>,
    drasyl_rx: Arc<Receiver<(Vec<u8>, Arc<SendHandle>)>>,
}

impl SdnNodeInner {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: Identity,
        networks: HashMap<Url, Network>,
        cancellation_token: CancellationToken,
        node: Arc<Node>,
        recv_buf_rx: Arc<Receiver<(PubKey, Vec<u8>)>>,
        tun_tx: Arc<Sender<(Vec<u8>, Arc<SendHandle>)>>,
        drasyl_rx: Arc<Receiver<(Vec<u8>, Arc<SendHandle>)>>,
    ) -> Self {
        Self {
            id,
            networks: Arc::new(Mutex::new(networks)),
            cancellation_token,
            node,
            recv_buf_rx,
            routes_handle: Arc::new(Handle::new().expect("Failed to create route handle")),
            trie_rx: ArcSwap::new(Arc::new(IpnetTrie::new())),
            tun_tx,
            drasyl_rx,
        }
    }

    pub(crate) async fn bind_node(
        config: &SdnNodeConfig,
    ) -> Result<(Arc<Node>, Arc<Receiver<(PubKey, Vec<u8>)>>), Error> {
        // options
        let super_peers = SuperPeerUrl::parse_list(&util::get_env(
            "SUPER_PEERS",
            SUPER_PEERS_DEFAULT
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" "),
        ))
        .expect("Invalid super peer urls");
        let min_pow_difficulty = util::get_env("MIN_POW_DIFFICULTY", 24);
        let network_id = util::get_env("NETWORK_ID", 1i32).to_be_bytes();
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
        let udp_sockets = util::get_env("UDP_SOCKETS", 3);

        // build node
        let (recv_buf_tx, recv_buf_rx) = flume::bounded::<(PubKey, Vec<u8>)>(recv_buf_cap);
        let mut builder = NodeOptsBuilder::default();
        builder
            .id(config.id.clone())
            .network_id(network_id)
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
        inner: Arc<SdnNodeInner>,
        cancellation_token: CancellationToken,
    ) {
        let node = inner.node.clone();
        let recv_buf_rx = inner.recv_buf_rx.clone();
        let drasyl_rx = inner.drasyl_rx.clone();

        // options
        let c2d_threads = util::get_env("C2D_THREADS", 3);
        let tun_threads = util::get_env("TUN_THREADS", 3);

        // tun <-> drasyl packet processing
        #[allow(unused_variables)]
        for i in 0..tun_threads {
            // drasyl -> tun
            let node = node.clone();
            let recv_buf_rx = recv_buf_rx.clone();
            let child_token = cancellation_token.child_token();
            let inner_clone = inner.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = child_token.cancelled() => {}
                    _ = async move {
                        while let Ok((sender_key, buf)) = recv_buf_rx.recv_async().await {
                            match Ipv4HeaderSlice::from_slice(&buf) {
                                Ok(ip_hdr) => {
                                    if enabled!(Level::TRACE) {
                                        trace!(
                                            peer=?sender_key,
                                            src=?ip_hdr.source_addr(),
                                            dst=?ip_hdr.destination_addr(),
                                            "Forwarding packet from drasyl to TUN device: {} -> {} (debug: https://hpd.gasmi.net/?data={}&force=ipv4)",
                                            ip_hdr.source_addr(),
                                            ip_hdr.destination_addr(),
                                            bytes_to_hex(&buf)
                                        );
                                    }

                                    // filter drasyl control plane messages
                                    if is_drasyl_control_packet(&buf) {
                                        trace!(
                                            peer=?sender_key,
                                            src=?ip_hdr.source_addr(),
                                            dst=?ip_hdr.destination_addr(),
                                            "Dropping drasyl control plane packet: {} -> {} (control traffic filtered)",
                                            ip_hdr.source_addr(),
                                            ip_hdr.destination_addr()
                                        );
                                        continue;
                                    }

                                    let source = IpNet::from(IpAddr::V4(ip_hdr.source_addr()));
                                    if let Some((_, source_trie)) = inner_clone.trie_rx.load().longest_match(&source) {
                                        let dest = IpNet::from(IpAddr::V4(ip_hdr.destination_addr()));
                                        if let Some((_, (expected_key, tun_device))) = source_trie.longest_match(&dest)
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
                                            else if let Err(e) = tun_device.send(&buf).await {
                                                warn!(
                                                    peer=?sender_key,
                                                    src=?ip_hdr.source_addr(),
                                                    dst=?ip_hdr.destination_addr(),
                                                    tun_device=?tun_device.name().unwrap_or("unknown".to_string()),
                                                    error=?e,
                                                    "Failed to forward packet to TUN device: {}", e
                                                );
                                            }
                                            else {
                                                trace!(
                                                    peer=?sender_key,
                                                    src=?ip_hdr.source_addr(),
                                                    dst=?ip_hdr.destination_addr(),
                                                    tun_device=?tun_device.name().unwrap_or("unknown".to_string()),
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
                    } => {}
                }
            });
        }

        #[allow(unused_variables)]
        for i in 0..c2d_threads {
            // channel -> drasyl
            let drasyl_rx = drasyl_rx.clone();
            let child_token = cancellation_token.child_token();
            tokio::spawn(async move {
                tokio::select! {
                    _ = child_token.cancelled() => {}
                    _ = async move {
                        while let Ok((buf, send_handle)) = drasyl_rx.recv_async().await {
                            if let Err(e) = send_handle.send(&buf).await {
                                warn!(
                                    packet_size=?buf.len(),
                                    recipient=?send_handle.recipient,
                                    error=?e,
                                    "Failed to send packet to drasyl network: recipient={}, packet_size={} bytes, error={}",
                                    send_handle.recipient,
                                    buf.len(),
                                    e
                                );
                            }
                        }
                    } => {}
                }
            });
        }

        tokio::select! {
            _ = cancellation_token.cancelled() => {}
            _ = node.cancelled() => {
                cancellation_token.cancel();
            }
        }
    }

    pub(crate) async fn fetch_network_config(url: &str) -> Result<NetworkConfig, Error> {
        trace!("Fetching network config from: {}", url);
        let body = if url.starts_with("http://") || url.starts_with("https://") {
            let https = HttpsConnectorBuilder::new()
                .with_webpki_roots()
                .https_or_http()
                .enable_http1()
                .build();
            let client = Client::builder(TokioExecutor::new()).build::<_, Empty<Bytes>>(https);

            // parse URL and extract auth info if present
            let parsed_url = url::Url::parse(url)?;
            let mut request = Request::builder().uri(parsed_url.as_str()).method("GET");

            // add basic auth header if username and password are present
            let username = parsed_url.username();
            let password = parsed_url.password();
            if !username.is_empty() && password.is_some() {
                let auth = BASE64.encode(format!("{}:{}", username, password.unwrap()));
                request = request.header("Authorization", format!("Basic {auth}"));
            }

            let request = request.body(Empty::new())?;
            let response = client.request(request).await?;
            let body_bytes = response.into_body().collect().await?.to_bytes();
            String::from_utf8(body_bytes.to_vec())?
        } else {
            let path = url.strip_prefix("file://").unwrap_or(url);
            fs::read_to_string(path)?
        };
        Ok(NetworkConfig::try_from(body.as_str())?)
    }

    pub(crate) async fn shutdown(&self) {
        self.cancellation_token.cancel();

        // remove physical routes
        trace!("remove physical routes");
        let networks = self.networks.lock().await;
        let mut all_physical_routes: Vec<(Option<u32>, EffectiveRoutingList)> = Vec::new();

        for network in networks.values() {
            if let Some(state) = network.state.as_ref() {
                all_physical_routes.push((
                    network
                        .tun_state
                        .as_ref()
                        .and_then(|tun| tun.device.if_index().ok()),
                    state.routes.clone(),
                ));
            }
        }

        let routes_handle = self.routes_handle.clone();
        let task = tokio::spawn(async move {
            for (if_index, physical_routes) in all_physical_routes {
                trace!("Remove physical routes: {}", physical_routes);
                Self::remove_routes(routes_handle.clone(), physical_routes, if_index).await;
            }
        });
        futures::executor::block_on(task).unwrap();

        // hostnames
        #[cfg(all(feature = "dns", any(target_os = "macos", target_os = "linux")))]
        if let Err(e) = crate::node::housekeeping::cleanup_hosts_file() {
            error!("Failed to cleanup /etc/hosts: {}", e);
        }
    }
}

pub fn is_drasyl_control_packet(buf: &[u8]) -> bool {
    if let Ok(ip_hdr) = Ipv4HeaderSlice::from_slice(buf) {
        if ip_hdr.protocol() == etherparse::IpNumber::UDP {
            let ip_header_len = ip_hdr.slice().len();
            let udp_header_len = 8;
            let magic_number_len = 4;

            if buf.len() >= ip_header_len + udp_header_len + magic_number_len {
                let payload_start = ip_header_len + udp_header_len;
                return &buf[payload_start..][..magic_number_len]
                    == LONG_HEADER_MAGIC_NUMBER.as_bytes();
            }
        }
    }
    false
}
