use crate::identity::PubKey;
use crate::node::NodeInner;
use crate::peer::Peer;
use lazy_static::lazy_static;
use prometheus::{CounterVec, HistogramVec, labels, register_counter_vec, register_histogram_vec};
use prometheus::{GaugeVec, register_gauge_vec};
use std::string::ToString;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{error, trace, warn};

lazy_static! {
    static ref PROMETHEUS_PEERS: GaugeVec =
        register_gauge_vec!("netsody_peers", "Number of peers.",
        &[
            "type" // super_peer, node_peer
        ]).unwrap();
    static ref PROMETHEUS_PEER_LATENCIES: HistogramVec = register_histogram_vec!(
    "netsody_peer_latencies",
    "Peer latencies.",
    &[
            "peer",
            "type" // super_peer, node_peer
        ],
    vec![0.001, 0.003, 0.006, 0.01, 0.03, 0.06, 0.1, 0.3, 0.6, 1.0]
).unwrap();
    static ref PROMETHEUS_PEER_PATHS: GaugeVec = register_gauge_vec!(
        "netsody_peer_paths",
        "Number of paths.",
        &[
            "peer",
            "state",
        ]
    )
    .unwrap();
    pub static ref PROMETHEUS_MESSAGES: CounterVec =
        register_counter_vec!("netsody_messages", "Number of messages received/sent.", &[
            "type", // ack, app, hello, unite
            "peer",
            "direction", // rx, tx
    ]).unwrap();
    pub static ref PROMETHEUS_BYTES: CounterVec =
        register_counter_vec!("netsody_bytes", "Number of bytes transmitted.", &[
            "peer",
            "direction", // rx, tx
            "path", // direct, relayed
    ]).unwrap();
}

pub const PROMETHEUS_LABEL_SUPER_PEER: &str = "super_peer";
pub const PROMETHEUS_LABEL_NODE_PEER: &str = "node_peer";
pub const PROMETHEUS_LABEL_REACHABLE: &str = "reachable";
pub const PROMETHEUS_LABEL_UNREACHABLE: &str = "unreachable";
pub const PROMETHEUS_LABEL_ACK: &str = "ack";
pub const PROMETHEUS_LABEL_APP: &str = "app";
pub const PROMETHEUS_LABEL_HELLO: &str = "hello";
pub const PROMETHEUS_LABEL_UNITE: &str = "unite";
pub const PROMETHEUS_LABEL_RX: &str = "rx";
pub const PROMETHEUS_LABEL_TX: &str = "tx";
pub const PROMETHEUS_LABEL_DIRECT: &str = "direct";
pub const PROMETHEUS_LABEL_RELAYED: &str = "relayed";

impl NodeInner {
    pub(crate) async fn prometheus_pusher(
        inner: Arc<NodeInner>,
        cancellation_token: CancellationToken,
    ) {
        if let (Some(prometheus_url), Some(prometheus_user), Some(prometheus_pass)) = (
            inner.opts.prometheus_url.clone(),
            inner.opts.prometheus_user.clone(),
            inner.opts.prometheus_pass.clone(),
        ) {
            let mut interval = tokio::time::interval(Duration::from_millis(5000));

            loop {
                tokio::select! {
                    biased;
                    _ = cancellation_token.cancelled() => {
                        break;
                    }
                    _ = interval.tick() => {
                        let inner = inner.clone();
                        let prometheus_url = prometheus_url.clone();
                        let prometheus_user = prometheus_user.clone();
                        let prometheus_pass = prometheus_pass.clone();
                        if let Err(e) = tokio::task::spawn_blocking(move || {
                            Self::push_metrics(&inner, prometheus_url, prometheus_user, prometheus_pass);
                        }).await {
                            error!("push metrics error {:?}", e);
                        }
                    }
                }
            }
        } else {
            trace!("prometheus_url, user or pass is empty. Stop prometheus_pusher");
        }
    }

    fn push_metrics(
        inner: &Arc<NodeInner>,
        prometheus_url: String,
        prometheus_user: String,
        prometheus_pass: String,
    ) {
        let metric_families = prometheus::gather();
        if let Err(e) = prometheus::push_metrics(
            "netsody_push",
            labels! {
                "instance".to_owned() => inner.opts.id.pk.to_string(),
                "node".to_owned() => inner.opts.id.pk.to_string(),
            },
            &prometheus_url,
            metric_families,
            Some(prometheus::BasicAuthentication {
                username: prometheus_user,
                password: prometheus_pass,
            }),
        ) {
            warn!("Failed to push gathered metrics to Pushgateway {prometheus_url}: {e}");
        } else {
            trace!("Pushed gathered metrics to Pushgateway {prometheus_url}");
        }
    }

    pub(crate) fn housekeeping_prometheus(&self, inner: &Arc<NodeInner>) {
        let time = self.current_time();

        PROMETHEUS_PEER_PATHS.reset();

        let mut peers_super_peer_count = 0;
        let mut peers_node_peer_count = 0;
        for (pk, peer) in &inner.peers_list.peers.pin() {
            let mut path_reachable_count = 0;
            let mut path_unreachable_count = 0;

            match peer {
                Peer::SuperPeer(super_peer) => {
                    if super_peer.is_reachable() {
                        peers_super_peer_count += 1;
                    }

                    // udp
                    for (_, path) in &super_peer.udp_paths.pin() {
                        if path.is_reachable(time, self.opts.hello_timeout) {
                            path_reachable_count += 1;
                        } else {
                            path_unreachable_count += 1;
                        }
                    }

                    // TODO: tcp?

                    if let Some(median_lat) = super_peer.median_lat() {
                        PROMETHEUS_PEER_LATENCIES
                            .with_label_values(&[
                                pk.to_string(),
                                PROMETHEUS_LABEL_SUPER_PEER.to_string(),
                            ])
                            .observe(median_lat as f64 / 1_000_000.0);
                    }
                }
                Peer::NodePeer(node_peer) => {
                    if node_peer.has_app_traffic(time) {
                        peers_node_peer_count += 1;

                        for (_, path) in &node_peer.paths.pin() {
                            if path.is_reachable(time, self.opts.hello_timeout) {
                                path_reachable_count += 1;
                            } else {
                                path_unreachable_count += 1;
                            }
                        }
                    }

                    if let Some(median_lat) = node_peer.median_lat() {
                        PROMETHEUS_PEER_LATENCIES
                            .with_label_values(&[
                                pk.to_string(),
                                PROMETHEUS_LABEL_NODE_PEER.to_string(),
                            ])
                            .observe(median_lat as f64 / 1_000_000.0);
                    }
                }
            }

            PROMETHEUS_PEER_PATHS
                .with_label_values(&[pk.to_string(), PROMETHEUS_LABEL_REACHABLE.to_string()])
                .set(path_reachable_count as f64);
            PROMETHEUS_PEER_PATHS
                .with_label_values(&[pk.to_string(), PROMETHEUS_LABEL_UNREACHABLE.to_string()])
                .set(path_unreachable_count as f64);
        }
        PROMETHEUS_PEERS
            .with_label_values(&[PROMETHEUS_LABEL_SUPER_PEER.to_string()])
            .set(peers_super_peer_count as f64);
        PROMETHEUS_PEERS
            .with_label_values(&[PROMETHEUS_LABEL_NODE_PEER.to_string()])
            .set(peers_node_peer_count as f64);
    }

    pub(crate) fn on_app_prometheus(peer: &PubKey, bytes_len: usize, path: String) {
        PROMETHEUS_MESSAGES
            .with_label_values(&[PROMETHEUS_LABEL_APP, &peer.to_string(), PROMETHEUS_LABEL_RX])
            .inc();
        PROMETHEUS_BYTES
            .with_label_values(&[peer.to_string(), PROMETHEUS_LABEL_RX.to_string(), path])
            .inc_by(bytes_len as f64);
    }
}
