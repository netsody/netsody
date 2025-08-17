use crate::sp::SuperPeerInner;
use crate::sp::TransportProt;
use hyper::Request;
use hyper::Response;
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use lazy_static::lazy_static;
use p2p::util;
use prometheus::{
    CounterVec, Encoder, HistogramVec, TextEncoder, register_counter_vec, register_histogram_vec,
};
use prometheus::{Gauge, GaugeVec, opts, register_gauge, register_gauge_vec};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::string::ToString;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tracing::{error, instrument, trace};

lazy_static! {
    static ref PROMETHEUS_PEERS: Gauge =
        register_gauge!(opts!("drasyl_sp_peers", "Number of peers.",)).unwrap();
    static ref PROMETHEUS_PEER_PATHS: GaugeVec = register_gauge_vec!(
        "drasyl_sp_peer_paths",
        "Number of paths.",
        &[
            "peer",
            "ip_version", // ipv4, ipv6
            "transport", // tcp, udp
        ]
    )
    .unwrap();
    static ref PROMETHEUS_PEER_ENDPOINTS: HistogramVec =
        register_histogram_vec!(
        "drasyl_sp_peer_endpoints",
        "Number of endpoints.",
        &[
            "peer",
        ],
        vec![0.0, 1.0, 2.0, 3.0, 5.0, 7.0, 10.0, 15.0]
    ).unwrap();
    pub static ref PROMETHEUS_MESSAGES: CounterVec =
        register_counter_vec!("drasyl_sp_messages", "Number of messages received/sent.", &[
            "type", // ack, app, hello, unite
            "peer",
            "direction", // rx, tx
    ]).unwrap();
    pub static ref PROMETHEUS_RELAYED_BYTES: CounterVec =
        register_counter_vec!("drasyl_sp_relayed_bytes", "Number of bytes relayed.", &[
            "src",
            "dst",
    ]).unwrap();
}

type BoxedErr = Box<dyn std::error::Error + Send + Sync + 'static>;

const PROMETHEUS_LISTEN_DEFAULT: SocketAddrV4 =
    SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 9898);
const PROMETHEUS_CONNECTION_TIMEOUT: u64 = 10_000; // millis
const PROMETHEUS_TOKEN_DEFAULT: &str = "";

const PROMETHEUS_LABEL_UDP: &str = "udp";
const PROMETHEUS_LABEL_TCP: &str = "tcp";
const PROMETHEUS_LABEL_IP4: &str = "ipv4";
const PROMETHEUS_LABEL_IP6: &str = "ipv6";
pub const PROMETHEUS_LABEL_ACK: &str = "ack";
pub const PROMETHEUS_LABEL_APP: &str = "app";
pub const PROMETHEUS_LABEL_HELLO: &str = "hello";
pub const PROMETHEUS_LABEL_UNITE: &str = "unite";
pub const PROMETHEUS_LABEL_RX: &str = "rx";
pub const PROMETHEUS_LABEL_TX: &str = "tx";

async fn serve_req(
    req: Request<Incoming>,
    required_token: &str,
) -> Result<Response<String>, BoxedErr> {
    // check correct path
    if req.uri().path() != "/metrics" {
        trace!(path = %req.uri().path(), "Non-metrics path accessed");
        return Ok(Response::builder()
            .status(404)
            .header("Connection", "close")
            .body("Not Found".to_string())?);
    }

    // authenticate
    if !required_token.is_empty() {
        let actual_token = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));

        if actual_token != Some(required_token) {
            return Ok(Response::builder()
                .status(401)
                .header("Connection", "close")
                .body("Unauthorized".to_string())?);
        }
    }

    let encoder = TextEncoder::new();

    let metric_families = prometheus::gather();
    let body = encoder.encode_to_string(&metric_families)?;

    trace!(body_len = body.len(), "Successfully encoded metrics");

    let response = Response::builder()
        .status(200)
        .header(CONTENT_TYPE, encoder.format_type())
        .body(body)?;

    trace!(status_code = %response.status(), "Successfully encoded metrics");

    Ok(response)
}

#[instrument(skip_all)]
pub async fn prometheus_server() {
    let prometheus_listen =
        util::get_env("PROMETHEUS_LISTEN", PROMETHEUS_LISTEN_DEFAULT.to_string());
    let prometheus_token = util::get_env("PROMETHEUS_TOKEN", PROMETHEUS_TOKEN_DEFAULT.to_string());

    trace!("Bind prometheus server to {}", prometheus_listen);
    match TcpListener::bind(prometheus_listen.clone()).await {
        Ok(listener) => loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    trace!("Prometheus server accepted connection from {}", addr);
                    let io = TokioIo::new(stream);

                    let service = service_fn(|req| serve_req(req, &prometheus_token));
                    let result = timeout(
                        Duration::from_millis(PROMETHEUS_CONNECTION_TIMEOUT),
                        http1::Builder::new()
                            .keep_alive(false)
                            .serve_connection(io, service),
                    )
                    .await;
                    match result {
                        Ok(Ok(_)) => {
                            trace!("Connection from {} handled and closed", addr);
                        }
                        Ok(Err(err)) => {
                            error!("server error: {:?}", err);
                        }
                        Err(_) => {
                            error!(
                                "server timeout after {} ms for {}",
                                PROMETHEUS_CONNECTION_TIMEOUT, addr
                            );
                        }
                    }
                }
                Err(e) => error!("accept failed: {:?}", e),
            }
        },
        Err(e) => error!("Prometheus server error: {}", e),
    }
}

impl SuperPeerInner {
    pub(crate) fn housekeeping_prometheus(&self) {
        PROMETHEUS_PEER_PATHS.reset();

        let mut peers_count = 0;
        for (pk, peer) in &self.peers_list.peers.pin() {
            peers_count += 1;
            let mut peer_paths_tcp_ipv4_count = 0;
            let mut peer_paths_tcp_ipv6_count = 0;
            let mut peer_paths_udp_ipv4_count = 0;
            let mut peer_paths_udp_ipv6_count = 0;
            match peer.endpoint() {
                Some((TransportProt::TCP, addr)) => match addr.ip() {
                    IpAddr::V4(_) => peer_paths_tcp_ipv4_count += 1,
                    IpAddr::V6(addr) => {
                        if addr.to_ipv4().is_some() {
                            peer_paths_tcp_ipv4_count += 1
                        } else {
                            peer_paths_tcp_ipv6_count += 1
                        }
                    }
                },
                Some((TransportProt::UDP, addr)) => match addr.ip() {
                    IpAddr::V4(_) => peer_paths_udp_ipv4_count += 1,
                    IpAddr::V6(addr) => {
                        if addr.to_ipv4().is_some() {
                            peer_paths_udp_ipv4_count += 1
                        } else {
                            peer_paths_udp_ipv6_count += 1
                        }
                    }
                },
                None => {}
            }

            // paths
            PROMETHEUS_PEER_PATHS
                .with_label_values(&[
                    pk.to_string(),
                    PROMETHEUS_LABEL_IP4.to_string(),
                    PROMETHEUS_LABEL_TCP.to_string(),
                ])
                .set(peer_paths_tcp_ipv4_count as f64);
            PROMETHEUS_PEER_PATHS
                .with_label_values(&[
                    pk.to_string(),
                    PROMETHEUS_LABEL_IP6.to_string(),
                    PROMETHEUS_LABEL_TCP.to_string(),
                ])
                .set(peer_paths_tcp_ipv6_count as f64);
            PROMETHEUS_PEER_PATHS
                .with_label_values(&[
                    pk.to_string(),
                    PROMETHEUS_LABEL_IP4.to_string(),
                    PROMETHEUS_LABEL_UDP.to_string(),
                ])
                .set(peer_paths_udp_ipv4_count as f64);
            PROMETHEUS_PEER_PATHS
                .with_label_values(&[
                    pk.to_string(),
                    PROMETHEUS_LABEL_IP6.to_string(),
                    PROMETHEUS_LABEL_UDP.to_string(),
                ])
                .set(peer_paths_udp_ipv6_count as f64);

            // endpoints
            PROMETHEUS_PEER_ENDPOINTS
                .with_label_values(&[pk.to_string()])
                .observe(peer.hello_endpoints().len() as f64);
        }
        PROMETHEUS_PEERS.set(peers_count as f64);
    }
}
