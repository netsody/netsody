use crate::network::{Network, PhysicalRoutingTable, VirtualRoutingTable};
use crate::node::SdnNode;
use crate::rest_api::RestApi;
use crate::rest_api::auth::AuthToken;
use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Local, Utc};
use drasyl::identity::PubKey;
use drasyl::message::ShortId;
use drasyl::node::{HELLO_TIMEOUT_DEFAULT, NodeOpts};
use drasyl::peer::{NodePeer, Peer, PeerPathInner, PeerPathKey, PowStatus, SessionKeys, SuperPeer};
use humantime::format_duration;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url;

impl RestApi {
    pub(crate) async fn status(State(sdn_node): State<Arc<SdnNode>>, _: AuthToken) -> Json<Status> {
        // opts
        let opts = sdn_node.drasyl_node().opts().clone();

        // peers
        let default_route = *sdn_node.drasyl_node().peers_list().default_route();
        let mut super_peers = HashMap::new();
        let mut node_peers = HashMap::new();
        for (pk, peer) in &sdn_node.drasyl_node().peers_list().peers.pin() {
            match peer {
                Peer::SuperPeer(super_peer) => {
                    super_peers.insert(*pk, SuperPeerStatus::new(super_peer));
                }
                Peer::NodePeer(node_peer) => {
                    node_peers.insert(*pk, NodePeerStatus::new(node_peer));
                }
            }
        }

        // networks
        let mut networks = HashMap::new();
        for (config_url, network) in &sdn_node.inner.networks {
            networks.insert(config_url.clone(), NetworkStatus::new(network));
        }

        let status = Status {
            opts,
            default_route,
            super_peers,
            node_peers,
            networks,
        };
        Json(status)
    }
}
#[derive(Serialize, Deserialize)]
pub struct Status {
    // drasyl
    opts: NodeOpts,
    default_route: PubKey,
    super_peers: HashMap<PubKey, SuperPeerStatus>,
    node_peers: HashMap<PubKey, NodePeerStatus>,
    // drasyl-sdn
    networks: HashMap<String, NetworkStatus>,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // opts
        writeln!(f, "Options:")?;
        writeln!(f, "  Identity:")?;
        // writeln!(f, "    Secret Key: {}", self.opts.id.sk)?;
        writeln!(f, "    Public Key: {}", self.opts.id.pk)?;
        writeln!(f, "    PoW: {}", self.opts.id.pow)?;
        writeln!(
            f,
            "  Network ID: {:?}",
            u32::from_be_bytes(self.opts.network_id)
        )?;
        writeln!(f, "  UDP:")?;
        writeln!(
            f,
            "    Addresses: {}",
            self.opts
                .udp_addrs
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(
            f,
            "    Port: {}",
            match self.opts.udp_port {
                None => format!(
                    "{} (derived from own public key)",
                    self.opts.id.pk.udp_port()
                ),
                Some(0) => "random".to_string(),
                Some(udp_port) => udp_port.to_string(),
            }
        )?;
        writeln!(f, "    Sockets: {}", self.opts.udp_sockets)?;
        writeln!(f, "  Arm Messages: {}", self.opts.arm_messages)?;
        writeln!(f, "  Max. Peers: {}", self.opts.max_peers)?;
        writeln!(f, "  Min. PoW difficulty: {}", self.opts.min_pow_difficulty)?;
        writeln!(
            f,
            "  HELLO timeout: {}",
            format_duration(Duration::from_millis(self.opts.hello_timeout))
        )?;
        writeln!(
            f,
            "  HELLO Max. Age: {}",
            format_duration(Duration::from_millis(self.opts.hello_max_age))
        )?;
        writeln!(f, "  Super Peers:")?;
        for super_peer in &self.opts.super_peers {
            writeln!(f, "    {}", super_peer)?;
        }
        writeln!(f, "  MTU: {}", self.opts.mtu)?;
        writeln!(f, "  Process UNITEs: {}", self.opts.process_unites)?;
        writeln!(
            f,
            "  Housekeeping interval: {}",
            format_duration(Duration::from_millis(self.opts.housekeeping_interval))
        )?;
        writeln!(f, "  Enforce TCP: {}", self.opts.enforce_tcp)?;
        writeln!(f)?;

        // peers list
        writeln!(f, "Default Route: {}", self.default_route)?;
        writeln!(f, "Super Peers:")?;
        let mut super_peers: Vec<_> = self.super_peers.iter().collect();
        super_peers.sort_by(|a, b| a.0.cmp(b.0));
        for (pk, super_peer) in super_peers {
            writeln!(f, "  {}:", pk)?;
            for line in super_peer.to_string().lines() {
                writeln!(f, "    {}", line)?;
            }
        }
        writeln!(f, "Node Peers:")?;
        let mut node_peers: Vec<_> = self.node_peers.iter().collect();
        node_peers.sort_by(|a, b| a.0.cmp(b.0));
        for (pk, node_peer) in node_peers {
            writeln!(f, "  {}:", pk)?;
            for line in node_peer.to_string().lines() {
                writeln!(f, "    {}", line)?;
            }
        }
        writeln!(f)?;

        // networks
        writeln!(f, "Networks:")?;
        let mut networks: Vec<_> = self.networks.iter().collect();
        networks.sort_by(|a, b| a.0.cmp(b.0));
        for (config_url, network) in networks {
            writeln!(f, "  {}:", mask_url(config_url))?;
            for line in network.to_string().lines() {
                writeln!(f, "    {}", line)?;
            }
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SuperPeerStatus {
    addr: String,
    tcp_port: u16,
    tcp_path: Option<PeerPathInner>,
    session_keys: Option<SessionKeys>,
    resolved_addrs: Vec<SocketAddr>,
    best_udp_path: Option<PeerPathKey>,
    udp_paths: HashMap<PeerPathKey, PeerPathInner>,
    // generated
    reachable: bool,
}

impl SuperPeerStatus {
    fn new(super_peer: &SuperPeer) -> Self {
        let udp_paths = super_peer
            .udp_paths
            .pin()
            .iter()
            .map(|(path_key, path)| (*path_key, path.inner_store.load().as_ref().clone()))
            .collect();

        Self {
            addr: super_peer.addr.clone(),
            tcp_port: super_peer.tcp_port,
            tcp_path: super_peer
                .tcp_connection()
                .as_ref()
                .map(|tcp| tcp.path.inner_store.load().as_ref().clone()),
            session_keys: super_peer.session_keys.clone(),
            resolved_addrs: super_peer.resolved_addrs().as_ref().clone(),
            best_udp_path: super_peer.best_udp_path_key().cloned(),
            udp_paths,
            reachable: super_peer.is_reachable(),
        }
    }
}

impl fmt::Display for SuperPeerStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Address: {}", self.addr)?;
        writeln!(f, "TCP:")?;
        writeln!(f, "  Port: {}", self.tcp_port)?;
        match &self.tcp_path {
            Some(path) => {
                writeln!(f, "  Connection: Established")?;
                for line in format_path(path).lines() {
                    writeln!(f, "  {}", line)?;
                }
            }
            None => writeln!(f, "  Connection: Not present")?,
        }
        // match &self.session_keys {
        //     Some(keys) => {
        //         writeln!(f, "Session Keys:")?;
        //         for line in keys.to_string().lines() {
        //             writeln!(f, "  {}", line)?;
        //         }
        //     }
        //     None => writeln!(f, "Session Keys: Not present")?,
        // }
        writeln!(f, "Resolved Addresses:")?;
        for addr in &self.resolved_addrs {
            writeln!(f, "  {}", addr)?;
        }
        writeln!(f, "UDP:")?;
        writeln!(
            f,
            "  Best Path: {}",
            self.best_udp_path
                .as_ref()
                .map_or("".to_string(), |p| p.to_string())
        )?;
        writeln!(f, "  Paths:")?;
        for (key, path) in &self.udp_paths {
            writeln!(f, "    {}:", key)?;
            for line in format_path(path).lines() {
                writeln!(f, "      {}", line)?;
            }
        }
        writeln!(f, "[Reachable: {}]", self.reachable)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct NodePeerStatus {
    pow: PowStatus,
    session_keys: Option<SessionKeys>,
    created_at: u64,
    app_tx: u64,
    app_rx: u64,
    best_path: Option<PeerPathKey>,
    paths: HashMap<PeerPathKey, PeerPathInner>,
    tx_short_id: Option<ShortId>,
    rx_short_id: ShortId,
    // generated
    reachable: bool,
}

impl NodePeerStatus {
    fn new(node_peer: &NodePeer) -> Self {
        let paths = node_peer
            .paths
            .pin()
            .iter()
            .map(|(path_key, path)| (*path_key, path.inner_store.load().as_ref().clone()))
            .collect();

        Self {
            pow: node_peer.pow(),
            session_keys: node_peer.session_keys.clone(),
            created_at: node_peer.created_at,
            app_tx: node_peer.app_tx.load(SeqCst),
            app_rx: node_peer.app_rx.load(SeqCst),
            best_path: node_peer.best_path_key().cloned(),
            paths,
            rx_short_id: node_peer.rx_short_id(),
            tx_short_id: node_peer.tx_short_id(),
            reachable: node_peer.is_reachable(),
        }
    }
}

impl fmt::Display for NodePeerStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "PoW State: {:?}", self.pow)?;
        // match &self.session_keys {
        //     Some(keys) => {
        //         writeln!(f, "Session Keys:")?;
        //         for line in keys.to_string().lines() {
        //             writeln!(f, "  {}", line)?;
        //         }
        //     }
        //     None => writeln!(f, "Session Keys: Not present")?,
        // }

        writeln!(
            f,
            "Created At: {}{}",
            format_timestamp(self.created_at),
            if self.created_at != 0 {
                format!(" ({} ago)", time_ago_in_words(self.created_at))
            } else {
                "".to_string()
            }
        )?;
        if self.app_tx > 0 {
            writeln!(
                f,
                "APP TX: {}{}",
                format_timestamp(self.app_tx),
                if self.app_tx != 0 {
                    format!(" ({} ago)", time_ago_in_words(self.app_tx))
                } else {
                    "".to_string()
                }
            )?;
        } else {
            writeln!(f, "APP TX: Never")?;
        }
        if self.app_rx > 0 {
            writeln!(
                f,
                "APP RX: {}{}",
                format_timestamp(self.app_rx),
                if self.app_rx != 0 {
                    format!(" ({} ago)", time_ago_in_words(self.app_rx))
                } else {
                    "".to_string()
                }
            )?;
        } else {
            writeln!(f, "APP RX: Never")?;
        }
        writeln!(
            f,
            "Best Path: {}",
            self.best_path
                .as_ref()
                .map_or("None".to_string(), |p| p.to_string())
        )?;
        if !self.paths.is_empty() {
            writeln!(f, "Paths:")?;
            for (key, path) in &self.paths {
                writeln!(f, "  {}:", key)?;
                for line in format_path(path).lines() {
                    writeln!(f, "    {}", line)?;
                }
            }
        } else {
            writeln!(f, "Paths: None")?;
        }
        writeln!(
            f,
            "TX Short ID: {}",
            self.tx_short_id
                .as_ref()
                .map_or("None".to_string(), |id| id.to_string())
        )?;
        writeln!(f, "RX Short ID: {}", self.rx_short_id)?;
        writeln!(f, "[Reachable: {}]", self.reachable)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct NetworkStatus {
    subnet: Option<Ipv4Net>,
    ip: Option<Ipv4Addr>,
    virtual_routes: Option<VirtualRoutingTable>,
    physical_routes: Option<PhysicalRoutingTable>,
    hostnames: Option<HashMap<Ipv4Addr, String>>,
    tun_device: Option<String>,
}

impl NetworkStatus {
    fn new(network: &Network) -> Self {
        let guard = network.state.lock().expect("Mutex poisoned");
        Self {
            subnet: guard.as_ref().map(|state| state.subnet),
            ip: guard.as_ref().map(|state| state.ip),
            virtual_routes: guard.as_ref().map(|state| state.virtual_routes.clone()),
            physical_routes: guard.as_ref().map(|state| state.physical_routes.clone()),
            hostnames: guard.as_ref().map(|state| state.hostnames.clone()),
            tun_device: network
                .inner
                .tun_state
                .lock()
                .expect("Mutex poisoned")
                .as_ref()
                .and_then(|tun| tun.device.name().ok()),
        }
    }
}

impl fmt::Display for NetworkStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Subnet: {}",
            self.subnet
                .as_ref()
                .map_or("None".to_string(), |s| s.to_string())
        )?;
        writeln!(
            f,
            "IP: {}",
            self.ip
                .as_ref()
                .map_or("None".to_string(), |ip| ip.to_string())
        )?;
        match &self.virtual_routes {
            Some(virtual_routes) if !virtual_routes.is_empty() => {
                writeln!(f, "Virtual Routes:")?;
                if let Some(virtual_routes) = &self.virtual_routes {
                    for line in virtual_routes.to_string().lines() {
                        writeln!(f, "  {}", line)?;
                    }
                }
            }
            _ => {
                writeln!(f, "Virtual Routes: None")?;
            }
        }
        match &self.physical_routes {
            Some(routes) if !routes.is_empty() => {
                writeln!(f, "Physical Routes:")?;
                for line in routes.to_string().lines() {
                    writeln!(f, "  {}", line)?;
                }
            }
            _ => {
                writeln!(f, "Physical Routes: None")?;
            }
        }
        #[cfg(all(feature = "dns", any(target_os = "macos", target_os = "linux")))]
        {
            match &self.hostnames {
                Some(hostnames) if !hostnames.is_empty() => {
                    writeln!(f, "Hostnames:")?;
                    if let Some(hostnames) = &self.hostnames {
                        let mut entries: Vec<_> = hostnames.iter().collect();
                        entries.sort_by(|a, b| a.0.cmp(b.0));
                        for (ip_addr, hostname) in entries {
                            writeln!(f, "  {:<15} {}", ip_addr, hostname)?;
                        }
                    }
                }
                _ => {
                    writeln!(f, "Hostnames: None")?;
                }
            }
        }
        writeln!(
            f,
            "TUN device: {}",
            self.tun_device
                .as_ref()
                .map_or("None".to_string(), |tun_device| tun_device.to_string())
        )?;

        Ok(())
    }
}

fn format_path(path: &PeerPathInner) -> String {
    let mut result = String::new();

    // Unanswered HELLO
    result.push_str(&format!(
        "Unanswered HELLO since: {}",
        match path.unanswered_hello_since {
            Some(unanswered_hello_since) if unanswered_hello_since != 0 => format!(
                "{} ({})",
                format_timestamp(unanswered_hello_since),
                time_ago_in_words(unanswered_hello_since)
            ),
            Some(_) => "No unanswered HELLO".to_string(),
            None => "No HELLO sent yet".to_string(),
        }
    ));
    result.push('\n');

    // Last ACK time
    result.push_str(&format!(
        "Last ACK time: {}{}",
        format_timestamp(path.last_ack_time),
        if path.last_ack_time != 0 {
            format!(" ({} ago)", time_ago_in_words(path.last_ack_time))
        } else {
            "".to_string()
        }
    ));
    result.push('\n');

    // Last ACK source
    result.push_str(&format!(
        "Last ACK source: {}",
        path.last_ack_src
            .as_ref()
            .map_or("".to_string(), |s| s.to_string())
    ));
    result.push('\n');

    // Latencies
    if !path.lats.is_empty() {
        result.push_str(&format!(
            "Latencies: {} ms",
            path.lats
                .iter()
                .map(|&lat| format!("{:.3}", lat as f64 / 1000.0))
                .collect::<Vec<_>>()
                .join(" ms, ")
        ));
    } else {
        result.push_str("Latencies:");
    }
    result.push('\n');

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;

    result.push_str(&format!(
        "[Reachable: {}]",
        path.is_reachable(now, HELLO_TIMEOUT_DEFAULT)
    ));

    result
}

/// format a microsecond timestamp as local time string
fn format_timestamp(timestamp: u64) -> String {
    if timestamp == 0 {
        "Never".to_string()
    } else {
        // Convert microseconds to seconds and nanoseconds
        let timestamp_secs = (timestamp / 1_000_000) as i64;
        let timestamp_nanos = ((timestamp % 1_000_000) * 1000) as u32;

        match DateTime::<Utc>::from_timestamp(timestamp_secs, timestamp_nanos) {
            Some(dt) => {
                let local_dt: DateTime<Local> = dt.with_timezone(&Local);
                local_dt.to_rfc3339()
            }
            None => format!("Invalid timestamp ({})", timestamp),
        }
    }
}

/// returns a human-readable relative time string for a microsecond timestamp
fn time_ago_in_words(timestamp_micros: u64) -> String {
    let now = SystemTime::now();
    let ts = UNIX_EPOCH + Duration::from_micros(timestamp_micros);

    let delta = match now.duration_since(ts) {
        Ok(delta) => delta,
        Err(e) => e.duration(), // future
    };
    format_duration(delta).to_string()
}

/// mask secrets in a network config url
fn mask_url(url: &str) -> String {
    if let Ok(parsed_url) = url::Url::parse(url) {
        if let Some(password) = parsed_url.password() {
            let mut masked_url = url.to_string();
            let username = parsed_url.username();
            let auth = format!("{}:{}", username, password);
            masked_url = masked_url.replace(&auth, "****:****");
            return masked_url;
        }
    }
    url.to_string()
}
