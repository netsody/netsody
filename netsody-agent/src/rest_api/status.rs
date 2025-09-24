use crate::agent::Agent;
use crate::network::{
    AgentState, AgentStateStatus, AppliedStatus, EffectiveAccessRuleList, EffectiveRoutingList,
    Network,
};
use crate::rest_api::RestApiClient;
use crate::rest_api::auth::AuthToken;
use crate::rest_api::error::Error;
use crate::rest_api::server::RestApiServer;
use crate::version_info::VersionInfo;
use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Local, Utc};
use humantime::format_duration;
use p2p::identity::PubKey;
use p2p::message::ShortId;
use p2p::node::{HELLO_TIMEOUT_DEFAULT, NodeOpts};
use p2p::peer::{NodePeer, Peer, PeerPathInner, PeerPathKey, PowStatus, SessionKeys, SuperPeer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fmt::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::trace;
use url;
use url::Url;

impl RestApiServer {
    pub(crate) async fn status(State(agent): State<Arc<Agent>>, _: AuthToken) -> Json<Status> {
        trace!("Status request received");

        // opts
        let opts = agent.node().opts().clone();

        // peers
        trace!("Getting peers");
        let default_route = *agent.node().peers_list().default_route();
        let mut super_peers = HashMap::new();
        let mut node_peers = HashMap::new();
        for (pk, peer) in &agent.node().peers_list().peers.pin() {
            match peer {
                Peer::SuperPeer(super_peer) => {
                    super_peers.insert(*pk, SuperPeerStatus::new(super_peer));
                }
                Peer::NodePeer(node_peer) => {
                    node_peers.insert(*pk, NodePeerStatus::new(node_peer));
                }
            }
        }

        let mtu = agent.inner.mtu;

        // networks
        trace!("Locking networks to get status");
        let mut networks = HashMap::new();
        {
            let guard = agent.inner.networks.lock().await;
            for (config_url, network) in &*guard {
                networks.insert(config_url.clone(), NetworkStatus::new(network));
            }
        }
        trace!("Networks retrieved");

        let status = Status {
            version_info: VersionInfo::new(),
            opts,
            default_route,
            super_peers,
            node_peers,
            mtu,
            networks,
        };
        trace!("Status request completed");

        Json(status)
    }
}

impl RestApiClient {
    pub async fn status(&self) -> Result<Status, Error> {
        self.get("/status").await
    }
}

#[derive(Serialize, Deserialize)]
pub struct Status {
    pub version_info: VersionInfo,
    // netsody-p2p
    pub opts: NodeOpts,
    default_route: PubKey,
    super_peers: HashMap<PubKey, SuperPeerStatus>,
    node_peers: HashMap<PubKey, NodePeerStatus>,
    // netsody-agent
    pub mtu: u16,
    pub networks: HashMap<Url, NetworkStatus>,
}

impl Status {
    /// Returns a string representation of the status with optional secret masking
    pub fn to_string_with_secrets(&self, include_secrets: bool) -> String {
        let mut output = String::new();
        self.fmt(&mut output, include_secrets).unwrap();
        output
    }

    /// Formats the status with optional secret masking
    fn fmt(&self, f: &mut String, include_secrets: bool) -> std::fmt::Result {
        // version info
        let info = &self.version_info;
        writeln!(f, "Info:")?;
        writeln!(f, "  Version: {0} ({1})", info.version, info.full_commit())?;
        writeln!(f, "  Built: {0}", info.build_timestamp)?;
        writeln!(f, "  Profile: {0}", info.profile())?;
        writeln!(f, "  Features: {0}", info.features)?;
        writeln!(f)?;

        // opts
        writeln!(f, "Options:")?;
        writeln!(f, "  Identity:")?;
        if include_secrets {
            writeln!(f, "    Secret Key: {}", self.opts.id.sk)?;
        } else {
            writeln!(f, "    Secret Key: ****")?;
        }
        writeln!(f, "    Public Key: {}", self.opts.id.pk)?;
        writeln!(f, "    PoW: {}", self.opts.id.pow)?;
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
        writeln!(f, "  Min. PoW Difficulty: {}", self.opts.min_pow_difficulty)?;
        writeln!(
            f,
            "  HELLO Timeout: {}",
            format_duration(Duration::from_millis(self.opts.hello_timeout))
        )?;
        writeln!(
            f,
            "  HELLO Max. Age: {}",
            format_duration(Duration::from_millis(self.opts.hello_max_age))
        )?;
        writeln!(f, "  Super Peers:")?;
        for super_peer in &self.opts.super_peers {
            writeln!(f, "    {super_peer}")?;
        }
        writeln!(f, "  Network MTU: {}", self.opts.mtu)?;
        writeln!(f, "  Process UNITEs: {}", self.opts.process_unites)?;
        writeln!(
            f,
            "  Housekeeping Interval: {}",
            format_duration(Duration::from_millis(self.opts.housekeeping_interval))
        )?;
        writeln!(f, "  Enforce TCP: {}", self.opts.enforce_tcp)?;
        #[cfg(feature = "prometheus")]
        {
            writeln!(f, "  Prometheus:")?;
            writeln!(
                f,
                "    URL: {}",
                self.opts
                    .prometheus_url
                    .as_ref()
                    .unwrap_or(&"None".to_string())
            )?;
            if include_secrets {
                writeln!(
                    f,
                    "    User: {}",
                    self.opts
                        .prometheus_user
                        .as_ref()
                        .unwrap_or(&"None".to_string())
                )?;
                writeln!(
                    f,
                    "    Password: {}",
                    self.opts
                        .prometheus_pass
                        .as_ref()
                        .unwrap_or(&"None".to_string())
                )?;
            } else {
                writeln!(f, "    User: ****")?;
                writeln!(f, "    Password: ****")?;
            }
        }
        writeln!(f, "  TUN MTU: {}", self.mtu)?;
        writeln!(f)?;

        // peers list
        writeln!(f, "Default Route: {}", self.default_route)?;
        writeln!(f, "Super Peers:")?;
        let mut super_peers: Vec<_> = self.super_peers.iter().collect();
        super_peers.sort_by(|a, b| a.0.cmp(b.0));
        for (pk, super_peer) in super_peers {
            writeln!(f, "  {pk}:")?;
            for line in super_peer.to_string_with_secrets(include_secrets).lines() {
                writeln!(f, "    {line}")?;
            }
        }
        writeln!(f, "Node Peers:")?;
        let mut node_peers: Vec<_> = self.node_peers.iter().collect();
        node_peers.sort_by(|a, b| a.0.cmp(b.0));
        for (pk, node_peer) in node_peers {
            writeln!(f, "  {pk}:")?;
            for line in node_peer.to_string_with_secrets(include_secrets).lines() {
                writeln!(f, "    {line}")?;
            }
        }
        writeln!(f)?;

        // networks
        writeln!(f, "Networks:")?;
        let mut networks: Vec<_> = self.networks.iter().collect();
        networks.sort_by(|a, b| a.0.cmp(b.0));
        for (config_url, network) in networks {
            if include_secrets {
                writeln!(f, "  {config_url}:")?;
            } else {
                writeln!(f, "  {}:", mask_url(config_url))?; // Masked URL
            }
            for line in network.to_string().lines() {
                writeln!(f, "    {line}")?;
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
    resolved_addrs: Option<Vec<SocketAddr>>,
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
            resolved_addrs: super_peer.resolved_addrs().as_ref().map(|v| (**v).clone()),
            best_udp_path: super_peer.best_udp_path_key().cloned(),
            udp_paths,
            reachable: super_peer.is_reachable(),
        }
    }
}

impl SuperPeerStatus {
    /// Returns a string representation with optional secret masking
    pub fn to_string_with_secrets(&self, include_secrets: bool) -> String {
        let mut output = String::new();
        self.fmt(&mut output, include_secrets).unwrap();
        output
    }

    /// Formats the status with optional secret masking
    fn fmt(&self, f: &mut String, _include_secrets: bool) -> std::fmt::Result {
        writeln!(f, "Address: {}", self.addr)?;
        writeln!(f, "TCP:")?;
        writeln!(f, "  Port: {}", self.tcp_port)?;
        match &self.tcp_path {
            Some(path) => {
                writeln!(f, "  Connection: Established")?;
                for line in format_path(path).lines() {
                    writeln!(f, "  {line}")?;
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
        match &self.resolved_addrs {
            Some(resolved_addrs) => {
                writeln!(f, "Resolved Addresses:")?;
                for addr in resolved_addrs {
                    writeln!(f, "  {addr}")?;
                }
            }
            None => {
                writeln!(f, "Resolved Addresses: None")?;
            }
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
            writeln!(f, "    {key}:")?;
            for line in format_path(path).lines() {
                writeln!(f, "      {line}")?;
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

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;

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
            reachable: node_peer.is_reachable(now, HELLO_TIMEOUT_DEFAULT),
        }
    }
}

impl NodePeerStatus {
    /// Returns a string representation with optional secret masking
    pub fn to_string_with_secrets(&self, include_secrets: bool) -> String {
        let mut output = String::new();
        self.fmt(&mut output, include_secrets).unwrap();
        output
    }

    /// Formats the status with optional secret masking
    fn fmt(&self, f: &mut String, _include_secrets: bool) -> std::fmt::Result {
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
                writeln!(f, "  {key}:")?;
                for line in format_path(path).lines() {
                    writeln!(f, "    {line}")?;
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
pub struct NetworkStatus {
    pub disabled: bool,
    pub name: Option<String>,
    pub status: AgentStateStatus,
    pub desired_state: AgentState,
    pub current_state: AgentState,
}

impl NetworkStatus {
    fn new(network: &Network) -> Self {
        Self {
            disabled: network.disabled,
            name: network.name.clone(),
            status: network.status.clone(),
            desired_state: network.desired_state.clone(),
            current_state: network.current_state.clone(),
        }
    }
}

impl NetworkStatus {
    /// Returns a user-friendly string representation of the network status
    pub fn status_text(&self) -> String {
        match &self.status {
            AgentStateStatus::Initializing => "Initializing".to_string(),
            AgentStateStatus::Disabled => "Disabled".to_string(),
            AgentStateStatus::Ok => "Ok".to_string(),
            AgentStateStatus::Pending => "Pending".to_string(),
            AgentStateStatus::RetrieveConfigError(error) => {
                format!("Config Error - {}", error)
            }
            AgentStateStatus::NotAMemberError => "Error - Not a Member".to_string(),
        }
    }
}

impl fmt::Display for NetworkStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Name: {}",
            self.name
                .as_ref()
                .map_or("None".to_string(), |name| name.to_string())
        )?;
        writeln!(f, "Disabled: {}", self.disabled)?;
        writeln!(f, "Status: {:?}", self.status)?;

        // ip
        if self.current_state.ip == self.desired_state.ip {
            writeln!(f, "IP: {}", self.current_state.ip)?;
        } else {
            writeln!(f, "IP:")?;
            writeln!(f, "  Current: {}", self.current_state.ip)?;
            writeln!(f, "  Desired: {}", self.desired_state.ip)?;
        }

        // access rules
        let write_access_rules = |f: &mut std::fmt::Formatter,
                                  access_rules_opt: &Option<EffectiveAccessRuleList>,
                                  indent: &str|
         -> Result<(), std::fmt::Error> {
            match access_rules_opt {
                Some(access_rules) if !access_rules.is_empty() => {
                    for line in access_rules.to_string().lines() {
                        writeln!(f, "{indent}{line}")?;
                    }
                }
                _ => {
                    writeln!(f, "{indent}Empty")?;
                }
            }
            Ok(())
        };
        if self.current_state.access_rules == self.desired_state.access_rules {
            writeln!(f, "Access Rules:")?;
            write_access_rules(f, &self.current_state.access_rules.applied, "  ")?;
        } else {
            writeln!(f, "Access Rules:")?;
            writeln!(f, "  Current:")?;
            write_access_rules(f, &self.current_state.access_rules.applied, "    ")?;
            writeln!(f, "  Desired:")?;
            write_access_rules(f, &self.desired_state.access_rules.applied, "    ")?;
        }

        // routes
        let write_routes = |f: &mut std::fmt::Formatter,
                            status: &AppliedStatus<EffectiveRoutingList>,
                            indent: &str|
         -> Result<(), std::fmt::Error> {
            match &status.applied {
                Some(routes) if !routes.is_empty() => {
                    for line in routes.to_string().lines() {
                        writeln!(f, "{indent}{line}")?;
                    }
                    if let Some(error) = &status.error {
                        writeln!(f, "{indent}Error: {}", error)?;
                    }
                }
                Some(_) => {
                    if let Some(error) = &status.error {
                        writeln!(f, "{indent}Empty (Error: {})", error)?;
                    } else {
                        writeln!(f, "{indent}Empty")?;
                    }
                }
                _ => {
                    if let Some(error) = &status.error {
                        writeln!(f, "{indent}None (Error: {})", error)?;
                    } else {
                        writeln!(f, "{indent}None")?;
                    }
                }
            }
            Ok(())
        };
        if self.current_state.routes == self.desired_state.routes {
            writeln!(f, "Routes:")?;
            write_routes(f, &self.current_state.routes, "  ")?;
        } else {
            writeln!(f, "Routes:")?;
            writeln!(f, "  Current:")?;
            write_routes(f, &self.current_state.routes, "    ")?;
            writeln!(f, "  Desired:")?;
            write_routes(f, &self.desired_state.routes, "    ")?;
        }

        // forwarding
        if self.current_state.forwarding == self.desired_state.forwarding {
            writeln!(f, "Forwarding: {}", self.current_state.forwarding)?;
        } else {
            writeln!(f, "Forwarding:")?;
            writeln!(f, "  Current: {}", self.current_state.forwarding)?;
            writeln!(f, "  Desired: {}", self.desired_state.forwarding)?;
        }

        #[cfg(all(
            feature = "dns",
            any(
                target_os = "macos",
                target_os = "linux",
                target_os = "ios",
                target_os = "android"
            )
        ))]
        {
            use crate::network::HostnameList;

            // hostnames
            let write_hostnames = |f: &mut std::fmt::Formatter,
                                   hostnames_opt: &Option<HostnameList>,
                                   indent: &str|
             -> Result<(), std::fmt::Error> {
                match hostnames_opt {
                    Some(hostnames) if !hostnames.is_empty() => {
                        for line in hostnames.to_string().lines() {
                            writeln!(f, "{indent}{line}")?;
                        }
                    }
                    _ => {
                        writeln!(f, "{indent}Empty")?;
                    }
                }
                Ok(())
            };

            if self.current_state.hostnames == self.desired_state.hostnames {
                writeln!(f, "Hostnames:")?;
                write_hostnames(f, &self.current_state.hostnames.applied, "  ")?;
            } else {
                writeln!(f, "Hostnames:")?;
                writeln!(f, "  Current:")?;
                write_hostnames(f, &self.current_state.hostnames.applied, "    ")?;
                writeln!(f, "  Desired:")?;
                write_hostnames(f, &self.desired_state.hostnames.applied, "    ")?;
            }
        }

        Ok(())
    }
}

fn format_path(path: &PeerPathInner) -> String {
    let mut result = String::new();

    // Unanswered HELLO
    result.push_str(&format!(
        "Unanswered HELLO Since: {}",
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
        "Last ACK Time: {}{}",
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
        "Last ACK Source: {}",
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
            None => format!("Invalid timestamp ({timestamp})"),
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
pub fn mask_url(url: &Url) -> String {
    if !url.username().is_empty() || url.password().is_some() {
        let mut masked_url = url.clone();
        masked_url.set_username("****").unwrap();
        masked_url.set_password(Some("****")).unwrap();
        return masked_url.to_string();
    }
    url.to_string()
}
