mod error;

use crate::network;
use ahash::RandomState;
pub use error::*;
use ipnet::Ipv4Net;
use ipnet_trie::IpnetTrie;
use p2p::identity::PubKey;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;

#[derive(PartialEq, Debug, Clone, Deserialize)]
pub struct NetworkConfig {
    #[serde(rename = "network")]
    pub subnet: Ipv4Net,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(rename = "node", default, deserialize_with = "deserialize_nodes")]
    pub nodes: HashMap<PubKey, NetworkNode>,
    #[serde(rename = "route", default, deserialize_with = "deserialize_routes")]
    pub routes: HashMap<Ipv4Net, NetworkRoute>,
    #[serde(rename = "policy", default, deserialize_with = "deserialize_policies")]
    pub policies: HashSet<NetworkPolicy>,
}

impl NetworkConfig {
    pub fn ip(&self, pk: &PubKey) -> Option<Ipv4Addr> {
        self.nodes.get(pk).map(|p| p.ip)
    }

    pub fn groups(&self) -> HashMap<String, HashSet<PubKey>, RandomState> {
        let mut groups = HashMap::with_hasher(RandomState::new());
        for (pk, node) in &self.nodes {
            for node_group in &node.groups {
                let group_members = groups
                    .entry(node_group.clone())
                    .or_insert_with(HashSet::new);
                group_members.insert(*pk);
            }
        }
        groups
    }

    pub fn effective_access_rule_list(
        &self,
        my_pk: &PubKey,
    ) -> Result<EffectiveAccessRuleList, network::ConfigError> {
        let node = self.nodes.get(my_pk).unwrap();
        let my_groups = &node.groups;
        let my_ip = &node.ip;

        let mut entries = HashMap::with_hasher(RandomState::new());

        // OUT
        for (pk, node) in &self.nodes {
            if !my_pk.eq(pk) {
                let source: Ipv4Net = (*my_ip).into();
                let dest: Ipv4Net = node.ip.into();
                let entry = EffectiveAccessRule {
                    direction: Direction::OUT,
                    source,
                    dest,
                    pk: *pk,
                    action: if self.matching_policy(my_pk, pk) {
                        Action::Allow
                    } else {
                        Action::Deny
                    },
                };
                tracing::trace!("Adding OUT rule for node: {:?}", entry);
                if entries.insert(entry.clone().into(), entry).is_some() {
                    return Err(ConfigError::RouteDuplicate);
                }
            }
        }
        for (dest, route) in &self.routes {
            if !my_pk.eq(&route.gw) {
                let source: Ipv4Net = (*my_ip).into();
                let accept =
                    route.groups.is_empty() || route.groups.iter().any(|g| my_groups.contains(g));
                let entry = EffectiveAccessRule {
                    direction: Direction::OUT,
                    source,
                    dest: *dest,
                    pk: route.gw,
                    action: if accept { Action::Allow } else { Action::Deny },
                };
                tracing::trace!("Adding OUT rule for route (non-gateway): {:?}", entry);
                if entries.insert(entry.clone().into(), entry).is_some() {
                    return Err(ConfigError::RouteDuplicate);
                }
            } else {
                for (pk, node) in &self.nodes {
                    if !my_pk.eq(pk) {
                        let node_dest: Ipv4Net = node.ip.into();
                        let accept = route.groups.is_empty()
                            || route.groups.iter().any(|g| node.groups.contains(g));

                        let entry = EffectiveAccessRule {
                            direction: Direction::OUT,
                            source: *dest,
                            dest: node_dest,
                            pk: *pk,
                            action: if accept { Action::Allow } else { Action::Deny },
                        };
                        tracing::trace!("Adding OUT rule for route (gateway): {:?}", entry);
                        if entries.insert(entry.clone().into(), entry).is_some() {
                            return Err(ConfigError::RouteDuplicate);
                        }
                    }
                }
            }
        }

        // IN
        for (pk, node) in &self.nodes {
            if !my_pk.eq(pk) {
                let source: Ipv4Net = node.ip.into();
                let dest: Ipv4Net = (*my_ip).into();
                let entry = EffectiveAccessRule {
                    direction: Direction::IN,
                    source,
                    dest,
                    pk: *pk,
                    action: if self.matching_policy(my_pk, pk) {
                        Action::Allow
                    } else {
                        Action::Deny
                    },
                };
                tracing::trace!("Adding IN rule for node: {:?}", entry);
                if entries.insert(entry.clone().into(), entry).is_some() {
                    return Err(ConfigError::RouteDuplicate);
                }
            }
        }
        for (dest, route) in &self.routes {
            if !my_pk.eq(&route.gw) {
                let source = *dest;
                let dest: Ipv4Net = (*my_ip).into();
                let accept =
                    route.groups.is_empty() || route.groups.iter().any(|g| my_groups.contains(g));
                let entry = EffectiveAccessRule {
                    direction: Direction::IN,
                    source,
                    dest,
                    pk: route.gw,
                    action: if accept { Action::Allow } else { Action::Deny },
                };
                tracing::trace!("Adding IN rule for route (non-gateway): {:?}", entry);
                if entries.insert(entry.clone().into(), entry).is_some() {
                    return Err(ConfigError::RouteDuplicate);
                }
            } else {
                for (pk, node) in &self.nodes {
                    if !my_pk.eq(pk) {
                        let source: Ipv4Net = node.ip.into();
                        let accept = route.groups.is_empty()
                            || route.groups.iter().any(|g| node.groups.contains(g));
                        let entry = EffectiveAccessRule {
                            direction: Direction::IN,
                            source,
                            dest: *dest,
                            pk: *pk,
                            action: if accept { Action::Allow } else { Action::Deny },
                        };
                        tracing::trace!("Adding IN rule for route (gateway): {:?}", entry);
                        if entries.insert(entry.clone().into(), entry).is_some() {
                            return Err(ConfigError::RouteDuplicate);
                        }
                    }
                }
            }
        }

        Ok(EffectiveAccessRuleList(entries))
    }

    pub(crate) fn hostnames(&self, my_pk: &PubKey) -> HashMap<Ipv4Addr, String> {
        let mut hostnames = HashMap::new();
        let mut entries: Vec<_> = self.nodes.values().collect();
        entries.sort_by(|a, b| a.ip.cmp(&b.ip));
        for node in entries {
            if self.matching_policy(my_pk, &node.pk) {
                hostnames.insert(node.ip, node.hostname.clone());
            }
        }
        hostnames
    }

    pub fn matching_policy(&self, source_pk: &PubKey, dest_pk: &PubKey) -> bool {
        if source_pk.eq(dest_pk) {
            return true;
        }

        let (source_node, dest_node) = match (self.nodes.get(source_pk), self.nodes.get(dest_pk)) {
            (Some(source), Some(dest)) => (source, dest),
            _ => return false,
        };

        self.policies.iter().any(|policy| {
            // Check source -> dest direction
            let source_match = policy.source_groups.contains("ALL")
                || !policy.source_groups.is_disjoint(&source_node.groups);
            let dest_match = policy.destination_groups.contains("ALL")
                || !policy.destination_groups.is_disjoint(&dest_node.groups);
            if source_match && dest_match {
                return true;
            }

            // Check dest -> source direction
            let source_match = policy.source_groups.contains("ALL")
                || !policy.source_groups.is_disjoint(&dest_node.groups);
            let dest_match = policy.destination_groups.contains("ALL")
                || !policy.destination_groups.is_disjoint(&source_node.groups);
            source_match && dest_match
        })
    }

    pub fn effective_routing_list(
        &self,
        my_pk: &PubKey,
    ) -> Result<EffectiveRoutingList, network::ConfigError> {
        let mut physical_route = HashMap::with_hasher(RandomState::new());
        for (dest, route) in &self.routes {
            if has_route_access(my_pk, route, &self.nodes) {
                if let Some(node) = self.nodes.get(&route.gw) {
                    let route = EffectiveRoute {
                        dest: *dest,
                        gw: node.ip,
                        state: RouteState::Applied,
                    };
                    physical_route.insert(*dest, route);
                } else {
                    return Err(ConfigError::GatewayNotFound(route.gw));
                }
            }
        }
        Ok(EffectiveRoutingList(physical_route))
    }

    /// Returns true if at least one route exists with the given node as gateway
    ///
    /// # Arguments
    /// * `my_pk` - The public key of the node to check
    ///
    /// # Returns
    /// * `true` if the node is configured as a gateway for at least one route
    /// * `false` if the node is not a gateway for any route
    pub(crate) fn is_gateway(&self, my_pk: &PubKey) -> bool {
        self.routes.values().any(|route| route.gw == *my_pk)
    }
}

/// Checks if a node has access to a route
fn has_route_access(
    my_pk: &PubKey,
    route: &NetworkRoute,
    nodes: &HashMap<PubKey, NetworkNode>,
) -> bool {
    if my_pk.eq(&route.gw) {
        // i am the gateway, nothing to do
        false
    } else if !route.groups.is_empty() {
        // allowed?
        let my_groups = &nodes.get(my_pk).unwrap().groups;
        my_groups.iter().any(|g| route.groups.contains(g))
        // TODO check if we can access gateway?
    } else {
        true
    }
}

impl TryFrom<&str> for NetworkConfig {
    type Error = ConfigError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let network: NetworkConfig = toml::from_str(value)?;

        let broadcast_addr = network.subnet.broadcast();
        let last_host_ip = Ipv4Addr::from(u32::from(broadcast_addr) - 1);

        for node in network.nodes.values() {
            // check if node IP is in the network
            if !network.subnet.contains(&node.ip) {
                return Err(ConfigError::IpNotInNetwork(node.ip, network.subnet));
            }

            // check if IP is reserved
            if node.ip == last_host_ip {
                return Err(network::ConfigError::IpReserved(node.ip));
            }

            // check if hostname is valid
            if !is_valid_hostname(&node.hostname.to_lowercase()) {
                return Err(network::ConfigError::HostnameInvalid(node.hostname.clone()));
            }
        }

        for route in network.routes.values() {
            // check if destination is a network address
            let is_network_address = route.dest.network() == route.dest.addr();
            if !is_network_address {
                return Err(network::ConfigError::NetworkAddressInvalid(route.dest));
            }

            // check if all route gateways exist in nodes
            if !network.nodes.contains_key(&route.gw) {
                return Err(network::ConfigError::GatewayNotFound(route.gw));
            }
        }

        Ok(network)
    }
}

fn deserialize_nodes<'de, D>(deserializer: D) -> Result<HashMap<PubKey, NetworkNode>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let nodes: Vec<NetworkNode> = Vec::deserialize(deserializer)?;

    let mut ip_set = HashSet::new();
    let mut hostname_set = HashSet::new();

    let mut result = HashMap::new();
    for node in nodes {
        if result.insert(node.pk, node.clone()).is_some() {
            return Err(serde::de::Error::custom(format!(
                "duplicate public key: {}",
                node.pk
            )));
        }
        if !ip_set.insert(node.ip) {
            return Err(serde::de::Error::custom(format!(
                "duplicate IP address: {}",
                node.ip
            )));
        }
        // Use to_lowercase() to ensure case-insensitive hostname uniqueness
        // This prevents conflicts between hostnames like "Node-1" and "node-1"
        if !hostname_set.insert(node.hostname.to_lowercase()) {
            return Err(serde::de::Error::custom(format!(
                "duplicate hostname: {}",
                node.ip
            )));
        }
    }

    Ok(result)
}

fn deserialize_routes<'de, D>(deserializer: D) -> Result<HashMap<Ipv4Net, NetworkRoute>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let routes: Vec<NetworkRoute> = Vec::deserialize(deserializer)?;

    let mut result = HashMap::new();
    for route in routes {
        if result.insert(route.dest, route.clone()).is_some() {
            return Err(serde::de::Error::custom(format!(
                "duplicate route destination: {}",
                route.dest
            )));
        }
    }

    Ok(result)
}

fn deserialize_groups<'de, D>(deserializer: D) -> Result<HashSet<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let vec: Vec<String> = Vec::deserialize(deserializer)?;
    Ok(vec.into_iter().collect())
}

fn deserialize_policies<'de, D>(deserializer: D) -> Result<HashSet<NetworkPolicy>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let policies: Vec<NetworkPolicy> = Vec::deserialize(deserializer)?;
    Ok(policies.into_iter().collect())
}

#[derive(PartialEq, Debug, Clone, Deserialize, Eq)]
pub struct NetworkNode {
    pub pk: PubKey,
    pub ip: Ipv4Addr,
    pub hostname: String,
    #[serde(default, deserialize_with = "deserialize_groups")]
    pub groups: HashSet<String>,
}

#[derive(PartialEq, Debug, Clone, Deserialize)]
pub struct NetworkRoute {
    pub dest: Ipv4Net,
    pub gw: PubKey,
    #[serde(default, deserialize_with = "deserialize_groups")]
    pub groups: HashSet<String>,
}

#[derive(PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct EffectiveAccessRuleList(
    pub HashMap<EffectiveAccessRuleListEntryKey, EffectiveAccessRule, RandomState>,
);

impl EffectiveAccessRuleList {
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn routing_tries(
        &self,
    ) -> (IpnetTrie<IpnetTrie<PubKey>>, IpnetTrie<IpnetTrie<PubKey>>) {
        // tx
        let mut trie_tx = IpnetTrie::new();

        let out_entries: Vec<&EffectiveAccessRule> = self
            .0
            .values()
            .filter(|e| e.direction == Direction::OUT && e.action == Action::Allow)
            .collect();
        let mut entries_by_source: HashMap<Ipv4Net, Vec<&EffectiveAccessRule>, RandomState> =
            HashMap::with_hasher(RandomState::new());
        for entry in out_entries {
            entries_by_source
                .entry(entry.source)
                .or_default()
                .push(entry);
        }
        for (source, entries) in entries_by_source {
            let mut source_trie = IpnetTrie::new();
            for entry in entries {
                source_trie.insert(entry.dest, entry.pk);
            }
            trie_tx.insert(source, source_trie);
        }

        // rx
        let mut trie_rx = IpnetTrie::new();

        let in_entries: Vec<&EffectiveAccessRule> = self
            .0
            .values()
            .filter(|e| e.direction == Direction::IN && e.action == Action::Allow)
            .collect();
        let mut entries_by_source: HashMap<Ipv4Net, Vec<&EffectiveAccessRule>> = HashMap::new();
        for entry in in_entries {
            entries_by_source
                .entry(entry.source)
                .or_default()
                .push(entry);
        }
        for (source, entries) in entries_by_source {
            let mut source_trie = IpnetTrie::new();
            for entry in entries {
                source_trie.insert(entry.dest, entry.pk);
            }
            trie_rx.insert(source, source_trie);
        }

        (trie_tx, trie_rx)
    }
}

impl Display for EffectiveAccessRuleList {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{:<4} {:<18} {:<18} {:<64} {:6}",
            "Type", "Source", "Destination", "PubKey", "Action"
        )?;

        let mut entries: Vec<&EffectiveAccessRule> = self.0.values().collect();
        entries.sort_by(|a, b| match a.direction.cmp(&b.direction) {
            Ordering::Equal => match a.source.cmp(&b.source) {
                Ordering::Equal => a.dest.cmp(&b.dest),
                other => other,
            },
            other => other,
        });

        for entry in entries {
            writeln!(
                f,
                "{:<4} {:<18} {:<18} {:<64} {:6}",
                entry.direction.to_string(),
                entry.source.to_string(),
                entry.dest.to_string(),
                entry.pk.to_string(),
                entry.action.to_string()
            )?;
        }

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct EffectiveAccessRuleListEntryKey {
    pub direction: Direction,
    pub source: Ipv4Net,
    pub dest: Ipv4Net,
}

impl From<EffectiveAccessRule> for EffectiveAccessRuleListEntryKey {
    fn from(entry: EffectiveAccessRule) -> Self {
        Self {
            direction: entry.direction,
            source: entry.source,
            dest: entry.dest,
        }
    }
}

impl Serialize for EffectiveAccessRuleListEntryKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = format!("{}-{}-{}", self.direction, self.source, self.dest);
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for EffectiveAccessRuleListEntryKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let parts: Vec<&str> = s.split('-').collect();

        if parts.len() != 3 {
            return Err(serde::de::Error::custom(
                "Invalid format. Expected DIRECTION-SOURCE-DEST",
            ));
        }

        let direction = match parts[0] {
            "IN" => Direction::IN,
            "OUT" => Direction::OUT,
            _ => {
                return Err(serde::de::Error::custom(
                    "Invalid direction. Expected IN or OUT",
                ));
            }
        };

        let source = parts[1]
            .parse::<Ipv4Net>()
            .map_err(|e| serde::de::Error::custom(format!("Invalid source network: {e}")))?;

        let dest = parts[2]
            .parse::<Ipv4Net>()
            .map_err(|e| serde::de::Error::custom(format!("Invalid destination network: {e}")))?;

        Ok(EffectiveAccessRuleListEntryKey {
            direction,
            source,
            dest,
        })
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct EffectiveAccessRule {
    pub direction: Direction,
    pub source: Ipv4Net,
    pub dest: Ipv4Net,
    pub pk: PubKey,
    pub action: Action,
}

impl Display for EffectiveAccessRule {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "direction={:?} source={:?} dest={:?} pk={:?} action={:?}",
            self.direction, self.source, self.dest, self.pk, self.action
        )?;
        Ok(())
    }
}

#[derive(PartialEq, Eq, Hash, Debug, Clone, Serialize, Deserialize)]
pub enum Direction {
    IN,
    OUT,
}

impl PartialOrd for Direction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Direction {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Direction::OUT, Direction::IN) => Ordering::Less,
            (Direction::IN, Direction::OUT) => Ordering::Greater,
            _ => Ordering::Equal,
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Direction::IN => write!(f, "IN"),
            Direction::OUT => write!(f, "OUT"),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum Action {
    Allow,
    Deny,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Action::Allow => write!(f, "ALLOW"),
            Action::Deny => write!(f, "DENY"),
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Deserialize)]
pub struct NetworkPolicy {
    #[serde(rename = "source_groups", deserialize_with = "deserialize_groups")]
    pub source_groups: HashSet<String>,
    #[serde(rename = "destination_groups", deserialize_with = "deserialize_groups")]
    pub destination_groups: HashSet<String>,
}

impl Hash for NetworkPolicy {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Sort groups to ensure consistent hash calculation
        let mut source_groups: Vec<&String> = self.source_groups.iter().collect();
        source_groups.sort();
        for group in source_groups {
            group.hash(state);
        }

        let mut dest_groups: Vec<&String> = self.destination_groups.iter().collect();
        dest_groups.sort();
        for group in dest_groups {
            group.hash(state);
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EffectiveRoute {
    pub(crate) dest: Ipv4Net,
    pub(crate) gw: Ipv4Addr,
    state: RouteState,
}

impl EffectiveRoute {
    pub(crate) fn as_pending_route(&self) -> Self {
        Self {
            dest: self.dest,
            gw: self.gw,
            state: RouteState::Pending,
        }
    }

    pub(crate) fn as_applied_route(&self) -> Self {
        Self {
            dest: self.dest,
            gw: self.gw,
            state: RouteState::Applied,
        }
    }

    pub(crate) fn as_removing_route(&self) -> Self {
        Self {
            dest: self.dest,
            gw: self.gw,
            state: RouteState::Removing,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, PartialOrd, Ord)]
pub enum RouteState {
    Pending,
    Applied,
    Removing,
}

impl fmt::Display for RouteState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            RouteState::Pending => write!(f, "PENDING"),
            RouteState::Applied => write!(f, "APPLIED"),
            RouteState::Removing => write!(f, "REMOVING"),
        }
    }
}

#[derive(PartialEq, Clone, Debug, Default, Serialize, Deserialize)]
pub struct EffectiveRoutingList(pub HashMap<Ipv4Net, EffectiveRoute, RandomState>);

impl EffectiveRoutingList {
    pub(crate) fn iter(&self) -> std::collections::hash_map::Iter<'_, Ipv4Net, EffectiveRoute> {
        self.0.iter()
    }

    pub(crate) fn contains(&self, dest: &Ipv4Net) -> bool {
        self.0.contains_key(dest)
    }

    pub(crate) fn add(&mut self, route: EffectiveRoute) {
        self.0.insert(route.dest, route);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Display for EffectiveRoutingList {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "{:<18} {:<15} {:<7}", "Destination", "Gateway", "State")?;

        let mut entries: Vec<(&Ipv4Net, &EffectiveRoute)> = self.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));

        for (dest, entry) in entries {
            writeln!(
                f,
                "{:<18} {:<15} {:<7}",
                dest.to_string(),
                entry.gw.to_string(),
                entry.state
            )?;
        }

        Ok(())
    }
}

fn is_valid_hostname(hostname: &str) -> bool {
    // Check length (1-63 characters)
    if hostname.is_empty() || hostname.len() > 63 {
        return false;
    }

    // Check if starts or ends with hyphen
    if hostname.starts_with('-') || hostname.ends_with('-') {
        return false;
    }

    // Check if contains only valid characters (lowercase letters, numbers, hyphens)
    hostname
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

#[cfg(test)]
mod tests {
    use crate::network;
    use crate::network::config::{NetworkConfig, NetworkPolicy};
    use ipnet::Ipv4Net;
    use p2p::identity::PubKey;
    use std::collections::HashSet;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn test_network_deserialization_with_name() {
        let toml_str = r#"
            network = "192.168.1.0/24"
            name = "Test Network"

            [[node]]
            pk       = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            ip       = "192.168.1.1"
            hostname = "node-1"
        "#;

        let network = NetworkConfig::try_from(toml_str).unwrap();

        assert_eq!(
            network.subnet,
            Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap()
        );
        assert_eq!(network.name, Some("Test Network".to_string()));
        assert_eq!(network.nodes.len(), 1);
    }

    #[test]
    fn test_network_deserialization_without_name() {
        let toml_str = r#"
            network = "192.168.1.0/24"

            [[node]]
            pk       = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            ip       = "192.168.1.1"
            hostname = "node-1"
        "#;

        let network = NetworkConfig::try_from(toml_str).unwrap();

        assert_eq!(
            network.subnet,
            Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap()
        );
        assert_eq!(network.name, None);
        assert_eq!(network.nodes.len(), 1);
    }

    #[test]
    fn test_network_deserialization() {
        let toml_str = r#"
            network = "192.168.1.0/24"

            [[node]]
            pk       = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            ip       = "192.168.1.1"
            hostname = "node-1"
            groups   = ["group1", "group2"]

            [[node]]
            pk       = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
            ip       = "192.168.1.2"
            hostname = "node-2"

            [[route]]
            dest   = "10.0.0.0/8"
            gw     = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            groups = ["group1"]

            [[policy]]
            source_groups      = ["ALL"]
            destination_groups = ["ALL"]

            [[policy]]
            source_groups      = ["heiko"]
            destination_groups = ["ALL"]
        "#;

        let network = NetworkConfig::try_from(toml_str).unwrap();

        assert_eq!(
            network.subnet,
            Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap()
        );
        assert_eq!(network.name, None);
        assert_eq!(network.nodes.len(), 2);
        assert_eq!(network.routes.len(), 1);
        assert_eq!(network.policies.len(), 2);

        let node1_pk =
            PubKey::from_str("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
                .unwrap();
        let node2_pk =
            PubKey::from_str("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
                .unwrap();

        // Test first node
        let node1 = network.nodes.get(&node1_pk).unwrap();
        assert_eq!(node1.ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(
            node1.groups,
            HashSet::from(["group1".to_string(), "group2".to_string()])
        );

        // Test second node
        let node2 = network.nodes.get(&node2_pk).unwrap();
        assert_eq!(node2.ip, Ipv4Addr::new(192, 168, 1, 2));
        assert!(node2.groups.is_empty());

        // Test route
        let route_dest = Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap();
        let route = network.routes.get(&route_dest).unwrap();
        assert_eq!(route.gw, node1_pk);
        assert_eq!(route.groups, HashSet::from(["group1".to_string()]));

        // Test policies
        let all_policy = NetworkPolicy {
            source_groups: HashSet::from(["ALL".to_string()]),
            destination_groups: HashSet::from(["ALL".to_string()]),
        };
        let heiko_policy = NetworkPolicy {
            source_groups: HashSet::from(["heiko".to_string()]),
            destination_groups: HashSet::from(["ALL".to_string()]),
        };
        assert!(network.policies.contains(&all_policy));
        assert!(network.policies.contains(&heiko_policy));
    }

    #[test]
    fn test_duplicate_pk() {
        let toml_str = r#"
            network = "192.168.1.0/24"

            [[node]]
            pk       = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            ip       = "192.168.1.1"
            hostname = "node-1"

            [[node]]
            pk       = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            ip       = "192.168.1.2"
            hostname = "node-2"
        "#;

        let result = NetworkConfig::try_from(toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, network::ConfigError::TomlError(_)));
        assert!(err.to_string().contains("duplicate public key"));
    }

    #[test]
    fn test_duplicate_ip() {
        let toml_str = r#"
            network = "192.168.1.0/24"

            [[node]]
            pk       = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            ip       = "192.168.1.1"
            hostname = "node-1"

            [[node]]
            pk       = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
            ip       = "192.168.1.1"
            hostname = "node-2"
        "#;

        let result = NetworkConfig::try_from(toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, network::ConfigError::TomlError(_)));
        assert!(err.to_string().contains("duplicate IP address"));
    }

    #[test]
    fn test_duplicate_hostname() {
        let toml_str = r#"
            network = "192.168.1.0/24"

            [[node]]
            pk       = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            ip       = "192.168.1.1"
            hostname = "node-1"

            [[node]]
            pk       = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
            ip       = "192.168.1.2"
            hostname = "node-1"
        "#;

        let result = NetworkConfig::try_from(toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, network::ConfigError::TomlError(_)));
        assert!(err.to_string().contains("duplicate hostname"));
    }

    #[test]
    fn test_duplicate_hostname_case_insensitive() {
        let toml_str = r#"
            network = "192.168.1.0/24"

            [[node]]
            pk       = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            ip       = "192.168.1.1"
            hostname = "Node-1"

            [[node]]
            pk       = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
            ip       = "192.168.1.2"
            hostname = "node-1"
        "#;

        let result = NetworkConfig::try_from(toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, network::ConfigError::TomlError(_)));
        assert!(err.to_string().contains("duplicate hostname"));
    }

    #[test]
    fn test_duplicate_route() {
        let toml_str = r#"
            network = "192.168.1.0/24"

            [[node]]
            pk       = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            ip       = "192.168.1.1"
            hostname = "node-1"

            [[route]]
            dest = "10.0.0.0/8"
            gw = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

            [[route]]
            dest = "10.0.0.0/8"
            gw = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
        "#;

        let result = NetworkConfig::try_from(toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, network::ConfigError::TomlError(_)));
        assert!(err.to_string().contains("duplicate route destination"));
    }

    #[test]
    fn test_ip_not_in_network() {
        let toml_str = r#"
            network = "192.168.1.0/24"

            [[node]]
            pk       = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            ip       = "192.168.2.1"
            hostname = "node-1"
        "#;

        let result = NetworkConfig::try_from(toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, network::ConfigError::IpNotInNetwork(_, _)));
        assert!(
            err.to_string()
                .contains("IP address 192.168.2.1 is not in network 192.168.1.0/24")
        );
    }

    #[test]
    fn test_reserved_ip() {
        let toml_str = r#"
            network = "192.168.1.0/24"

            [[node]]
            pk       = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            ip       = "192.168.1.254"
            hostname = "node-1"
        "#;

        let result = NetworkConfig::try_from(toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, network::ConfigError::IpReserved(_)));
        assert!(err.to_string().contains("192.168.1.254"));
    }

    #[test]
    fn test_gateway_not_found() {
        let toml_str = r#"
            network = "192.168.1.0/24"

            [[node]]
            pk       = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            ip       = "192.168.1.1"
            hostname = "node-1"

            [[route]]
            dest = "10.0.0.0/8"
            gw = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
        "#;

        let result = NetworkConfig::try_from(toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, network::ConfigError::GatewayNotFound(_)));
        assert!(err.to_string().contains("gateway fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 not found in nodes"));
    }

    #[test]
    fn test_invalid_dest() {
        let toml_str = r#"
            network = "192.168.1.0/24"

            [[node]]
            pk       = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            ip       = "192.168.1.1"
            hostname = "node-1"

            [[route]]
            dest = "10.10.10.5/24"
            gw = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        "#;

        let result = NetworkConfig::try_from(toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            network::ConfigError::NetworkAddressInvalid(_)
        ));
        assert!(err.to_string().contains("invalid network address:"));
    }

    #[test]
    fn test_matching_policy() {
        let toml_str = r#"
            network = "192.168.1.0/24"

            [[node]]
            pk       = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            ip       = "192.168.1.1"
            hostname = "node-1"
            groups   = ["group1"]

            [[node]]
            pk       = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
            ip       = "192.168.1.2"
            hostname = "node-2"
            groups   = ["group2"]

            [[node]]
            pk       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ip       = "192.168.1.3"
            hostname = "node-3"
            groups   = ["group3"]

            [[policy]]
            source_groups = ["group1"]
            destination_groups = ["group1"]

            [[policy]]
            source_groups = ["group1"]
            destination_groups = ["group2"]

            [[policy]]
            source_groups = ["group2"]
            destination_groups = ["group2"]

            [[policy]]
            source_groups = ["group2"]
            destination_groups = ["group3"]
        "#;

        let network = NetworkConfig::try_from(toml_str).unwrap();
        let node1_pk =
            PubKey::from_str("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
                .unwrap();
        let node2_pk =
            PubKey::from_str("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
                .unwrap();
        let node3_pk =
            PubKey::from_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();

        // Teste Kommunikation zwischen verschiedenen Knoten
        assert!(network.matching_policy(&node1_pk, &node2_pk)); // group1 -> group2
        assert!(network.matching_policy(&node2_pk, &node1_pk)); // group2 -> group1
        assert!(network.matching_policy(&node2_pk, &node3_pk)); // group2 -> group3
        assert!(network.matching_policy(&node3_pk, &node2_pk)); // group3 -> group2
        assert!(!network.matching_policy(&node1_pk, &node3_pk)); // keine Policy zwischen group1 und group3
        assert!(!network.matching_policy(&node3_pk, &node1_pk)); // keine Policy zwischen group3 und group1
    }

    #[test]
    fn test_invalid_hostname() {
        let long_hostname = "a".repeat(64);
        let test_cases = vec![
            ("", "empty hostname"),
            ("host-name", "valid hostname"),
            ("host--name", "valid hostname with double hyphen"),
            ("-hostname", "hostname starting with hyphen"),
            ("hostname-", "hostname ending with hyphen"),
            ("host.name", "hostname with dot"),
            ("host_name", "hostname with underscore"),
            (&long_hostname, "hostname too long"),
        ];

        for (hostname, description) in test_cases {
            let toml_str = format!(
                r#"
                network = "192.168.1.0/24"
                
                [[node]]
                pk = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                ip = "192.168.1.1"
                hostname = "{hostname}"
                "#
            );

            let result = NetworkConfig::try_from(toml_str.as_str());
            match hostname {
                "host-name" | "host--name" => {
                    assert!(result.is_ok(), "{description} should be valid")
                }
                _ => assert!(result.is_err(), "{description} should be invalid"),
            }
        }
    }

    #[test]
    fn test_has_route_access() {
        use crate::network::config::{NetworkNode, NetworkRoute, has_route_access};
        use std::collections::HashMap;
        use std::str::FromStr;

        // Create test data
        let node1_pk =
            PubKey::from_str("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
                .unwrap();
        let node2_pk =
            PubKey::from_str("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
                .unwrap();
        let node3_pk =
            PubKey::from_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();

        let mut nodes = HashMap::new();
        nodes.insert(
            node1_pk,
            NetworkNode {
                pk: node1_pk,
                ip: Ipv4Addr::new(192, 168, 1, 1),
                hostname: "node-1".to_string(),
                groups: HashSet::from(["group1".to_string(), "group2".to_string()]),
            },
        );
        nodes.insert(
            node2_pk,
            NetworkNode {
                pk: node2_pk,
                ip: Ipv4Addr::new(192, 168, 1, 2),
                hostname: "node-2".to_string(),
                groups: HashSet::from(["group2".to_string()]),
            },
        );
        nodes.insert(
            node3_pk,
            NetworkNode {
                pk: node3_pk,
                ip: Ipv4Addr::new(192, 168, 1, 3),
                hostname: "node-3".to_string(),
                groups: HashSet::new(),
            },
        );

        // Test 1: Node is the gateway itself - should return false
        let route_gateway = NetworkRoute {
            dest: Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
            gw: node1_pk,
            groups: HashSet::new(),
        };
        assert!(!has_route_access(&node1_pk, &route_gateway, &nodes));

        // Test 2: Route without groups - should return true
        let route_no_groups = NetworkRoute {
            dest: Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
            gw: node1_pk,
            groups: HashSet::new(),
        };
        assert!(has_route_access(&node2_pk, &route_no_groups, &nodes));

        // Test 3: Route with groups, node belongs to allowed group
        let route_with_groups = NetworkRoute {
            dest: Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
            gw: node1_pk,
            groups: HashSet::from(["group2".to_string()]),
        };
        assert!(has_route_access(&node2_pk, &route_with_groups, &nodes));

        // Test 4: Route with groups, node belongs to allowed group (multiple groups)
        let route_with_groups = NetworkRoute {
            dest: Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
            gw: node2_pk,
            groups: HashSet::from(["group1".to_string(), "group3".to_string()]),
        };
        assert!(has_route_access(&node1_pk, &route_with_groups, &nodes));

        // Test 5: Route with groups, node doesn't belong to allowed groups
        let route_with_groups = NetworkRoute {
            dest: Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
            gw: node1_pk,
            groups: HashSet::from(["group3".to_string()]),
        };
        assert!(!has_route_access(&node2_pk, &route_with_groups, &nodes));

        // Test 6: Node without groups tries to access route with groups
        let route_with_groups = NetworkRoute {
            dest: Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
            gw: node1_pk,
            groups: HashSet::from(["group1".to_string()]),
        };
        assert!(!has_route_access(&node3_pk, &route_with_groups, &nodes));

        // Test 7: Node without groups tries to access route without groups
        let route_no_groups = NetworkRoute {
            dest: Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
            gw: node1_pk,
            groups: HashSet::new(),
        };
        assert!(has_route_access(&node3_pk, &route_no_groups, &nodes));
    }

    #[test]
    fn test_route_access_without_gateway_access() {
        let toml_str = r#"
network = "192.168.1.0/24"

[[node]]
pk = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ip = "192.168.1.1"
hostname = "example-node-1"
groups = ["a"]

[[node]]
pk = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
ip = "192.168.1.2"
hostname = "example-gateway"
groups = ["b"]

[[route]]
dest = "10.0.0.0/16"
gw = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
groups = ["a"]
"#;

        let network = NetworkConfig::try_from(toml_str).unwrap();

        // Test for aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        let gateway_host =
            PubKey::from_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();

        // Get effective_access_rule_list
        let rules_list_host = network.effective_access_rule_list(&gateway_host).unwrap();
        // println!("rules_list for aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:\n{}", rules_list_host);

        // Check the expected access rules
        let rules = &rules_list_host.0;

        // OUT  192.168.1.1/32        10.0.0.0/16     bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ALLOW
        let expected_out_route_allow = crate::network::config::EffectiveAccessRule {
            direction: crate::network::config::Direction::OUT,
            source: Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 1), 32).unwrap(),
            dest: Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 16).unwrap(),
            pk: PubKey::from_str(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
            .unwrap(),
            action: crate::network::config::Action::Allow,
        };
        assert!(
            rules.values().any(|rule| rule == &expected_out_route_allow),
            "OUT rule for route 10.0.0.0/16 should be ALLOW"
        );

        // Test for bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
        let gateway_pk =
            PubKey::from_str("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .unwrap();

        // Get effective_access_rule_list
        let rules_list_gateway = network.effective_access_rule_list(&gateway_pk).unwrap();
        // println!("rules_list for bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:\n{}", rules_list_gateway);

        // Check the expected access rules
        let rules = &rules_list_gateway.0;

        // OUT  10.0.0.0/16        192.168.1.1/32     aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ALLOW
        let expected_out_route_allow = crate::network::config::EffectiveAccessRule {
            direction: crate::network::config::Direction::OUT,
            source: Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 16).unwrap(),
            dest: Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 1), 32).unwrap(),
            pk: PubKey::from_str(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            action: crate::network::config::Action::Allow,
        };
        assert!(
            rules.values().any(|rule| rule == &expected_out_route_allow),
            "OUT rule for route 10.0.0.0/16 should be ALLOW"
        );

        // OUT  192.168.1.2/32     192.168.1.1/32     aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa DENY
        let expected_out_gateway_deny = crate::network::config::EffectiveAccessRule {
            direction: crate::network::config::Direction::OUT,
            source: Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 2), 32).unwrap(),
            dest: Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 1), 32).unwrap(),
            pk: PubKey::from_str(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            action: crate::network::config::Action::Deny,
        };
        assert!(
            rules
                .values()
                .any(|rule| rule == &expected_out_gateway_deny),
            "OUT rule for gateway 192.168.1.2/32 should be DENY"
        );

        // IN   192.168.1.1/32     10.0.0.0/16        aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ALLOW
        let expected_in_route_allow = crate::network::config::EffectiveAccessRule {
            direction: crate::network::config::Direction::IN,
            source: Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 1), 32).unwrap(),
            dest: Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 16).unwrap(),
            pk: PubKey::from_str(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            action: crate::network::config::Action::Allow,
        };
        assert!(
            rules.values().any(|rule| rule == &expected_in_route_allow),
            "IN rule for route 10.0.0.0/16 should be ALLOW"
        );

        // IN   192.168.1.1/32     192.168.1.2/32     aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa DENY
        let expected_in_gateway_deny = crate::network::config::EffectiveAccessRule {
            direction: crate::network::config::Direction::IN,
            source: Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 1), 32).unwrap(),
            dest: Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 2), 32).unwrap(),
            pk: PubKey::from_str(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            action: crate::network::config::Action::Deny,
        };
        assert!(
            rules.values().any(|rule| rule == &expected_in_gateway_deny),
            "IN rule for gateway 192.168.1.2/32 should be DENY"
        );
    }

    #[test]
    fn test_is_gateway_returns_true_when_node_is_gateway() {
        let toml_str = r#"
            network = "192.168.1.0/24"
            name = "Test Network"

            [[node]]
            pk       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ip       = "192.168.1.1"
            hostname = "gateway-node"

            [[node]]
            pk       = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            ip       = "192.168.1.2"
            hostname = "client-node"

            [[route]]
            dest   = "10.0.0.0/8"
            gw     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "#;

        let config = NetworkConfig::try_from(toml_str).unwrap();
        let my_pk =
            PubKey::from_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();

        // Test that is_gateway returns true when my_pk is a gateway
        assert!(
            config.is_gateway(&my_pk),
            "is_gateway should return true when node is a gateway"
        );
    }

    #[test]
    fn test_is_gateway_returns_false_when_node_is_not_gateway() {
        let toml_str = r#"
            network = "192.168.1.0/24"
            name = "Test Network"

            [[node]]
            pk       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ip       = "192.168.1.1"
            hostname = "client-node"

            [[node]]
            pk       = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            ip       = "192.168.1.2"
            hostname = "gateway-node"

            [[route]]
            dest   = "10.0.0.0/8"
            gw     = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        "#;

        let config = NetworkConfig::try_from(toml_str).unwrap();
        let my_pk =
            PubKey::from_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();

        // Test that is_gateway returns false when my_pk is not a gateway
        assert!(
            !config.is_gateway(&my_pk),
            "is_gateway should return false when node is not a gateway"
        );
    }
}
