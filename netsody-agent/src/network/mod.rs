pub(crate) mod config;

pub use config::*;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;

#[derive(Clone)]
pub struct TunState {
    pub(crate) ip: Ipv4Addr,
}

#[derive(PartialEq, Clone)]
pub struct LocalNodeState {
    pub(crate) subnet: Ipv4Net,
    pub(crate) ip: Ipv4Addr,
    pub(crate) access_rules: EffectiveAccessRuleList,
    pub(crate) routes: EffectiveRoutingList,
    pub(crate) forwarding: bool,
    pub(crate) hostnames: HashMap<Ipv4Addr, String>,
}

impl LocalNodeState {
    pub(crate) fn tun_state(&self) -> (Ipv4Net, Ipv4Addr) {
        (self.subnet, self.ip)
    }
}

#[derive(Deserialize, Serialize, Clone)]
pub struct Network {
    pub(crate) config_url: String,
    #[serde(default)]
    pub(crate) disabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    #[serde(skip_deserializing, skip_serializing, default)]
    pub(crate) state: Option<LocalNodeState>,
    #[serde(skip_deserializing, skip_serializing, default)]
    pub(crate) tun_state: Option<TunState>,
}
