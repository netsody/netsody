pub(crate) mod config;

use arc_swap::ArcSwap;
pub use config::*;
use drasyl::node::SendHandle;
use ipnet::Ipv4Net;
use ipnet_trie::IpnetTrie;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;
use tun_rs::AsyncDevice as TunDevice;

#[derive(Clone)]
pub struct TunState {
    pub(crate) cancellation_token: CancellationToken,
    pub(crate) device: Arc<TunDevice>,
}

#[derive(PartialEq, Clone)]
pub struct LocalNodeState {
    pub(crate) subnet: Ipv4Net,
    pub(crate) ip: Ipv4Addr,
    pub(crate) virtual_routes: VirtualRoutingTable,
    pub(crate) physical_routes: PhysicalRoutingTable,
    pub(crate) hostnames: HashMap<Ipv4Addr, String>,
}

impl LocalNodeState {
    pub(crate) fn tun_state(&self) -> (Ipv4Net, Ipv4Addr) {
        (self.subnet, self.ip)
    }
}

pub struct NetworkInner {
    pub(crate) trie_tx: ArcSwap<IpnetTrie<IpnetTrie<Arc<SendHandle>>>>,
    pub(crate) tun_state: Mutex<Option<TunState>>,
}

impl Default for NetworkInner {
    fn default() -> Self {
        Self {
            trie_tx: ArcSwap::from_pointee(IpnetTrie::new()),
            tun_state: Default::default(),
        }
    }
}

pub struct Network {
    pub(crate) config_url: String,
    pub(crate) state: Mutex<Option<LocalNodeState>>,
    pub(crate) inner: Arc<NetworkInner>,
}

impl Network {
    pub(crate) fn new(config_url: String) -> Self {
        Self {
            config_url,
            state: Default::default(),
            inner: Default::default(),
        }
    }
}
