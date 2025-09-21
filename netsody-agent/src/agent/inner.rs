pub(crate) use crate::agent::Error;
use crate::network::{AgentState, Network};
use arc_swap::ArcSwap;
use bytes::Bytes;
use etherparse::Ipv4HeaderSlice;
use flume::{Receiver, Sender};
use http_body_util::Empty;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use p2p::identity::{Identity, PubKey};
use p2p::message::LONG_HEADER_MAGIC_NUMBER;
use p2p::node::{Node, SendHandle};

use crate::agent::firewall::AgentFirewall;
use crate::agent::netif::{AgentNetif, AgentNetifInterface};
#[cfg(any(target_os = "ios", target_os = "android"))]
pub(crate) use crate::agent::network_listener::{NetworkChange, NetworkListener};
use crate::agent::router::{AgentRouter, AgentRouterInterface};
use crate::agent::{AgentConfig, PlatformDependent};
use ipnet_trie::IpnetTrie;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};
use tokio_util::sync::CancellationToken;
use tracing::trace;
use url::Url;

pub(crate) type TrieRx = IpnetTrie<IpnetTrie<PubKey>>;
pub(crate) type TrieTx = IpnetTrie<IpnetTrie<Arc<SendHandle>>>;

pub struct AgentInner {
    pub(crate) id: Identity,
    pub(crate) networks: Arc<Mutex<HashMap<Url, Network>>>,
    pub(crate) cancellation_token: CancellationToken,
    pub(crate) node: Arc<Node>,
    pub(crate) recv_buf_rx: Arc<Receiver<(PubKey, Vec<u8>)>>,
    pub(crate) netif: AgentNetif,
    pub(crate) firewall: AgentFirewall,
    pub(crate) router: AgentRouter,
    #[cfg(feature = "dns")]
    pub(crate) dns: crate::agent::dns::AgentDns,
    pub(crate) trie_tx: ArcSwap<TrieTx>,
    pub(crate) trie_rx: ArcSwap<TrieRx>,
    pub(crate) tun_tx: Arc<Sender<(Vec<u8>, Arc<SendHandle>)>>,
    pub(crate) netsody_rx: Arc<Receiver<(Vec<u8>, Arc<SendHandle>)>>,
    pub(crate) config_path: String,
    pub(crate) token_path: String,
    pub(crate) mtu: u16,
    #[allow(dead_code)]
    pub(crate) platform_dependent: Arc<PlatformDependent>,
    #[cfg(any(target_os = "ios", target_os = "android"))]
    pub(crate) last_network_change: Mutex<Option<NetworkChange>>,
    pub(crate) client: Client<HttpsConnector<HttpConnector>, Empty<Bytes>>,
}

impl AgentInner {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: Identity,
        networks: HashMap<Url, Network>,
        cancellation_token: CancellationToken,
        node: Arc<Node>,
        recv_buf_rx: Arc<Receiver<(PubKey, Vec<u8>)>>,
        tun_tx: Arc<Sender<(Vec<u8>, Arc<SendHandle>)>>,
        netsody_rx: Arc<Receiver<(Vec<u8>, Arc<SendHandle>)>>,
        config_path: String,
        token_path: String,
        mtu: u16,
        platform_dependent: Arc<PlatformDependent>,
    ) -> Self {
        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();

        Self {
            id,
            networks: Arc::new(Mutex::new(networks)),
            cancellation_token,
            node,
            recv_buf_rx,
            netif: AgentNetif::new(platform_dependent.clone()),
            firewall: AgentFirewall::new(),
            router: AgentRouter::new(),
            #[cfg(feature = "dns")]
            dns: crate::agent::dns::AgentDns::new(platform_dependent.clone()),
            trie_tx: ArcSwap::new(Arc::new(TrieTx::new())),
            trie_rx: ArcSwap::new(Arc::new(TrieRx::new())),
            tun_tx,
            netsody_rx,
            config_path,
            token_path,
            mtu,
            platform_dependent,
            #[cfg(any(target_os = "ios", target_os = "android"))]
            last_network_change: Mutex::default(),
            client: Client::builder(TokioExecutor::new())
                .pool_max_idle_per_host(0)
                .build::<_, Empty<Bytes>>(https),
        }
    }

    pub(crate) async fn apply_desired_state(
        &self,
        inner: Arc<AgentInner>,
        config_url: &Url,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        self.netif
            .apply_desired_state(inner.clone(), config_url, networks)
            .await;
        // TODO: should we abort of netif state is not Ok?
        self.router
            .apply_desired_state(inner.clone(), config_url, networks)
            .await;
        self.firewall
            .apply_desired_state(inner.clone(), config_url, networks)
            .await;
        #[cfg(feature = "dns")]
        {
            use crate::agent::dns::AgentDnsInterface;
            self.dns
                .apply_desired_state(inner, config_url, networks)
                .await;
        }
    }

    pub(crate) async fn shutdown(&self, inner: Arc<AgentInner>) {
        trace!("Cancel agent token");
        self.cancellation_token.cancel();

        // reset all networks to default state. This will cause the agent to tear down everything
        let mut networks = self.networks.lock().await;

        // collect config URLs first to avoid borrowing conflicts
        let config_urls: Vec<Url> = networks.keys().cloned().collect();

        for config_url in config_urls {
            if let Some(network) = networks.get_mut(&config_url) {
                network.desired_state = AgentState::default();
            }
            self.apply_desired_state(inner.clone(), &config_url, &mut networks)
                .await;
        }
    }

    /// saves the current configuration to file
    pub(crate) async fn save_config(
        &self,
        networks: &MutexGuard<'_, HashMap<Url, Network>>,
    ) -> Result<(), Error> {
        trace!("Saving configuration");

        // load current configuration
        let mut config = AgentConfig::load(&self.config_path)?;

        // update networks from inner state
        config.networks = (*networks).clone();

        // save configuration
        config.save(&self.config_path)
    }
}

pub fn is_netsody_control_packet(buf: &[u8]) -> bool {
    if let Ok(ip_hdr) = Ipv4HeaderSlice::from_slice(buf)
        && ip_hdr.protocol() == etherparse::IpNumber::UDP
    {
        let ip_header_len = ip_hdr.slice().len();
        let udp_header_len = 8;
        let magic_number_len = 4;

        if buf.len() >= ip_header_len + udp_header_len + magic_number_len {
            let payload_start = ip_header_len + udp_header_len;
            return &buf[payload_start..][..magic_number_len]
                == LONG_HEADER_MAGIC_NUMBER.as_bytes();
        }
    }
    false
}
