pub(crate) use crate::agent::Error;
use crate::network::Network;
use crate::network::config::NetworkConfig;
use arc_swap::ArcSwap;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use etherparse::Ipv4HeaderSlice;
use flume::{Receiver, Sender};
use http::Request;
use http_body_util::{BodyExt, Empty};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use p2p::identity::{Identity, PubKey};
use p2p::message::LONG_HEADER_MAGIC_NUMBER;
use p2p::node::{Node, SendHandle};

use crate::agent::AgentConfig;
pub(crate) use crate::agent::network_listener::{NetworkChange, NetworkListener};
use crate::agent::routing::{AgentRouting, AgentRoutingInterface};
use ipnet_trie::IpnetTrie;
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};
use tokio_util::sync::CancellationToken;
use tracing::trace;
use tun_rs::AsyncDevice as TunDevice;
use url::Url;

pub(crate) type TrieRx = IpnetTrie<IpnetTrie<PubKey>>;
pub(crate) type TrieTx = IpnetTrie<IpnetTrie<Arc<SendHandle>>>;

pub struct AgentInner {
    pub(crate) id: Identity,
    pub(crate) networks: Arc<Mutex<HashMap<Url, Network>>>,
    pub(crate) cancellation_token: CancellationToken,
    pub(crate) node: Arc<Node>,
    pub(crate) recv_buf_rx: Arc<Receiver<(PubKey, Vec<u8>)>>,
    pub(crate) tun_device: Arc<TunDevice>,
    pub(crate) routing: AgentRouting,
    #[cfg(feature = "dns")]
    pub(crate) dns: crate::agent::dns::AgentDns,
    pub(crate) trie_tx: ArcSwap<TrieTx>,
    pub(crate) trie_rx: ArcSwap<TrieRx>,
    pub(crate) tun_tx: Arc<Sender<(Vec<u8>, Arc<SendHandle>)>>,
    pub(crate) drasyl_rx: Arc<Receiver<(Vec<u8>, Arc<SendHandle>)>>,
    pub(crate) config_path: String,
    pub(crate) token_path: String,
    pub(crate) mtu: u16,
    pub(crate) network_listener: Option<Arc<NetworkListener>>,
    pub(crate) last_network_change: Mutex<Option<NetworkChange>>,
    client: Client<HttpsConnector<HttpConnector>, Empty<Bytes>>,
}

impl AgentInner {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: Identity,
        networks: HashMap<Url, Network>,
        cancellation_token: CancellationToken,
        node: Arc<Node>,
        recv_buf_rx: Arc<Receiver<(PubKey, Vec<u8>)>>,
        tun_device: Arc<TunDevice>,
        tun_tx: Arc<Sender<(Vec<u8>, Arc<SendHandle>)>>,
        drasyl_rx: Arc<Receiver<(Vec<u8>, Arc<SendHandle>)>>,
        config_path: String,
        token_path: String,
        mtu: u16,
        network_listener: Option<NetworkListener>,
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
            tun_device,
            routing: AgentRouting::new(),
            #[cfg(feature = "dns")]
            dns: crate::agent::dns::AgentDns::new(),
            trie_tx: ArcSwap::new(Arc::new(TrieTx::new())),
            trie_rx: ArcSwap::new(Arc::new(TrieRx::new())),
            tun_tx,
            drasyl_rx,
            config_path,
            token_path,
            mtu,
            network_listener: network_listener.map(Arc::new),
            last_network_change: Mutex::default(),
            client: Client::builder(TokioExecutor::new())
                .pool_max_idle_per_host(0)
                .build::<_, Empty<Bytes>>(https),
        }
    }

    pub(crate) async fn fetch_network_config(&self, url: &str) -> Result<NetworkConfig, Error> {
        trace!("Fetching network config from: {}", url);

        let body = match url {
            url if url.starts_with("http://") || url.starts_with("https://") => {
                self.fetch_with_redirects(url).await?
            }
            url if url.starts_with("file://") => {
                // Handle file:// URLs properly, especially on Windows
                let path_part = url.strip_prefix("file://").unwrap();
                let path = if cfg!(target_os = "windows")
                    && path_part.starts_with('/')
                    && path_part.len() > 2
                {
                    // Remove the leading slash and ensure proper Windows path format
                    // e.g., file:///C:/path becomes /C:/path, which needs to be C:/path
                    &path_part[1..]
                } else {
                    path_part
                };
                trace!("Reading file: {}", path);
                fs::read_to_string(path)?
            }
            _ => {
                return Err(Error::ConfigParseError {
                    reason: format!("Unsupported URL scheme: {url}"),
                });
            }
        };
        Ok(NetworkConfig::try_from(body.as_str())?)
    }

    async fn fetch_with_redirects(&self, url: &str) -> Result<String, Error> {
        let mut current_url = url.to_string();
        let mut redirect_count = 0;
        const MAX_REDIRECTS: usize = 5;

        loop {
            if redirect_count >= MAX_REDIRECTS {
                return Err(Error::ConfigParseError {
                    reason: format!("Too many redirects (max {MAX_REDIRECTS}): {url}"),
                });
            }

            // parse URL and extract auth info if present
            let parsed_url = url::Url::parse(&current_url)?;
            trace!("Parsed URL: {}", parsed_url);
            let mut request = Request::builder()
                .uri(parsed_url.as_str())
                .method("GET")
                .header("Connection", "close")
                .header("drasyl-pk", self.id.pk.to_string());

            // add basic auth header if username and password are present
            let username = parsed_url.username();
            let password = parsed_url.password();
            if !username.is_empty() && password.is_some() {
                trace!("Adding basic auth header: {}", username);
                let auth = BASE64.encode(format!("{}:{}", username, password.unwrap()));
                request = request.header("Authorization", format!("Basic {auth}"));
            }

            trace!("Building request");
            let request = request.body(Empty::new())?;
            trace!("Sending request");
            let response = self.client.request(request).await?;
            trace!("Received response");

            let status = response.status();

            // Handle redirects
            if status.is_redirection()
                && let Some(location) = response.headers().get("Location")
                && let Ok(location_str) = location.to_str()
            {
                redirect_count += 1;
                trace!(
                    "Following redirect {}: {} -> {}",
                    redirect_count, current_url, location_str
                );

                // Handle relative URLs
                if location_str.starts_with("http://") || location_str.starts_with("https://") {
                    current_url = location_str.to_string();
                } else {
                    // Resolve relative URL
                    let base_url = url::Url::parse(&current_url)?;
                    let redirect_url = base_url.join(location_str)?;
                    current_url = redirect_url.to_string();
                }
                continue;
            }

            // Check for success
            if !status.is_success() {
                return Err(Error::ConfigParseError {
                    reason: format!(
                        "HTTP request failed with status {}: {}",
                        status,
                        status.canonical_reason().unwrap_or("Unknown")
                    ),
                });
            }

            let body_bytes = response.into_body().collect().await?.to_bytes();
            trace!("Received body");
            return Ok(String::from_utf8(body_bytes.to_vec())?);
        }
    }

    pub(crate) async fn shutdown(&self) {
        trace!("Cancel agent token");
        self.cancellation_token.cancel();

        trace!("Shutdown routing");
        self.routing
            .shutdown(self.networks.clone(), self.tun_device.clone())
            .await;

        #[cfg(feature = "dns")]
        {
            use crate::agent::dns::AgentDnsInterface;

            trace!("Shutdown DNS");
            self.dns.shutdown().await;
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

pub fn is_drasyl_control_packet(buf: &[u8]) -> bool {
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
