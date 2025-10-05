use crate::agent::Error;
use crate::agent::inner::AgentInner;
use crate::network::{AgentState, AgentStateStatus, AppliedStatus, Network, NetworkConfig};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use http::Request;
use http_body_util::BodyExt;
use http_body_util::Empty;
use ipnet::Ipv4Net;
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::MutexGuard;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{error, instrument, trace, warn};
use url::Url;

/// Timeout in milliseconds for retrieving network config.
/// If a config cannot be received within this time, the retrieval is considered failed.
pub(crate) const CONFIG_RETRIEVE_TIMEOUT: u64 = 5_000;

/// Housekeeping interval in milliseconds.
pub(crate) const HOUSEKEEPING_INTERVAL_MS: u64 = 10_000;

impl AgentInner {
    pub(crate) async fn housekeeping_runner(
        inner: Arc<AgentInner>,
        housekeeping_shutdown: CancellationToken,
    ) -> Result<(), String> {
        let mut interval = tokio::time::interval(Duration::from_millis(HOUSEKEEPING_INTERVAL_MS));

        loop {
            tokio::select! {
                biased;
                _ = housekeeping_shutdown.cancelled() => {
                    trace!("Housekeeping runner cancelled");
                    break
                },
                _ = interval.tick() => {
                    if let Err(e) = inner.housekeeping(&inner).await {
                        error!("Error in housekeeping: {e}");
                    }
                }
            }
        }

        trace!("Housekeeping runner finished");
        Ok(())
    }

    async fn housekeeping(&self, inner: &Arc<AgentInner>) -> Result<(), Error> {
        trace!("Locking networks to get network keys");
        let urls: Vec<Url> = {
            let networks = inner.networks.lock().await;
            networks.keys().cloned().collect()
        };
        trace!("Got network keys");

        trace!("Locking networks for housekeeping");
        let mut networks = self.networks.lock().await;
        for url in urls {
            self.housekeeping_network(inner.clone(), url, &mut networks)
                .await;
        }
        trace!("Finished housekeeping");

        #[cfg(any(target_os = "ios", target_os = "tvos", target_os = "android"))]
        {
            // ensure network listener is fired on network changes
            self.notify_on_network_change(&networks, inner.clone())
                .await;
        }

        Ok(())
    }

    #[instrument(fields(network = %config_url), skip_all)]
    async fn housekeeping_network(
        &self,
        inner: Arc<AgentInner>,
        config_url: Url,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        let mut save_config = false;
        if let Some(network) = networks.get_mut(&config_url) {
            let mut new_status = None;

            // retrieve network config to get (new) desired state
            match timeout(
                Duration::from_millis(CONFIG_RETRIEVE_TIMEOUT),
                self.retrieve_network_config(network.config_url.as_str()),
            )
            .await
            {
                Ok(Ok(config)) => {
                    trace!("Network config retrieved successfully");

                    // update network name from config
                    if let (Some(new_name), Some(old_name)) = (
                        config.name.as_ref().filter(|s| !s.trim().is_empty()),
                        network.name.as_ref(),
                    ) && new_name != old_name
                    {
                        trace!(
                            "Network name changed from '{:?}' to '{:?}'",
                            network.name, config.name
                        );

                        save_config = true;
                    }
                    network.name = config.name.clone();

                    // create the desired state
                    network.desired_state = if network.disabled {
                        trace!("Network is disabled. We need to teardown everything.");
                        new_status = Some(AgentStateStatus::Disabled);
                        AgentState::default()
                    } else {
                        match config.ip(&inner.id.pk) {
                            Some(desired_ip) => {
                                let desired_effective_access_rule_list = config
                                    .effective_access_rule_list(&inner.id.pk)
                                    .expect("Failed to get effective access rule");
                                let desired_effective_routing_list = config
                                    .effective_routing_list(&inner.id.pk)
                                    .expect("Failed to get effective routing list");
                                #[cfg(feature = "dns")]
                                let desired_hostnames = config.hostnames(&inner.id.pk);
                                let desired_forwarding = config.is_gateway(&inner.id.pk);
                                AgentState {
                                    ip: AppliedStatus::applied(
                                        Ipv4Net::new(desired_ip, config.subnet.prefix_len())
                                            .unwrap(),
                                    ),
                                    access_rules: AppliedStatus::applied(
                                        desired_effective_access_rule_list,
                                    ),
                                    routes: AppliedStatus::applied(desired_effective_routing_list),
                                    #[cfg(feature = "dns")]
                                    hostnames: AppliedStatus::applied(desired_hostnames),
                                    forwarding: AppliedStatus::applied(desired_forwarding),
                                }
                            }
                            None => {
                                trace!("I'm not member of this network.");
                                new_status = Some(AgentStateStatus::NotAMemberError);
                                AgentState::default()
                            }
                        }
                    };
                }
                Ok(Err(e)) => {
                    warn!("Failed to retrieve network config: {}", e);
                    new_status = Some(AgentStateStatus::RetrieveConfigError(format!("{}", e)));
                }
                Err(_) => {
                    warn!(
                        "Timeout of {} ms exceeded while attempting to retrieve network config",
                        CONFIG_RETRIEVE_TIMEOUT
                    );
                    new_status = Some(AgentStateStatus::RetrieveConfigError(format!(
                        "Timeout of {} ms exceeded while attempting to retrieve network config",
                        CONFIG_RETRIEVE_TIMEOUT
                    )));
                }
            }

            // update network state to be aligned with desired state
            self.apply_desired_state(inner.clone(), &config_url, networks)
                .await;

            if let Some(network) = networks.get_mut(&config_url) {
                if let Some(new_status) = new_status {
                    network.status = new_status;
                } else if network.current_state == network.desired_state {
                    network.status = AgentStateStatus::Ok;
                } else {
                    network.status = AgentStateStatus::Pending;
                }
            }
        }

        if save_config {
            // persist configuration
            self.save_config(networks)
                .await
                .expect("Failed to save config");
        }
    }

    pub(crate) async fn retrieve_network_config(&self, url: &str) -> Result<NetworkConfig, Error> {
        trace!("Retrieving network config from: {}", url);

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
                .header("netsody-pk", self.id.pk.to_string());

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
                    reason: format!("HTTP request failed with status '{}'", status,),
                });
            }

            let body_bytes = response.into_body().collect().await?.to_bytes();
            trace!("Received body");
            return Ok(String::from_utf8(body_bytes.to_vec())?);
        }
    }
}
