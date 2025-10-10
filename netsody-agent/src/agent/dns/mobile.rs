use crate::agent::dns::AgentDnsInterface;
use crate::agent::{AgentInner, PlatformDependent};
use crate::network::Network;
use arc_swap::ArcSwap;
#[cfg(target_os = "android")]
use hickory_proto::xfer::Protocol;
#[cfg(target_os = "android")]
use hickory_resolver::config::NameServerConfig;
use hickory_resolver::config::NameServerConfigGroup;
use hickory_server::authority::Catalog;
use std::collections::HashMap;
use std::net::Ipv4Addr;
#[cfg(target_os = "android")]
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
use tokio::sync::MutexGuard;
use tracing::trace;
use url::Url;

/// DNS management for mobile platforms (iOS, tvOS, Android).
///
/// Provides embedded DNS server for resolving netsody.me hostnames
/// with optional upstream forwarding on Android.
pub struct AgentDns {
    /// Embedded DNS catalog for resolving netsody.me hostnames
    pub(crate) embedded_catalog: ArcSwap<Catalog>,
    /// Currently configured DNS server IP address (as u32 for atomic operations)
    pub(crate) server_ip: AtomicU32,
    /// Upstream DNS servers for forwarding (Android only)
    upstream_servers: NameServerConfigGroup,
}

impl AgentDns {
    /// Create a new DNS manager instance for mobile platforms.
    ///
    /// On Android, this initializes upstream DNS forwarding using the provided
    /// DNS servers from the platform. On iOS/tvOS, only the embedded DNS server
    /// is used.
    ///
    /// # Arguments
    /// * `platform_dependent` - Platform-specific dependencies including DNS servers
    ///
    /// # Returns
    /// Initialized AgentDns instance
    #[allow(unused_variables)]
    pub(crate) async fn new(platform_dependent: Arc<PlatformDependent>) -> Self {
        #[cfg(target_os = "android")]
        trace!(
            "Initializing DNS with upstream servers: {:?}",
            platform_dependent.dns_servers
        );
        let upstream_servers = {
            #[cfg(target_os = "android")]
            {
                NameServerConfigGroup::from(
                    platform_dependent
                        .dns_servers
                        .iter()
                        .map(|&ip| NameServerConfig::new(SocketAddr::from((ip, 53)), Protocol::Udp))
                        .collect::<Vec<_>>(),
                )
            }
            #[cfg(not(target_os = "android"))]
            {
                NameServerConfigGroup::new()
            }
        };

        Self {
            embedded_catalog: ArcSwap::from_pointee(Catalog::new()),
            server_ip: AtomicU32::default(),
            upstream_servers,
        }
    }
}

impl AgentDnsInterface for AgentDns {
    /// Apply desired DNS state for all configured networks.
    ///
    /// On mobile platforms, DNS is managed by the OS, so this only updates
    /// the embedded DNS catalog with hostname mappings.
    async fn apply_desired_state(
        &self,
        _inner: Arc<AgentInner>,
        _config_url: &Url,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        // Calculate desired DNS IP from enabled networks
        let network_dns_ips: Vec<Ipv4Addr> = networks
            .values()
            .filter(|network| !network.disabled)
            .filter_map(|network| network.current_state.ip.applied)
            .map(|network_ip| {
                let broadcast = network_ip.broadcast();
                // DNS server IP is the broadcast address minus 1
                Ipv4Addr::from(u32::from(broadcast).saturating_sub(1))
            })
            .collect();
        let desired_dns_ip = network_dns_ips.first();

        // Update DNS server IP if changed
        let current_ip_bits = self.server_ip.load(SeqCst);
        let current_ip = if current_ip_bits == 0 {
            None
        } else {
            Some(Ipv4Addr::from(current_ip_bits))
        };

        if current_ip != desired_dns_ip.copied() {
            trace!(
                "DNS server IP changed: {:?} -> {:?}",
                current_ip, desired_dns_ip
            );
            self.server_ip
                .store(desired_dns_ip.map(|ip| ip.to_bits()).unwrap_or(0), SeqCst);
        }

        // Check if hostname mappings need to be updated
        let mut update_hostnames = false;
        for (_, network) in networks.iter_mut() {
            if network.current_state.hostnames != network.desired_state.hostnames {
                trace!(
                    "DNS hostnames mismatch: current={:?} desired={:?}",
                    &network.current_state.hostnames, network.desired_state.hostnames
                );
                update_hostnames = true;
                break;
            }
        }
        if !update_hostnames {
            trace!("All DNS hostnames up to date");
        } else {
            trace!("Update hostnames in DNS");
            // Update DNS catalog with new hostname mappings
            self.embedded_catalog.store(Arc::new(
                self.build_catalog(networks, &self.upstream_servers),
            ));

            for (_, network) in networks.iter_mut() {
                network.current_state.hostnames = network.desired_state.hostnames.clone();
            }
        }
    }
}
