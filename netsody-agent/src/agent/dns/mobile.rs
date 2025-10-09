use crate::agent::dns::AgentDnsInterface;
use crate::agent::housekeeping::HOUSEKEEPING_INTERVAL_MS;
use crate::agent::{AgentInner, PlatformDependent};
use crate::network::{AppliedStatus, Network};
use arc_swap::ArcSwap;
use etherparse::PacketBuilder;
use hickory_proto::ProtoError;
use hickory_proto::op::{Header, MessageType, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};
use hickory_proto::xfer::Protocol;
use hickory_resolver::config::*;
use hickory_server::authority::{Authority, Catalog, MessageRequest, MessageResponse, ZoneType};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::store::in_memory::InMemoryAuthority;
use std::collections::HashMap;
use std::io;
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::atomic::{AtomicBool, AtomicU32};
use tokio::sync::MutexGuard;
use tracing::{Level, debug, enabled, error, instrument, trace};
use tun_rs::AsyncDevice;
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
        config_url: &Url,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    ) {
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
