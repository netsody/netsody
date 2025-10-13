use std::net::Ipv4Addr;
use std::process::Stdio;
use tokio::process::Command;

use crate::agent::dns::{AgentDnsInterface, NETSODY_DOMAIN};

use crate::agent::{AgentInner, PlatformDependent};
use crate::network::{AppliedStatus, Network};
use arc_swap::ArcSwap;
use hickory_resolver::config::NameServerConfigGroup;
use hickory_server::authority::Catalog;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering::SeqCst;
use tokio::sync::MutexGuard;
use tracing::{trace, warn};
use url::Url;
use windows::Win32::System::GroupPolicy::RefreshPolicyEx;
use windows_registry::LOCAL_MACHINE;

pub struct AgentDns {
    /// Embedded DNS catalog for resolving netsody.me hostnames
    pub(crate) embedded_catalog: ArcSwap<Catalog>,
    /// Currently configured DNS server IP address (as u32 for atomic operations)
    pub(crate) server_ip: AtomicU32,
    /// Upstream DNS servers for forwarding
    upstream_servers: NameServerConfigGroup,
}

impl AgentDns {
    /// Create a new DNS manager instance for Windows.
    ///
    /// # Arguments
    /// * `platform_dependent` - Platform-specific dependencies
    ///
    /// # Returns
    /// Initialized AgentDns instance
    #[allow(unused_variables)]
    pub(crate) async fn new(platform_dependent: Arc<PlatformDependent>) -> Self {
        Self {
            embedded_catalog: ArcSwap::from_pointee(Catalog::new()),
            server_ip: AtomicU32::default(),
            upstream_servers: NameServerConfigGroup::new(),
        }
    }
}

impl AgentDnsInterface for AgentDns {
    /// Apply desired DNS state for all configured networks.
    ///
    /// This method:
    /// 1. Queries current DNS configuration via registry
    /// 2. Calculates desired DNS IP from enabled networks
    /// 3. Updates DNS server configuration if needed
    /// 4. Updates hostname mappings in embedded DNS catalog
    /// 5. Flushes DNS caches when changes are made
    async fn apply_desired_state(
        &self,
        _inner: Arc<AgentInner>,
        _config_url: &Url,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        // Get current DNS configuration
        let mut current_dns_ip = match dns_policy_get_ip() {
            Ok(dns_ip) => {
                trace!("Current DNS IP: {:?}", dns_ip);
                dns_ip
            }
            Err(e) => {
                warn!("Unable to determine current DNS IP: {}", e);
                for (_, network) in networks.iter_mut() {
                    if network.current_state.hostnames.applied.is_some() {
                        network.current_state.hostnames = AppliedStatus::error(format!(
                            "Unable to determine current DNS IP: {}",
                            e
                        ));
                    }
                }
                return;
            }
        };

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

        // Remove current DNS server if it doesn't match desired state
        if let Some(current_ip) = current_dns_ip
            && Some(&current_ip) != desired_dns_ip
        {
            trace!(
                "Removing DNS server because current IP is not in desired state: current_ip={:?}, desired_ip={:?}",
                current_ip, desired_dns_ip
            );

            if let Err(e) = dns_policy_remove() {
                warn!("Unable to remove DNS server from registry: {}.", e);
                for (_, network) in networks.iter_mut() {
                    if network.current_state.hostnames.applied.is_some() {
                        network.current_state.hostnames = AppliedStatus::error(format!(
                            "Unable to remove DNS server from registry: {}",
                            e
                        ));
                    }
                }
                return;
            }

            // Refresh DNS policies to apply changes
            if let Err(e) = dns_policies_refresh() {
                warn!("Unable to refresh DNS policies: {}.", e);
            }

            trace!("Successfully removed DNS server.");
            current_dns_ip = None;
            self.server_ip.store(0, SeqCst);
        }

        // Add DNS server if desired state requires it
        if let Some(desired_ip) = desired_dns_ip
            && current_dns_ip != Some(*desired_ip)
        {
            trace!("We need to set DNS server to {:?}.", desired_ip);

            // Configure DNS server in Windows registry
            if let Err(e) = dns_policy_add(*desired_ip) {
                warn!("Unable to set DNS server in registry: {}.", e);
                for (_, network) in networks.iter_mut() {
                    if network.current_state.hostnames.applied.is_some() {
                        network.current_state.hostnames = AppliedStatus::error(format!(
                            "Unable to set DNS server in registry: {}",
                            e
                        ));
                    }
                }
                return;
            }

            // Refresh DNS policies to apply changes
            if let Err(e) = dns_policies_refresh() {
                warn!("Unable to refresh DNS policies: {}.", e);
            }

            trace!("Successfully set DNS server to {:?}.", desired_ip);
            self.server_ip.store(desired_ip.to_bits(), SeqCst);
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

            // Flush DNS caches after updating entries
            if let Err(e) = dns_flush_cache().await {
                warn!("Unable to flush DNS caches: {}.", e);
            }
        }
    }
}

/// Read the currently configured DNS server IP from the Windows registry
///
/// # Returns
/// * `Ok(Some(ip))` if DNS server exists and IP could be parsed
/// * `Ok(None)` if DNS server doesn't exist
/// * `Err(String)` with error message on failure
fn dns_policy_get_ip() -> Result<Option<Ipv4Addr>, String> {
    trace!("Checking if DNS configuration exists in registry and getting server IP");

    // Create the same key path used for writing
    let key_name = "Netsody-Rule-0";
    let base_path = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
    let full_path = format!(r"{}\{}", base_path, key_name);

    // Try to open the registry key
    let key = match LOCAL_MACHINE.open(&full_path) {
        Ok(k) => k,
        Err(e) => {
            trace!("DNS configuration does not exist: {}", e);
            return Ok(None);
        }
    };

    // Try to read the GenericDNSServers value
    let dns_server_str: String = key
        .get_string("GenericDNSServers")
        .map_err(|e| format!("Failed to read GenericDNSServers from registry: {}", e))?;

    // Parse the IP address string
    let ip = dns_server_str
        .parse::<Ipv4Addr>()
        .map_err(|e| format!("Failed to parse DNS server IP '{}': {}", dns_server_str, e))?;

    trace!("Found DNS server IP: {}", ip);
    Ok(Some(ip))
}

/// Add a DNS server entry to the Windows registry for domain-specific DNS resolution
///
/// # Arguments
/// * `dns_ip` - The IP address of the DNS server to configure
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(String)` with error message on failure
fn dns_policy_add(dns_ip: Ipv4Addr) -> Result<(), String> {
    trace!("Adding DNS configuration to registry: IP={}", dns_ip);

    // Create the key name
    let key_name = "Netsody-Rule-0";
    let base_path = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
    let full_path = format!(r"{}\{}", base_path, key_name);

    // Open or create the registry key
    let key = LOCAL_MACHINE
        .create(&full_path)
        .map_err(|e| format!("Failed to create registry key: {}", e))?;

    // Set Version (DWORD) = 2
    key.set_u32("Version", 2)
        .map_err(|e| format!("Failed to set Version: {}", e))?;

    // Set Name (REG_MULTI_SZ) = [".netsody.me"]
    let domain_with_dot = format!(".{}", NETSODY_DOMAIN);
    key.set_multi_string("Name", &[domain_with_dot.as_str()])
        .map_err(|e| format!("Failed to set Name: {}", e))?;

    // Set GenericDNSServers (string) = IP address
    key.set_string("GenericDNSServers", &dns_ip.to_string())
        .map_err(|e| format!("Failed to set GenericDNSServers: {}", e))?;

    // Set ConfigOptions (DWORD) = 0x8
    key.set_u32("ConfigOptions", 0x8)
        .map_err(|e| format!("Failed to set ConfigOptions: {}", e))?;

    // Set Comment (REG_SZ) = "Managed by Netsody"
    key.set_string("Comment", "Managed by Netsody")
        .map_err(|e| format!("Failed to set Comment: {}", e))?;

    // Set DisplayName (REG_SZ) = empty string
    key.set_string("DisplayName", "")
        .map_err(|e| format!("Failed to set DisplayName: {}", e))?;

    // Set IPSECCARestriction (REG_SZ) = empty string
    key.set_string("IPSECCARestriction", "")
        .map_err(|e| format!("Failed to set IPSECCARestriction: {}", e))?;

    trace!("Registry configuration completed successfully");
    Ok(())
}

/// Remove the DNS server entry from the Windows registry
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(String)` with error message on failure
fn dns_policy_remove() -> Result<(), String> {
    trace!("Removing DNS configuration from registry");

    // Create the same key path
    let key_name = "Netsody-Rule-0";
    let base_path = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";

    // Open the parent key
    let parent_key = LOCAL_MACHINE
        .open(base_path)
        .map_err(|e| format!("Failed to open registry key: {}", e))?;

    // Delete the subkey
    parent_key
        .remove_tree(&key_name)
        .map_err(|e| format!("Failed to remove registry key: {}", e))?;

    trace!("Registry remove completed successfully");
    Ok(())
}

/// Refreshes DNS policies on Windows
///
/// This function forces a refresh of computer group policies to ensure
/// DNS policy changes take effect immediately.
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(String)` with error message on failure
fn dns_policies_refresh() -> Result<(), String> {
    trace!("Refreshing DNS policies");

    unsafe {
        // bMachine = TRUE (Computer Policies)
        // dwOptions = 0x1 (RP_FORCE → forces full reload)
        match RefreshPolicyEx(true, 0x1) {
            Ok(_) => {
                trace!("DNS policy refresh successful");
                Ok(())
            }
            Err(e) => Err(format!("DNS policy refresh failed: {}", e)),
        }
    }
}

/// Flushes DNS caches on Windows.
///
/// This function runs `ipconfig /flushdns` to clear the DNS resolver cache.
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(String)` with error message on failure
async fn dns_flush_cache() -> Result<(), String> {
    trace!("Flushing DNS caches on Windows");

    // Run ipconfig /flushdns
    let output = Command::new("ipconfig")
        .arg("/flushdns")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("Failed to spawn ipconfig: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "ipconfig /flushdns failed with status {}: {}",
            output.status, stderr
        ));
    }

    trace!("ipconfig /flushdns completed successfully");
    trace!("DNS cache flush successful");

    Ok(())
}
