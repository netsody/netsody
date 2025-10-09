use std::net::Ipv4Addr;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::io::BufWriter;
use tokio::process::Command;

use crate::agent::dns::{AgentDnsInterface, NETSODY_DOMAIN};

const SCUTIL_DNS_KEY: &str = "/Network/Service/Netsody/DNS";
use crate::agent::{AgentInner, PlatformDependent};
use crate::network::{AppliedStatus, Network};
use arc_swap::ArcSwap;
use hickory_resolver::config::*;
use hickory_server::authority::Catalog;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::atomic::AtomicU32;
use tokio::sync::MutexGuard;
use tracing::{trace, warn};
use url::Url;

/// DNS management for macOS systems.
///
/// Manages DNS configuration via scutil and provides embedded DNS server
/// for resolving netsody.me hostnames.
pub struct AgentDns {
    /// Embedded DNS catalog for resolving netsody.me hostnames
    pub(crate) embedded_catalog: ArcSwap<Catalog>,
    /// Currently configured DNS server IP address (as u32 for atomic operations)
    pub(crate) server_ip: AtomicU32,
    /// Upstream DNS servers for forwarding
    upstream_servers: NameServerConfigGroup,
}

impl AgentDns {
    /// Create a new DNS manager instance for macOS.
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
    /// 1. Queries current DNS configuration via scutil
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
        let mut current_dns_ip = match scutil_get_dns_ip().await {
            Ok(dns_ip) => {
                trace!("Current DNS IP: {:?}", dns_ip);
                dns_ip
            }
            Err(e) => {
                warn!("Unable to determine current DNS IP: {}.", e);
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

            if let Err(e) = scutil_remove().await {
                warn!("Unable to revert DNS server IP: {}.", e);
                for (_, network) in networks.iter_mut() {
                    if network.current_state.hostnames.applied.is_some() {
                        network.current_state.hostnames =
                            AppliedStatus::error(format!("Unable to revert DNS server IP: {}", e));
                    }
                }
                return;
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

            // Add the DNS server using scutil
            let domains = vec![NETSODY_DOMAIN];
            if let Err(e) = scutil_add(desired_ip, &domains).await {
                warn!("Unable to set DNS server IP: {}.", e);
                for (_, network) in networks.iter_mut() {
                    if network.current_state.hostnames.applied.is_some() {
                        network.current_state.hostnames =
                            AppliedStatus::error(format!("Unable to set DNS server IP: {}", e));
                    }
                }
                return;
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
            if let Err(e) = macos_flush_caches().await {
                warn!("Unable to flush DNS caches: {}.", e);
            }
        }
    }
}

/// Adds DNS configuration using scutil (macOS).
///
/// # Arguments
/// * `dns_ip` - The DNS server IP address
/// * `domains` - List of domains to add as supplemental match domains
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(String)` with error message on failure
pub(crate) async fn scutil_add(dns_ip: &Ipv4Addr, domains: &[&str]) -> Result<(), String> {
    trace!(
        "Adding DNS configuration with scutil: IP={}, domains={:?}",
        dns_ip, domains
    );

    let mut child = Command::new("scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn scutil: {e}"))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or("Failed to open stdin for scutil".to_string())?;

    let mut writer = BufWriter::new(&mut stdin);

    // Build scutil script
    let mut script = String::new();
    script.push_str("d.init\n");
    script.push_str(&format!("d.add ServerAddresses * {}\n", dns_ip));
    script.push_str(&format!(
        "d.add SupplementalMatchDomains * {}\n",
        domains.join(" ")
    ));
    script.push_str("d.add SupplementalMatchDomainsNoSearch 0\n");
    script.push_str(&format!("set State:{}\n", SCUTIL_DNS_KEY));
    script.push_str("quit\n");

    writer
        .write_all(script.as_bytes())
        .await
        .map_err(|e| format!("Failed to write to scutil stdin: {e}"))?;
    writer
        .flush()
        .await
        .map_err(|e| format!("Failed to flush scutil stdin: {e}"))?;
    drop(writer); // Close stdin so scutil can process input

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("Failed to wait for scutil: {e}"))?;

    if output.status.success() {
        trace!("scutil completed successfully.");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "scutil failed with status {}: {}",
            output.status, stderr
        ))
    }
}

/// Gets the DNS server IP address from the current configuration (macOS).
///
/// # Returns
/// * `Ok(Some(ip))` if DNS server exists and IP could be parsed
/// * `Ok(None)` if DNS server doesn't exist
/// * `Err(String)` with error message on failure
pub(crate) async fn scutil_get_dns_ip() -> Result<Option<Ipv4Addr>, String> {
    trace!("Checking if DNS configuration exists with scutil and getting server IP");

    let mut child = Command::new("scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn scutil: {e}"))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or("Failed to open stdin for scutil".to_string())?;

    let mut writer = BufWriter::new(&mut stdin);

    let script = format!("show State:{}\nquit\n", SCUTIL_DNS_KEY);

    writer
        .write_all(script.as_bytes())
        .await
        .map_err(|e| format!("Failed to write to scutil stdin: {e}"))?;
    writer
        .flush()
        .await
        .map_err(|e| format!("Failed to flush scutil stdin: {e}"))?;

    drop(writer);
    drop(stdin);

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("Failed to wait for scutil: {e}"))?;

    // Check if the key exists by examining the output content
    // scutil returns "No such key" when the key doesn't exist
    let stdout_str = String::from_utf8_lossy(&output.stdout);

    if !output.status.success() || stdout_str.is_empty() || stdout_str.contains("No such key") {
        trace!("DNS configuration does not exist");
        return Ok(None);
    }

    // Parse the server IP address from the output
    // The output format can be either:
    // Format 1: ServerAddresses : * 192.168.1.1
    // Format 2: ServerAddresses : <array> { 0 : 10.13.255.254 }

    for line in stdout_str.lines() {
        if line.contains("ServerAddresses") {
            // Try format 1: ServerAddresses : * IP
            if line.contains("*") {
                if let Some(ip_start) = line.find("*") {
                    let ip_part = &line[ip_start + 1..].trim();
                    if let Ok(ip) = ip_part.parse::<Ipv4Addr>() {
                        trace!("Found DNS server IP (format 1): {}", ip);
                        return Ok(Some(ip));
                    }
                }
            }
            // Try format 2: ServerAddresses : <array> { 0 : IP }
            else if line.contains("<array>") {
                // Look for the next line that contains an IP address
                let lines: Vec<&str> = stdout_str.lines().collect();
                if let Some(current_line_idx) = lines.iter().position(|&l| l == line) {
                    // Check the next few lines for IP address
                    for i in 1..=3 {
                        if let Some(next_line) = lines.get(current_line_idx + i) {
                            let trimmed = next_line.trim();
                            // Look for pattern like "0 : 10.13.255.254"
                            if let Some(colon_pos) = trimmed.find(":") {
                                let ip_part = &trimmed[colon_pos + 1..].trim();
                                if let Ok(ip) = ip_part.parse::<Ipv4Addr>() {
                                    trace!("Found DNS server IP (format 2): {}", ip);
                                    return Ok(Some(ip));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // If we reach here, the key exists but we couldn't parse the IP
    trace!(
        "DNS configuration exists but could not parse server IP from output: {}",
        stdout_str
    );
    Ok(None)
}

pub(crate) async fn scutil_remove() -> Result<(), String> {
    trace!("Removing DNS configuration with scutil");

    let mut child = Command::new("scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn scutil: {e}"))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or("Failed to open stdin for scutil".to_string())?;

    let mut writer = BufWriter::new(&mut stdin);

    let script = format!("remove State:{}\nquit\n", SCUTIL_DNS_KEY);

    writer
        .write_all(script.as_bytes())
        .await
        .map_err(|e| format!("Failed to write to scutil stdin: {e}"))?;
    writer
        .flush()
        .await
        .map_err(|e| format!("Failed to flush scutil stdin: {e}"))?;
    drop(writer); // important: close stdin so scutil can process input

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("Failed to wait for scutil: {e}"))?;

    if output.status.success() {
        trace!("scutil remove completed successfully.");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "scutil remove failed with status {}: {}",
            output.status, stderr
        ))
    }
}

/// Flushes DNS caches on macOS.
///
/// This function runs two commands:
/// 1. `dscacheutil -flushcache` - flushes the Directory Service cache
/// 2. `killall -HUP mDNSResponder` - restarts mDNSResponder to clear its cache
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(String)` with error message on failure
pub(crate) async fn macos_flush_caches() -> Result<(), String> {
    trace!("Flushing DNS caches on macOS");

    // Run dscacheutil -flushcache
    let output = Command::new("dscacheutil")
        .arg("-flushcache")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("Failed to spawn dscacheutil: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "dscacheutil -flushcache failed with status {}: {}",
            output.status, stderr
        ));
    }

    trace!("dscacheutil -flushcache completed successfully");

    // Run killall -HUP mDNSResponder
    let output = Command::new("killall")
        .arg("-HUP")
        .arg("mDNSResponder")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("Failed to spawn killall: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "killall -HUP mDNSResponder failed with status {}: {}",
            output.status, stderr
        ));
    }

    trace!("killall -HUP mDNSResponder completed successfully");
    trace!("DNS caches flushed successfully");

    Ok(())
}
