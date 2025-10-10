use crate::agent::dns::NETSODY_DOMAIN;
use crate::agent::dns::NETSODY_INTERFACE_NAME;
use libc::{AF_INET, if_nametoindex};
use std::ffi::CString;
use std::net::Ipv4Addr;
use tracing::trace;
use zbus::{Connection, proxy};

/// D-Bus proxy for checking if systemd-resolved is available
#[proxy(
    interface = "org.freedesktop.DBus.Peer",
    default_path = "/org/freedesktop/resolve1",
    default_service = "org.freedesktop.resolve1"
)]
trait Peer {
    fn ping(&self) -> zbus::Result<()>;
}

/// D-Bus proxy for systemd-resolved Manager interface
#[proxy(
    interface = "org.freedesktop.resolve1.Manager",
    default_path = "/org/freedesktop/resolve1",
    default_service = "org.freedesktop.resolve1"
)]
trait Manager {
    #[zbus(property, name = "DNSStubListener")]
    fn dns_stub_listener(&self) -> zbus::Result<String>;

    fn flush_caches(&self) -> zbus::Result<()>;

    /// Set DNS servers for a given network link.
    ///
    /// D-Bus signature: `ia(iay)`
    /// - `ifindex`: Interface index (as returned by `ip link` or `resolvectl status`)
    /// - `addresses`: Array of tuples `(address_family, address_bytes)`
    #[zbus(name = "SetLinkDNS")]
    fn set_link_dns(&self, ifindex: i32, addresses: Vec<(i32, Vec<u8>)>) -> zbus::Result<()>;

    /// Reverts any per-link configuration (DNS servers, domains, DNSSEC, etc.)
    /// previously set via the Manager API or resolvectl.
    ///
    /// D-Bus signature: `(i)`
    fn revert_link(&self, ifindex: i32) -> zbus::Result<()>;

    /// Sets routing or search domains for a given link.
    ///
    /// D-Bus signature: `ia(sb)`
    /// Each tuple consists of:
    /// - `s`: domain name (e.g., `"netsody.me"`)
    /// - `b`: routing domain flag (`true` = routing domain `~example.com`,
    ///                            `false` = search domain `example.com`)
    fn set_link_domains(&self, ifindex: i32, domains: Vec<(String, bool)>) -> zbus::Result<()>;

    /// Returns the object path for the given network interface index.
    fn get_link(&self, ifindex: i32) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
}

/// D-Bus proxy for systemd-resolved Link interface
#[proxy(
    interface = "org.freedesktop.resolve1.Link",
    default_service = "org.freedesktop.resolve1"
)]
trait Link {
    #[zbus(property, name = "DNS")]
    fn dns(&self) -> zbus::Result<Vec<(i32, Vec<u8>)>>;

    #[zbus(property)]
    fn domains(&self) -> zbus::Result<Vec<(String, bool)>>;

    /// Set DNS servers for this link.
    ///
    /// D-Bus signature: `a(iay)`
    /// - `addresses`: Array of tuples `(address_family, address_bytes)`
    #[zbus(name = "SetDNS")]
    fn set_dns(&self, addresses: Vec<(i32, Vec<u8>)>) -> zbus::Result<()>;

    /// Set routing or search domains for this link.
    ///
    /// D-Bus signature: `a(sb)`
    /// Each tuple consists of:
    /// - `s`: domain name (e.g., `"netsody.me"`)
    /// - `b`: routing domain flag (`true` = routing domain `~example.com`,
    ///                            `false` = search domain `example.com`)
    #[zbus(name = "SetDomains")]
    fn set_domains(&self, domains: Vec<(String, bool)>) -> zbus::Result<()>;
}

/// Check if systemd-resolved is available on the system.
///
/// # Returns
/// * `Ok(true)` - systemd-resolved is available
/// * `Ok(false)` - systemd-resolved is not available
/// * `Err(String)` - Error occurred while checking
pub async fn systemd_resolved_available() -> Result<bool, String> {
    trace!("systemd_resolved_available: checking if systemd-resolved is available");
    let connection = Connection::system()
        .await
        .map_err(|e| format!("Failed to connect to system bus: {e}"))?;
    trace!("systemd_resolved_available: connected to system bus");
    let peer = PeerProxy::new(&connection)
        .await
        .map_err(|e| format!("Failed to create proxy: {e}"))?;
    trace!("systemd_resolved_available: created peer proxy");
    peer.ping()
        .await
        .map_err(|e| format!("Failed to call method: {e}"))?;
    trace!("systemd_resolved_available: systemd-resolved is available");
    Ok(true)
}

/// Check if the systemd-resolved DNS stub listener is enabled.
///
/// # Returns
/// * `Ok(true)` - Stub listener is enabled
/// * `Ok(false)` - Stub listener is disabled
/// * `Err(String)` - Error occurred while checking
pub async fn systemd_resolved_dns_stub_listener() -> Result<bool, String> {
    trace!("systemd_resolved_dns_stub_listener: getting current DNS stub listener state");
    let connection = Connection::system()
        .await
        .map_err(|e| format!("Failed to connect to system bus: {e}"))?;
    trace!("systemd_resolved_dns_stub_listener: connected to system bus");
    let manager = ManagerProxy::new(&connection)
        .await
        .map_err(|e| format!("Failed to create ManagerProxy: {e}"))?;
    trace!("systemd_resolved_dns_stub_listener: created manager proxy");
    let stub_active = manager
        .dns_stub_listener()
        .await
        .map_err(|e| format!("Failed to call dns_stub_listener: {e}"))?;
    trace!(
        "systemd_resolved_dns_stub_listener: got stub_active={}",
        stub_active
    );
    Ok(stub_active == "yes")
}

/// Flush DNS caches in systemd-resolved.
///
/// # Returns
/// * `Ok(())` - Successfully flushed caches
/// * `Err(String)` - Error occurred while flushing
pub async fn systemd_resolved_flush_caches() -> Result<(), String> {
    trace!("systemd_resolved_flush_caches: flushing DNS caches");
    let connection = Connection::system()
        .await
        .map_err(|e| format!("Failed to connect to system bus: {e}"))?;
    trace!("systemd_resolved_flush_caches: connected to system bus");
    let manager = ManagerProxy::new(&connection)
        .await
        .map_err(|e| format!("Failed to create ManagerProxy: {e}"))?;
    trace!("systemd_resolved_flush_caches: created manager proxy");
    manager
        .flush_caches()
        .await
        .map_err(|e| format!("Failed to call flush_caches: {e}"))?;
    trace!("systemd_resolved_flush_caches: DNS caches flushed");
    Ok(())
}

/// Get the current DNS IP configuration for the netsody interface.
///
/// # Returns
/// * `Ok(Some(ip))` - DNS server IP is configured for the interface
/// * `Ok(None)` - No DNS server is configured for the interface
/// * `Err(String)` - Error occurred while querying the configuration
pub async fn systemd_resolved_dns_ip() -> Result<Option<Ipv4Addr>, String> {
    trace!("systemd_resolved_dns_ip: getting current DNS IP configuration");
    let ifindex = match get_interface_index() {
        Ok(idx) => idx,
        Err(_) => {
            trace!("systemd_resolved_dns_ip: interface not found, returning None");
            return Ok(None);
        }
    };
    trace!("systemd_resolved_dns_ip: got ifindex={}", ifindex);

    let connection = Connection::system()
        .await
        .map_err(|e| format!("Failed to connect to system bus: {e}"))?;
    trace!("systemd_resolved_dns_ip: connected to system bus");
    let manager = ManagerProxy::new(&connection)
        .await
        .map_err(|e| format!("Failed to create ManagerProxy: {e}"))?;
    trace!("systemd_resolved_dns_ip: created manager proxy");

    let path = manager
        .get_link(ifindex)
        .await
        .map_err(|e| format!("Failed to call get_link: {e}"))?;
    trace!("systemd_resolved_dns_ip: got link path: {:?}", path);
    let builder = LinkProxy::builder(&connection)
        .path(path)
        .map_err(|e| format!("Failed to build link path: {e}"))?;
    let link = builder
        .build()
        .await
        .map_err(|e| format!("Failed to create LinkProxy: {e}"))?;
    trace!("systemd_resolved_dns_ip: created link proxy");

    // Define desired values
    let desired_domains = vec![(NETSODY_DOMAIN.to_string(), true)];

    // Get current values
    let current_dns = link
        .dns()
        .await
        .map_err(|e| format!("Failed to call dns: {e}"))?;
    trace!("systemd_resolved_dns_ip: current DNS: {:?}", current_dns);
    let current_domains = link
        .domains()
        .await
        .map_err(|e| format!("Failed to call domains: {e}"))?;
    trace!(
        "systemd_resolved_dns_ip: current domains: {:?}",
        current_domains
    );

    if let Some((family, addr)) = current_dns.first() {
        if *family == AF_INET && current_domains == desired_domains {
            if addr.len() == 4 {
                let ipv4 = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
                trace!("systemd_resolved_dns_ip: found configured DNS IP: {}", ipv4);
                Ok(Some(ipv4))
            } else {
                trace!("systemd_resolved_dns_ip: address length mismatch");
                Ok(None)
            }
        } else {
            trace!("systemd_resolved_dns_ip: family or domains mismatch");
            Ok(None)
        }
    } else {
        trace!("systemd_resolved_dns_ip: no DNS configured");
        Ok(None)
    }
}

/// Revert DNS configuration for the netsody interface.
///
/// This removes any DNS servers and domains previously configured via systemd-resolved.
///
/// # Returns
/// * `Ok(())` - Successfully reverted DNS configuration
/// * `Err(String)` - Error occurred while reverting
pub async fn systemd_resolved_revert() -> Result<(), String> {
    trace!("systemd_resolved_revert: reverting DNS configuration");
    let ifindex = get_interface_index()?;
    trace!("systemd_resolved_revert: got ifindex={}", ifindex);

    let connection = Connection::system()
        .await
        .map_err(|e| format!("Failed to connect to system bus: {e}"))?;
    trace!("systemd_resolved_revert: connected to system bus");
    let manager = ManagerProxy::new(&connection)
        .await
        .map_err(|e| format!("Failed to create ManagerProxy: {e}"))?;
    trace!("systemd_resolved_revert: created manager proxy");

    manager
        .revert_link(ifindex)
        .await
        .map_err(|e| format!("Failed to call revert_link: {e}"))?;
    trace!("systemd_resolved_revert: DNS configuration reverted");

    Ok(())
}

/// Set DNS server IP for the netsody interface via systemd-resolved.
///
/// # Arguments
/// * `dns_ip` - The DNS server IP address to configure
///
/// # Returns
/// * `Ok(())` - Successfully set DNS IP
/// * `Err(String)` - Error occurred while setting DNS IP
pub async fn systemd_resolved_set_dns_ip(dns_ip: &Ipv4Addr) -> Result<(), String> {
    trace!("systemd_resolved_set_dns_ip: setting DNS IP to {}", dns_ip);
    let ifindex = get_interface_index()?;
    trace!("systemd_resolved_set_dns_ip: got ifindex={}", ifindex);

    let connection = Connection::system()
        .await
        .map_err(|e| format!("Failed to connect to system bus: {e}"))?;
    trace!("systemd_resolved_set_dns_ip: connected to system bus");
    let manager = ManagerProxy::new(&connection)
        .await
        .map_err(|e| format!("Failed to create ManagerProxy: {e}"))?;
    trace!("systemd_resolved_set_dns_ip: created manager proxy");

    manager
        .set_link_dns(ifindex, vec![(AF_INET, dns_ip.octets().to_vec())])
        .await
        .map_err(|e| format!("Failed to call set_link_dns: {e}"))?;
    trace!("systemd_resolved_set_dns_ip: set link DNS");

    manager
        .set_link_domains(ifindex, vec![(NETSODY_DOMAIN.into(), true)])
        .await
        .map_err(|e| format!("Failed to call set_link_domains: {e}"))?;
    trace!("systemd_resolved_set_dns_ip: set link domains");

    Ok(())
}

/// Get the interface index for the netsody TUN interface.
///
/// # Returns
/// * `Ok(i32)` - Interface index
/// * `Err(String)` - Interface not found or error occurred
fn get_interface_index() -> Result<i32, String> {
    let ifname = CString::new(NETSODY_INTERFACE_NAME)
        .map_err(|e| format!("Invalid interface name: {}", e))?;
    let ifindex = unsafe { if_nametoindex(ifname.as_ptr()) };
    if ifindex == 0 {
        return Err(format!(
            "Unable to get ifindex for {} interface.",
            NETSODY_INTERFACE_NAME
        ));
    }
    Ok(ifindex as i32)
}
