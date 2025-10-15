use crate::agent::AgentInner;
use crate::agent::router::AgentRouterInterface;
#[cfg(target_os = "linux")]
use crate::network::EffectiveForwardingList;
use crate::network::{AppliedStatus, EffectiveRoute, EffectiveRoutingList, Network};
use cfg_if::cfg_if;
use net_route::{Handle, Route};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::MutexGuard;
use tracing::{trace, warn};
use tun_rs::AsyncDevice;
use url::Url;

#[cfg(target_os = "linux")]
const NETSODY_IFACE: &str = "netsody";
#[cfg(target_os = "linux")]
const NAT_CHAIN: &str = "NETSODY-NAT";
#[cfg(target_os = "linux")]
const FORWARD_CHAIN: &str = "NETSODY-FORWARD";

pub struct AgentRouter {
    pub(crate) handle: Arc<Handle>,
}

impl AgentRouter {
    pub(crate) fn new() -> Self {
        Self {
            handle: Arc::new(Handle::new().expect("Failed to create route handle")),
        }
    }

    #[allow(unused_variables)]
    fn net_route(effective_route: &EffectiveRoute, if_index: Option<u32>) -> Route {
        let route = Route::new(
            IpAddr::V4(effective_route.dest.addr()),
            effective_route.dest.prefix_len(),
        )
        .with_gateway(IpAddr::V4(effective_route.gw));
        #[cfg(any(target_os = "windows", target_os = "linux"))]
        let route = route.with_metric(4900);
        #[cfg(target_os = "windows")]
        let route = route.with_ifindex(if_index.expect("Interface index is required"));
        route
    }

    async fn update_network_inner(
        &self,
        current_routes: Option<EffectiveRoutingList>,
        desired_routes: Option<EffectiveRoutingList>,
        tun_device: Arc<AsyncDevice>,
    ) -> EffectiveRoutingList {
        #[allow(unused_mut)]
        let mut applied_routes = EffectiveRoutingList::default();
        trace!(
            "Routes change: current={:?}; desired={:?}",
            current_routes, desired_routes
        );

        trace!("Updating routes using net_route");
        let routes_handle = self.handle.clone();
        let if_index = tun_device.if_index().ok();
        if let Some(current_routes) = current_routes.as_ref() {
            for (dest, route) in current_routes.iter() {
                match desired_routes.as_ref() {
                    Some(desired_routes) if desired_routes.contains(dest) => {
                        applied_routes.add(route.clone());
                    }
                    _ => {
                        trace!("delete route: {:?}", route);
                        let net_route = Self::net_route(route, if_index);
                        if let Err(e) = routes_handle.delete(&net_route).await {
                            warn!("Failed to delete route {:?}: {}", route, e);
                            applied_routes.add(route.clone());
                        }
                    }
                }
            }
        }

        if let Some(desired_routes) = desired_routes.as_ref() {
            if let Ok(existing_routes) = routes_handle.list().await {
                for (_, route) in desired_routes.iter() {
                    let net_route = Self::net_route(route, if_index);
                    let existing = existing_routes.iter().any(|route| {
                        net_route.destination == route.destination
                            && net_route.prefix == route.prefix
                            && net_route.gateway == route.gateway
                    });
                    if existing {
                        trace!("route does already exist: {:?}", route);
                        applied_routes.add(route.clone());
                    } else {
                        trace!("add route: {:?}", route);
                        if let Err(e) = routes_handle.add(&net_route).await {
                            warn!("Failed to add route {:?}: {}", route, e);
                        } else {
                            applied_routes.add(route.clone());
                        }
                    }
                }
            } else {
                warn!("Failed to list existing routes");
            }
        }

        applied_routes
    }
}

impl AgentRouterInterface for AgentRouter {
    async fn apply_desired_state(
        &self,
        inner: Arc<AgentInner>,
        config_url: &Url,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        if let Some(network) = networks.get_mut(config_url) {
            // routes

            // check if routes are still in desired state
            let routes_handle = self.handle.clone();
            if let Some(routes) = network.current_state.routes.applied.clone()
                && let Ok(existing_routes) = routes_handle.list().await
            {
                let result = inner.netif.tun_device.load().as_ref().cloned();
                let tun_device = result.map(|result| result.0.clone());
                if let Some(tun_device) = tun_device {
                    let if_index = tun_device.if_index().ok();
                    for (_, route) in routes.0.iter() {
                        let net_route = Self::net_route(route, if_index);
                        let existing = existing_routes.iter().any(|route| {
                            net_route.destination == route.destination
                                && net_route.prefix == route.prefix
                                && net_route.gateway == route.gateway
                        });

                        if !existing {
                            warn!("Route {:?} has been removed externally.", route);
                            network.current_state.routes = AppliedStatus::error(format!(
                                "Route {:?} has been removed externally.",
                                route
                            ));
                        }
                    }
                } else if network.desired_state.routes.applied.is_some() {
                    network.current_state.routes =
                        AppliedStatus::error("TUN device does not exist.".to_string());
                    return;
                }
            }

            if network.current_state.routes != network.desired_state.routes {
                trace!("Routes are not in desired state");

                trace!("Try to apply routes '{}'", &network.current_state.routes);
                let tun_device = inner
                    .netif
                    .tun_device
                    .load()
                    .as_ref()
                    .map(|result| result.0.clone());
                if let Some(tun_device) = tun_device {
                    let applied_routes = AppliedStatus::applied(
                        self.update_network_inner(
                            network.current_state.routes.applied.clone(),
                            network.desired_state.routes.applied.clone(),
                            tun_device.clone(),
                        )
                        .await,
                    );

                    trace!("Applied routes {}", &network.current_state.routes);
                    if network.desired_state.routes.applied.is_none() {
                        network.current_state.routes = network.desired_state.routes.clone();
                    } else {
                        network.current_state.routes = applied_routes;
                    }
                } else if network.desired_state.routes.applied.is_some() {
                    network.current_state.routes =
                        AppliedStatus::error("TUN device does not exist.".to_string());
                } else if network.desired_state.routes.applied.is_none() {
                    network.current_state.routes = network.desired_state.routes.clone();
                }
            }
        }

        // IP forwarding is a system-level setting, so we need to set up forwarding for all networks at the same time
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                // Check if any network requires us to do forwarding
                let needs_forwarding = networks.values()
                    .any(|net| net.desired_state.forwardings.applied.as_ref().map_or(false, |list| !list.is_empty()));

                if needs_forwarding {
                    // Apply IP forwarding via sysctl (global kernel setting)
                    match apply_ip_forwarding(needs_forwarding) {
                        Ok(forwarding_enabled) => {
                            if forwarding_enabled {
                                // IP forwarding is enabled, now apply forwarding filter rules
                                match apply_forwarding_filter_rules(&networks).await {
                                    Ok(()) => {
                                        trace!("Successfully applied IP forwarding and forwarding filter rules.");
                                        // Update current_state for all networks that have forwarding destinations
                                        for network in networks.values_mut() {
                                            if let Some(desired_list) = &network.desired_state.forwardings.applied {
                                                if !desired_list.is_empty() {
                                                    network.current_state.forwardings = AppliedStatus::applied(desired_list.clone());
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Failed to apply forwarding filter rules: {}", e);
                                        // Update current_state for all networks that have forwarding destinations
                                        for network in networks.values_mut() {
                                            if let Some(desired_list) = &network.desired_state.forwardings.applied {
                                                if !desired_list.is_empty() {
                                                    network.current_state.forwardings = AppliedStatus::with_error(
                                                        EffectiveForwardingList::default(),
                                                        format!("IP forwarding enabled but forwarding filter rules failed: {}", e)
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                // Forwarding is disabled for all networks
                                for network in networks.values_mut() {
                                    network.current_state.forwardings = AppliedStatus::applied(EffectiveForwardingList::default());
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to apply IP forwarding: {}", e);
                            for network in networks.values_mut() {
                                if let Some(desired_list) = &network.desired_state.forwardings.applied {
                                    if !desired_list.is_empty() {
                                        network.current_state.forwardings = AppliedStatus::with_error(EffectiveForwardingList::default(), e.clone());
                                    }
                                }
                            }
                        }
                    }
                } else {
                    // No network needs forwarding, ensure all are marked as empty
                    for network in networks.values_mut() {
                        if network.desired_state.forwardings.applied.as_ref().map_or(true, |list| list.is_empty()) {
                            network.current_state.forwardings = AppliedStatus::applied(EffectiveForwardingList::default());
                        }
                    }
                }
            }
            else {
                for network in networks.values_mut() {
                    if let Some(desired_list) = &network.desired_state.forwardings.applied {
                        if !desired_list.is_empty() {
                            warn!("We're configured as a gateway. Forwarding is not supported on this platform.");
                            network.current_state.forwardings = AppliedStatus::error("We're configured as a gateway. Forwarding is not supported on this platform.".to_string());
                        } else {
                            network.current_state.forwardings = network.desired_state.forwardings.clone();
                        }
                    } else {
                        network.current_state.forwardings = network.desired_state.forwardings.clone();
                    }
                }
            }
        }
    }
}

/// Apply IP forwarding setting via sysctl
///
/// IP forwarding must be enabled in the kernel to allow routing between network interfaces.
/// Without this, packets would be dropped by the kernel even if iptables rules allow forwarding.
/// This is a global kernel setting that applies to all networks.
///
/// Returns `Ok(true)` if forwarding is enabled, `Ok(false)` if disabled, `Err(msg)` on failure.
#[cfg(target_os = "linux")]
fn apply_ip_forwarding(needs_forwarding: bool) -> Result<bool, String> {
    use sysctl::Sysctl;

    let ctl = sysctl::Ctl::new("net.ipv4.ip_forward")
        .map_err(|e| format!("Failed to construct Ctl for 'net.ipv4.ip_forward': {}", e))?;

    let current_value = ctl
        .value_string()
        .map_err(|e| format!("Failed to get value for Ctl 'net.ipv4.ip_forward': {}", e))?;

    match (current_value.as_str(), needs_forwarding) {
        ("1", true) => {
            trace!("IP forwarding is already enabled as needed.");
            Ok(true)
        }
        ("0", true) => {
            trace!("At least one network needs forwarding, enabling IP forwarding.");
            ctl.set_value_string("1")
                .map_err(|e| format!("Failed to enable IP forwarding: {}", e))?;
            trace!("Enabled IP forwarding.");
            Ok(true)
        }
        ("0", false) => {
            trace!("No network needs forwarding, IP forwarding is already disabled.");
            Ok(false)
        }
        ("1", false) => {
            trace!(
                "IP forwarding is enabled, but we don't need it. We keep it enabled, because we can't know if another application needs it."
            );
            Ok(true)
        }
        _ => Err(format!("Unexpected IP forwarding value: {}", current_value)),
    }
}

/// Apply forwarding filter rules via iptables for all networks
///
/// Configures MASQUERADE (NAT) and FORWARD filter rules to enable gateway functionality.
/// MASQUERADE rules rewrite source addresses for outgoing packets, while FORWARD rules
/// allow packets to flow between the netsody interface and physical interfaces.
///
/// Note: FORWARD rules are only strictly necessary if the default FORWARD policy is DROP/REJECT.
/// If the default policy is ACCEPT, packets would be forwarded anyway. However, we explicitly
/// create these rules to ensure forwarding works regardless of the system's default policy.
///
/// Returns `Ok(())` on success, `Err(msg)` on failure.
#[cfg(target_os = "linux")]
async fn apply_forwarding_filter_rules(networks: &HashMap<Url, Network>) -> Result<(), String> {
    use ipnet::Ipv4Net;
    use libc::{IF_NAMESIZE, c_char, if_indextoname};
    use net_route::Handle as RouteHandle;
    use std::collections::{HashMap, HashSet};
    use std::ffi::CStr;

    // Collect all destinations from all networks
    let destinations: HashSet<Ipv4Net> = networks
        .values()
        .flat_map(|net| {
            net.desired_state
                .forwardings
                .applied
                .as_ref()
                .map(|list| list.iter().copied().collect::<Vec<_>>())
                .unwrap_or_default()
        })
        .collect();

    trace!(
        "This node needs to forward to following destinations: {:?}.",
        destinations
    );

    // Get routing table to determine which interface to use for each destination
    let route_handle =
        RouteHandle::new().map_err(|e| format!("Failed to create route handle: {}", e))?;
    let routes = route_handle
        .list()
        .await
        .map_err(|e| format!("Failed to list routes: {}", e))?;

    trace!(
        "Retrieved {} routes from system routing table.",
        routes.len()
    );

    let mut dest_to_iface: HashMap<Ipv4Net, String> = HashMap::new();
    for dest in destinations.iter() {
        // Find the best matching route for this destination (store interface name and prefix length)
        let mut best_match: Option<(String, u8)> = None; // (interface_name, prefix_len)

        for route in &routes {
            // Only consider IPv4 routes with an ifindex
            if let (IpAddr::V4(route_dest), Some(ifindex)) = (route.destination, route.ifindex) {
                // Convert ifindex to interface name
                let mut buf = [0u8; IF_NAMESIZE];
                let result = unsafe { if_indextoname(ifindex, buf.as_mut_ptr() as *mut c_char) };

                if result.is_null() {
                    continue; // Skip routes with invalid ifindex
                }

                let ifname = unsafe {
                    match CStr::from_ptr(buf.as_ptr() as *const c_char).to_str() {
                        Ok(name) => name.to_string(),
                        Err(_) => continue, // Skip routes with invalid interface names
                    }
                };

                // Skip routes that go through the Netsody interface itself
                if ifname == NETSODY_IFACE {
                    continue;
                }

                let route_prefix = route.prefix;
                // Create network for this route
                if let Ok(route_net) = Ipv4Net::new(route_dest, route_prefix) {
                    // Check if this route matches our destination (destination is within route's network)
                    if route_net.contains(dest) {
                        // Use the most specific route (longest prefix match)
                        if best_match
                            .as_ref()
                            .map_or(true, |(_, prefix)| route_prefix > *prefix)
                        {
                            best_match = Some((ifname, route_prefix));
                        }
                    }
                }
            }
        }

        if let Some((ifname, prefix_len)) = best_match {
            trace!(
                "Mapping destination '{}' to interface '{}' via routing table (prefix: /{}).",
                dest, ifname, prefix_len
            );
            dest_to_iface.insert(*dest, ifname);
        } else {
            return Err(format!(
                "No route found for destination '{}' (ignoring routes via netsody interface). Cannot configure gateway rules without a matching physical route.",
                dest
            ));
        }
    }

    trace!(
        "Successfully mapped {} destinations to their interfaces.",
        dest_to_iface.len()
    );

    let ipt = iptables::new(false).map_err(|e| format!("Failed to initialize iptables: {}", e))?;

    // If no valid destination mappings exist, clean up all chains and exit
    if dest_to_iface.is_empty() {
        trace!("No valid destination-to-interface mappings, removing all Netsody iptables rules.");

        // Remove jump rule from POSTROUTING
        let nat_jump_rule = format!("-j {}", NAT_CHAIN);
        if ipt
            .exists("nat", "POSTROUTING", &nat_jump_rule)
            .map_err(|e| format!("Failed to check NAT rule existence: {}", e))?
        {
            ipt.delete("nat", "POSTROUTING", &nat_jump_rule)
                .map_err(|e| format!("Failed to delete NAT jump rule: {}", e))?;
            trace!(
                "No NAT needed without valid destinations, removed POSTROUTING jump to '{}'",
                NAT_CHAIN
            );
        }

        // Remove jump rule from FORWARD
        let forward_jump_rule = format!("-j {}", FORWARD_CHAIN);
        if ipt
            .exists("filter", "FORWARD", &forward_jump_rule)
            .map_err(|e| format!("Failed to check FORWARD rule existence: {}", e))?
        {
            ipt.delete("filter", "FORWARD", &forward_jump_rule)
                .map_err(|e| format!("Failed to delete FORWARD jump rule: {}", e))?;
            trace!(
                "No forwarding needed without valid destinations, removed FORWARD jump to '{}'",
                FORWARD_CHAIN
            );
        }

        // Flush and delete NAT chain
        if ipt
            .chain_exists("nat", NAT_CHAIN)
            .map_err(|e| format!("Failed to check NAT chain existence: {}", e))?
        {
            ipt.flush_chain("nat", NAT_CHAIN)
                .map_err(|e| format!("Failed to flush NAT chain: {}", e))?;
            ipt.delete_chain("nat", NAT_CHAIN)
                .map_err(|e| format!("Failed to delete NAT chain: {}", e))?;
            trace!(
                "NAT chain '{}' no longer needed, flushed and deleted it",
                NAT_CHAIN
            );
        }

        // Flush and delete FORWARD chain
        if ipt
            .chain_exists("filter", FORWARD_CHAIN)
            .map_err(|e| format!("Failed to check FORWARD chain existence: {}", e))?
        {
            ipt.flush_chain("filter", FORWARD_CHAIN)
                .map_err(|e| format!("Failed to flush FORWARD chain: {}", e))?;
            ipt.delete_chain("filter", FORWARD_CHAIN)
                .map_err(|e| format!("Failed to delete FORWARD chain: {}", e))?;
            trace!(
                "FORWARD chain '{}' no longer needed, flushed and deleted it",
                FORWARD_CHAIN
            );
        }

        trace!("Cleaned up all Netsody iptables rules.");
        return Ok(());
    }

    // We have valid destination-to-interface mappings, so we need NAT and FORWARD chains
    trace!(
        "Have {} valid destination mappings, ensuring NAT and FORWARD chains are configured.",
        dest_to_iface.len()
    );

    // iptables -t nat -L $CHAIN || iptables -t nat -N $CHAIN
    if !ipt
        .chain_exists("nat", NAT_CHAIN)
        .map_err(|e| format!("Failed to check NAT chain: {}", e))?
    {
        ipt.new_chain("nat", NAT_CHAIN)
            .map_err(|e| format!("Failed to create NAT chain: {}", e))?;
        trace!(
            "NAT chain '{}' did not exist, created it to organize MASQUERADE rules.",
            NAT_CHAIN
        );
    } else {
        trace!(
            "NAT chain '{}' already exists, skipping creation.",
            NAT_CHAIN
        );
    }

    // iptables -t nat -C POSTROUTING -j $CHAIN || iptables -t nat -A POSTROUTING -j $CHAIN
    let nat_jump_rule = format!("-j {}", NAT_CHAIN);
    if !ipt
        .exists("nat", "POSTROUTING", &nat_jump_rule)
        .map_err(|e| format!("Failed to check POSTROUTING rule: {}", e))?
    {
        ipt.append("nat", "POSTROUTING", &nat_jump_rule)
            .map_err(|e| format!("Failed to add POSTROUTING rule: {}", e))?;
        trace!(
            "POSTROUTING did not jump to '{}', added jump rule to route packets through our NAT chain.",
            NAT_CHAIN
        );
    } else {
        trace!(
            "POSTROUTING already jumps to '{}', no action needed.",
            NAT_CHAIN
        );
    }

    // iptables -N $FORWARD_CHAIN
    if !ipt
        .chain_exists("filter", FORWARD_CHAIN)
        .map_err(|e| format!("Failed to check FORWARD chain: {}", e))?
    {
        ipt.new_chain("filter", FORWARD_CHAIN)
            .map_err(|e| format!("Failed to create FORWARD chain: {}", e))?;
        trace!(
            "FORWARD chain '{}' did not exist, created it to organize forwarding rules.",
            FORWARD_CHAIN
        );
    } else {
        trace!(
            "FORWARD chain '{}' already exists, skipping creation.",
            FORWARD_CHAIN
        );
    }

    // iptables -C FORWARD -j $FORWARD_CHAIN || iptables -A FORWARD -j $FORWARD_CHAIN
    let forward_jump_rule = format!("-j {}", FORWARD_CHAIN);
    if !ipt
        .exists("filter", "FORWARD", &forward_jump_rule)
        .map_err(|e| format!("Failed to check FORWARD jump rule: {}", e))?
    {
        ipt.append("filter", "FORWARD", &forward_jump_rule)
            .map_err(|e| format!("Failed to add FORWARD jump rule: {}", e))?;
        trace!(
            "FORWARD did not jump to '{}', added jump rule to route packets through our forward chain.",
            FORWARD_CHAIN
        );
    } else {
        trace!(
            "FORWARD already jumps to '{}', no action needed.",
            FORWARD_CHAIN
        );
    }

    // Collect all valid physical interfaces from the cached mappings
    let valid_phy_ifaces: HashSet<&str> = dest_to_iface.values().map(|s| s.as_str()).collect();
    trace!(
        "Valid interfaces that should have rules: {:?}.",
        valid_phy_ifaces
    );

    // Clean up rules for interfaces not in destinations
    if ipt
        .chain_exists("nat", NAT_CHAIN)
        .map_err(|e| format!("Failed to check NAT chain: {}", e))?
    {
        let nat_rules = ipt
            .list("nat", NAT_CHAIN)
            .map_err(|e| format!("Failed to list NAT rules: {}", e))?;
        trace!("Checking NAT chain for obsolete rules (interfaces no longer in destinations).");
        for rule in nat_rules.iter() {
            // Remove "-A CHAIN_NAME " prefix from the rule string
            let prefix = format!("-A {} ", NAT_CHAIN);
            let rule_cleaned = rule.strip_prefix(&prefix).unwrap_or(rule).trim();

            if rule_cleaned.contains("-o") && rule_cleaned.contains("MASQUERADE") {
                // Extract interface name from rule like "-o eth0 -j MASQUERADE"
                if let Some(iface) = rule_cleaned
                    .split_whitespace()
                    .skip_while(|&s| s != "-o")
                    .nth(1)
                {
                    trace!(
                        "Found MASQUERADE rule for interface '{}' in NAT chain.",
                        iface
                    );
                    if !valid_phy_ifaces.contains(iface) {
                        let rule_to_delete = format!("-o {} -j MASQUERADE", iface);
                        ipt.delete("nat", NAT_CHAIN, &rule_to_delete)
                            .map_err(|e| format!("Failed to delete NAT rule: {}", e))?;
                        trace!(
                            "Interface '{}' not in destinations {:?}, deleted obsolete MASQUERADE rule.",
                            iface, valid_phy_ifaces
                        );
                    } else {
                        trace!(
                            "Interface '{}' still in destinations, keeping MASQUERADE rule.",
                            iface
                        );
                    }
                }
            }
        }
    }

    if ipt
        .chain_exists("filter", FORWARD_CHAIN)
        .map_err(|e| format!("Failed to check FORWARD chain: {}", e))?
    {
        let forward_rules = ipt
            .list("filter", FORWARD_CHAIN)
            .map_err(|e| format!("Failed to list FORWARD rules: {}", e))?;
        trace!("Checking FORWARD chain for obsolete rules (interfaces no longer in destinations).");
        for rule in forward_rules.iter() {
            // Remove "-A CHAIN_NAME " prefix from the rule string
            let prefix = format!("-A {} ", FORWARD_CHAIN);
            let rule_cleaned = rule.strip_prefix(&prefix).unwrap_or(rule).trim();

            // Check for FORWARD rules with physical interfaces
            if (rule_cleaned.contains("-i") || rule_cleaned.contains("-o"))
                && (rule_cleaned.contains(NETSODY_IFACE)
                    || rule_cleaned.contains("RELATED,ESTABLISHED"))
            {
                // Extract physical interface from rules and check if rule should be deleted
                let parts: Vec<&str> = rule_cleaned.split_whitespace().collect();
                let mut should_delete = false;
                for (i, &part) in parts.iter().enumerate() {
                    if (part == "-i" || part == "-o") && i + 1 < parts.len() {
                        let iface = parts[i + 1];
                        if iface != NETSODY_IFACE && !valid_phy_ifaces.contains(iface) {
                            // Found an interface that's not in our destinations - delete this rule
                            should_delete = true;
                            ipt.delete("filter", FORWARD_CHAIN, rule_cleaned)
                                .map_err(|e| format!("Failed to delete FORWARD rule: {}", e))?;
                            trace!(
                                "Interface '{}' no longer in destinations, deleted FORWARD rule: {}.",
                                iface, rule_cleaned
                            );
                            break;
                        }
                    }
                }

                if !should_delete {
                    trace!("FORWARD rule still needed, keeping: {}.", rule_cleaned);
                }
            }
        }
    }

    // Iterate over unique interfaces to configure rules once per interface (avoid duplicate work)
    trace!(
        "Configuring rules for {} unique interfaces.",
        valid_phy_ifaces.len()
    );

    // Iterate over each unique interface and configure rules once per interface
    for phy_iface in valid_phy_ifaces.iter() {
        // Find which destinations use this interface (for logging)
        let destinations_for_iface: Vec<Ipv4Net> = dest_to_iface
            .iter()
            .filter(|(_, iface)| iface.as_str() == *phy_iface)
            .map(|(dest, _)| *dest)
            .collect();

        trace!(
            "Configuring rules for interface '{}' (used by {} destination(s): {:?}).",
            phy_iface,
            destinations_for_iface.len(),
            destinations_for_iface
        );

        // iptables -t nat -A $CHAIN -o $PHY_IFACE -j MASQUERADE
        let masquerade_rule = format!("-o {} -j MASQUERADE", phy_iface);
        if !ipt
            .exists("nat", NAT_CHAIN, &masquerade_rule)
            .map_err(|e| format!("Failed to check MASQUERADE rule: {}", e))?
        {
            ipt.append("nat", NAT_CHAIN, &masquerade_rule)
                .map_err(|e| format!("Failed to add MASQUERADE rule: {}", e))?;
            trace!(
                "Interface '{}' requires NAT, added MASQUERADE rule.",
                phy_iface
            );
        } else {
            trace!(
                "MASQUERADE rule for '{}' already exists, no action needed.",
                phy_iface
            );
        }

        // iptables -A $FORWARD_CHAIN -i $PHY_IFACE -o $NETSODY_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
        let forward_in_rule = format!(
            "-i {} -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT",
            phy_iface, NETSODY_IFACE
        );
        if !ipt
            .exists("filter", FORWARD_CHAIN, &forward_in_rule)
            .map_err(|e| format!("Failed to check FORWARD in rule: {}", e))?
        {
            ipt.append("filter", FORWARD_CHAIN, &forward_in_rule)
                .map_err(|e| format!("Failed to add FORWARD in rule: {}", e))?;
            trace!(
                "Need to forward response packets from '{}' to '{}', added RELATED,ESTABLISHED rule.",
                phy_iface, NETSODY_IFACE
            );
        } else {
            trace!(
                "FORWARD rule for responses from '{}' already exists, no action needed.",
                phy_iface
            );
        }

        // iptables -A $FORWARD_CHAIN -i $NETSODY_IFACE -o $PHY_IFACE -j ACCEPT
        let forward_out_rule = format!("-i {} -o {} -j ACCEPT", NETSODY_IFACE, phy_iface);
        if !ipt
            .exists("filter", FORWARD_CHAIN, &forward_out_rule)
            .map_err(|e| format!("Failed to check FORWARD out rule: {}", e))?
        {
            ipt.append("filter", FORWARD_CHAIN, &forward_out_rule)
                .map_err(|e| format!("Failed to add FORWARD out rule: {}", e))?;
            trace!(
                "Need to forward outgoing packets from '{}' to '{}', added ACCEPT rule.",
                NETSODY_IFACE, phy_iface
            );
        } else {
            trace!(
                "FORWARD rule for outgoing to '{}' already exists, no action needed.",
                phy_iface
            );
        }
    }

    trace!(
        "Configured NAT chain '{}', FORWARD chain '{}', netsody iface '{}'.",
        NAT_CHAIN, FORWARD_CHAIN, NETSODY_IFACE
    );

    Ok(())
}
