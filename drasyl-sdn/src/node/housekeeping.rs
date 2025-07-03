use crate::network::config::EffectiveRoutingList;
use crate::network::{LocalNodeState, Network, NetworkInner, TunState};
use crate::node::Error;
use crate::node::inner::SdnNodeInner;
use crate::node::inner::is_drasyl_control_packet;
use drasyl::identity::PubKey;
use drasyl::message::ARM_HEADER_LEN;
use drasyl::message::LONG_HEADER_LEN;
use drasyl::message::SHORT_HEADER_LEN;
use drasyl::node::SendHandle;
use drasyl::util;
use drasyl::util::bytes_to_hex;
use etherparse::Ipv4HeaderSlice;
use ipnet::{IpNet, Ipv4Net};
use ipnet_trie::IpnetTrie;
use net_route::Handle;
#[cfg(target_os = "linux")]
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::task;
use tokio_util::sync::CancellationToken;
use tracing::{Level, enabled, error, instrument, trace, warn};
use tun_rs::{AsyncDevice as TunDevice, AsyncDevice, DeviceBuilder as TunDeviceBuilder};
#[cfg(all(feature = "dns", any(target_os = "macos", target_os = "linux")))]
use {std::fs, std::io::Write};

impl SdnNodeInner {
    pub(crate) async fn housekeeping_runner(
        inner: Arc<SdnNodeInner>,
        housekeeping_shutdown: CancellationToken,
    ) {
        let mut interval = tokio::time::interval(Duration::from_millis(10_000));

        loop {
            tokio::select! {
                biased;
                _ = housekeeping_shutdown.cancelled() => break,
                _ = interval.tick() => {
                    if let Err(e) = inner.housekeeping(&inner).await {
                        error!("Error in housekeeping: {e}");
                    }
                }
            }
        }
    }

    async fn housekeeping(&self, inner: &Arc<SdnNodeInner>) -> Result<(), Error> {
        {
            let mut networks = inner.networks.lock().await;

            for network in networks.values_mut() {
                self.housekeeping_network(inner.clone(), network).await;
            }
        }

        // TODO: we update the rx tries here because within the housekeeping_network we already have a lock on the networks
        self.update_rx_tries(inner.clone()).await;

        // TODO: we update the hosts file here because within the housekeeping_network we already have a lock on the networks
        #[cfg(all(feature = "dns", any(target_os = "macos", target_os = "linux")))]
        if let Err(e) = update_hosts_file(inner.clone()).await {
            error!("failed to update /etc/hosts: {}", e);
        }

        Ok(())
    }

    #[instrument(fields(network = %network.config_url), skip_all)]
    async fn housekeeping_network(&self, inner: Arc<SdnNodeInner>, network: &mut Network) {
        match Self::fetch_network_config(network.config_url.as_str()).await {
            Ok(config) => {
                trace!("Network config fetched successfully");

                let desired = match config.ip(&inner.id.pk) {
                    Some(desired_ip) => {
                        let desired_effective_access_rule_list = config
                            .effective_access_rule_list(&inner.id.pk)
                            .expect("Failed to get effective access rule");
                        let desired_effective_routing_list = config
                            .effective_routing_list(&inner.id.pk)
                            .expect("Failed to get effective routing list");
                        let desired_hostnames = config.hostnames(&inner.id.pk);
                        Some(LocalNodeState {
                            subnet: config.subnet,
                            ip: desired_ip,
                            access_rules: desired_effective_access_rule_list,
                            routes: desired_effective_routing_list,
                            hostnames: desired_hostnames,
                        })
                    }
                    None => None,
                };

                let current = network.state.as_ref().cloned();

                match (current, desired) {
                    (Some(current), Some(desired)) if current == desired => {
                        trace!("Network is already in desired state");
                    }
                    (Some(current), Some(desired))
                        if current.tun_state() == desired.tun_state() =>
                    {
                        trace!("TUN is in desired state");
                        self.update_routes_and_hostnames(
                            inner.clone(),
                            network,
                            Some(current),
                            desired,
                        )
                        .await;
                    }
                    (current, Some(desired)) => {
                        if current.is_some() {
                            trace!(
                                "TUN is not in desired state. We need to teardown everything and then setup everything again."
                            );
                            self.teardown_network(inner.clone(), network).await;
                        } else {
                            trace!("TUN device does not exist. We need to setup everything.");
                        }
                        self.setup_network(inner.clone(), network, current, desired)
                            .await;
                    }
                    (_, None) => {
                        trace!("I'm not part of this network.");
                        self.teardown_network(inner.clone(), network).await;
                    }
                }
            }
            Err(e) => {
                warn!("Failed to fetch network config: {}", e);
            }
        }
    }

    async fn update_routes_and_hostnames(
        &self,
        inner: Arc<SdnNodeInner>,
        network: &mut Network,
        current: Option<LocalNodeState>,
        desired: LocalNodeState,
    ) {
        // routes
        let applied_routes = match current.as_ref().map(|state| state.routes.clone()) {
            Some(current_routes) if current_routes == desired.routes => current_routes,
            current_routes => {
                Self::update_routes(
                    self.routes_handle.clone(),
                    current_routes,
                    Some(desired.routes.clone()),
                )
                .await
            }
        };

        network.state = Some(LocalNodeState {
            subnet: desired.subnet,
            ip: desired.ip,
            access_rules: desired.access_rules.clone(),
            routes: applied_routes,
            hostnames: desired.hostnames.clone(),
        });

        // access rules
        match current.as_ref().map(|state| state.access_rules.clone()) {
            Some(current_access_rules) if current_access_rules == desired.access_rules => {}
            current_access_rules => {
                trace!(
                    "Access rules change: current=\n{}; desired=\n{}",
                    current_access_rules.map_or("None".to_string(), |v| v.to_string()),
                    desired.access_rules
                );
                self.update_tx_trie(network).await;
                // TODO: we can't update the rx tries here because we already have a lock on the networks
                // self.update_rx_tries(inner.clone()).await;
            }
        }

        // TODO: we can't update the hostnames here because we already have a lock on the networks
        // // hostnames
        // #[cfg(all(feature = "dns", any(target_os = "macos", target_os = "linux")))]
        // match current.as_ref().map(|state| state.hostnames.clone()) {
        //     Some(current_hostnames) if current_hostnames == desired.hostnames => {}
        //     _ => {
        //         if let Err(e) = update_hosts_file(inner.clone()).await {
        //             error!("failed to update /etc/hosts: {}", e);
        //         }
        //     }
        // }
    }

    pub(crate) async fn teardown_network(&self, inner: Arc<SdnNodeInner>, network: &mut Network) {
        // routes
        let routes = { network.state.as_ref().map(|state| state.routes.clone()) };
        if let Some(routes) = routes {
            Self::remove_routes(self.routes_handle.clone(), routes).await;
        }

        network.state = None;

        // access rules
        self.update_tx_trie(network).await;
        // TODO: we can't update the rx tries here because we already have a lock on the networks
        // self.update_rx_tries(inner.clone()).await;

        // TODO: we can't update the hostnames here because we already have a lock on the networks
        // // hostnames
        // #[cfg(all(feature = "dns", any(target_os = "macos", target_os = "linux")))]
        // if let Err(e) = update_hosts_file(inner.clone()).await {
        //     error!("failed to update /etc/hosts: {}", e);
        // }

        // tun device
        self.remove_tun_device(network).await;
    }

    async fn setup_network(
        &self,
        inner: Arc<SdnNodeInner>,
        network: &mut Network,
        current: Option<LocalNodeState>,
        desired: LocalNodeState,
    ) {
        // tun device
        let (tun_cancellation_token, tun_device) = self.create_tun_device(
            inner.clone(),
            desired.ip,
            desired.subnet.prefix_len(),
            Self::tun_dev_name(desired.subnet),
            network.inner.clone(),
        );
        network.tun_state = Some(TunState {
            cancellation_token: tun_cancellation_token,
            device: tun_device.clone(),
        });

        self.update_routes_and_hostnames(inner.clone(), network, current, desired)
            .await;
    }

    #[instrument(skip_all)]
    async fn update_tx_trie(&self, network: &Network) {
        trace!("Update trie tx");
        let mut trie_tx: IpnetTrie<IpnetTrie<Arc<SendHandle>>> = IpnetTrie::new();

        if let Some(access_rules) = network
            .state
            .as_ref()
            .map(|state| state.access_rules.clone())
        {
            let (network_trie_tx, _) = access_rules.routing_tries();

            trace!(
                network=?network.config_url,
                "Processing access rules for network"
            );

            // tx
            for (source, trie) in network_trie_tx.iter() {
                let mut source_trie = IpnetTrie::new();
                trace!(source_net=?source, "Building TX trie for source network");

                for (dest, pk) in trie.iter() {
                    let send_handle = self
                        .node
                        .send_handle(pk)
                        .expect("Failed to create send handle");
                    source_trie.insert(dest, send_handle);

                    trace!(
                        source_net=?source,
                        dest_net=?dest,
                        peer=?pk,
                        "Added TX route: {} -> {} via peer {}",
                        source,
                        dest,
                        pk
                    );
                }
                trie_tx.insert(source, source_trie);
            }
        } else {
            trace!(
                network=?network.config_url,
                "No access rules available for network"
            );
        }

        trace!("Trie tx rebuilt successfully.",);
        network.inner.trie_tx.store(Arc::new(trie_tx));
    }

    #[instrument(skip_all)]
    pub(crate) async fn update_rx_tries(&self, inner: Arc<SdnNodeInner>) {
        trace!("Rebuild tries");
        let mut trie_rx: IpnetTrie<IpnetTrie<(PubKey, Arc<TunDevice>)>> = IpnetTrie::new();

        for (config_url, network) in inner.networks.lock().await.iter() {
            if let Some(access_rules) = network
                .state
                .as_ref()
                .map(|state| state.access_rules.clone())
            {
                if let Some(tun_device) =
                    network.tun_state.as_ref().map(|state| state.device.clone())
                {
                    let (_, network_trie_rx) = access_rules.routing_tries();

                    trace!(
                        network=?config_url,
                        "Processing access rules for network"
                    );

                    // rx
                    for (src, trie) in network_trie_rx.iter() {
                        let mut source_trie = IpnetTrie::new();
                        trace!(source_net=?src, "Building RX trie for source network");

                        for (source, pk) in trie.iter() {
                            source_trie.insert(source, (*pk, tun_device.clone()));

                            trace!(
                                source_net=?src,
                                dest_net=?source,
                                peer=?pk,
                                tun_device=?tun_device.name().unwrap_or("unknown".to_string()),
                                "Added RX route: {} -> {} from peer {} to TUN device",
                                src,
                                source,
                                pk
                            );
                        }
                        trie_rx.insert(src, source_trie);
                    }
                } else {
                    trace!(
                        network=?config_url,
                        "No TUN device available for network, skipping access rules"
                    );
                }
            } else {
                trace!(
                    network=?config_url,
                    "No access rules available for network"
                );
            }
        }

        trace!("Tries rebuilt successfully.",);

        inner.trie_rx.store(Arc::new(trie_rx));
    }

    fn create_tun_device(
        &self,
        inner: Arc<SdnNodeInner>,
        ip: Ipv4Addr,
        netmask: u8,
        name: Option<String>,
        network_inner: Arc<NetworkInner>,
    ) -> (CancellationToken, Arc<AsyncDevice>) {
        // create tun device
        let cancellation_token = CancellationToken::new();
        // options
        let arm_messages = util::get_env("ARM_MESSAGES", true);
        let mtu = util::get_env(
            "MTU",
            if arm_messages {
                1472 - 4 - ARM_HEADER_LEN /* - 11 for COMPRESSION */ - (LONG_HEADER_LEN - SHORT_HEADER_LEN)
            } else {
                1472 - 4 /* - 11 for COMPRESSION */ - (LONG_HEADER_LEN - SHORT_HEADER_LEN)
            } as u16,
        );

        // create tun device
        trace!("Create TUN device");
        let mut dev_builder = TunDeviceBuilder::new().ipv4(ip, netmask, Some(ip)).mtu(mtu);
        if let Some(name) = &name {
            dev_builder = dev_builder.name(name);
        }
        #[cfg(target_os = "linux")]
        let tun_device = Arc::new(
            dev_builder
                .multi_queue(true)
                .build_async()
                .expect("Failed to build device"),
        );
        #[cfg(not(target_os = "linux"))]
        let tun_device = Arc::new(dev_builder.build_async().expect("Failed to build device"));
        trace!("TUN device created: {:?}", tun_device.name());

        // crate tun task
        // TODO: guard einführen der aufräumt wenn der task hier stirbt
        let cancellation_token_clone = cancellation_token.clone();
        let inner_clone = inner.clone();
        let tun_device_clone = tun_device.clone();
        let network_inner_clone = network_inner.clone();
        let child_token = cancellation_token_clone.child_token();
        task::spawn(async move {
            tokio::select! {
                _ = cancellation_token_clone.cancelled() => {}
                _ = Self::tun_runner(inner_clone, tun_device_clone, child_token, ip, network_inner_clone) => {
                    error!("TUN runner terminated. Must have crashed.");
                    std::process::exit(1); // TODO: would be nicer to just stop this task
                }
            }
        });
        trace!("TUN task spawned");

        (cancellation_token, tun_device)
    }

    async fn remove_tun_device(&self, network: &mut Network) {
        if let Some(tun_state) = network.tun_state.as_ref() {
            trace!("Remove existing TUN device by cancelling token");
            tun_state.cancellation_token.cancel();
        }
        network.tun_state = None;
    }

    #[cfg(target_os = "linux")]
    fn tun_dev_name(network: Ipv4Net) -> Option<String> {
        const PREFIX: &str = "drasyl";
        const MAX_TOTAL_LEN: usize = 15;
        const MAX_ID_LEN: usize = MAX_TOTAL_LEN - PREFIX.len();

        const BASE36: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
        let mut hash = {
            let mut hasher = DefaultHasher::new();
            network.hash(&mut hasher);
            hasher.finish()
        };
        let mut buf = ['0'; 15]; // Max IFNAMSIZ-1 sicherstellen
        let mut i = MAX_ID_LEN;

        while hash != 0 && i > 0 {
            i -= 1;
            buf[i] = BASE36[(hash % 36) as usize] as char;
            hash /= 36;
        }
        let clean_id: String = buf[i..MAX_ID_LEN].iter().collect();
        Some(format!("{}{}", PREFIX, clean_id))
    }

    #[cfg(not(target_os = "linux"))]
    #[allow(unused_variables)]
    fn tun_dev_name(network: Ipv4Net) -> Option<String> {
        None
    }

    async fn tun_runner(
        inner: Arc<SdnNodeInner>,
        device: Arc<TunDevice>,
        cancellation_token: CancellationToken,
        ip: Ipv4Addr,
        network_inner: Arc<NetworkInner>,
    ) {
        let node = inner.node.clone();
        let tun_tx = inner.tun_tx.clone();

        // options
        let arm_messages = util::get_env("ARM_MESSAGES", true);
        let tun_threads = util::get_env("TUN_THREADS", 3);
        let mtu = util::get_env(
            "MTU",
            if arm_messages {
                1472 - 4 - ARM_HEADER_LEN /* - 11 for COMPRESSION */ - (LONG_HEADER_LEN - SHORT_HEADER_LEN)
            } else {
                1472 - 4 /* - 11 for COMPRESSION */ - (LONG_HEADER_LEN - SHORT_HEADER_LEN)
            } as u16,
        );

        // tun <-> drasyl packet processing
        #[allow(unused_variables)]
        for i in 0..tun_threads {
            // tun -> channel
            #[cfg(target_os = "linux")]
            let dev = if i == 0 {
                device.clone()
            } else {
                Arc::new(device.try_clone().unwrap())
            };
            let dev_clone = device.clone();
            let tun_tx = tun_tx.clone();
            let child_token = cancellation_token.child_token();
            let inner_clone = inner.clone();
            let network_inner_clone = network_inner.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; mtu as usize];
                tokio::select! {
                    _ = child_token.cancelled() => {}
                    _ = async move {
                        while let Ok(size) = dev_clone.recv(&mut buf).await {
                            let buf = &buf[..size];
                            if let Ok(ip_hdr) = Ipv4HeaderSlice::from_slice(buf) {
                                if enabled!(Level::TRACE) {
                                    trace!(
                                        src=?ip_hdr.source_addr(),
                                        dst=?ip_hdr.destination_addr(),
                                        "Forwarding packet from TUN device to drasyl: {} -> {} (debug: https://hpd.gasmi.net/?data={}&force=ipv4)",
                                        ip_hdr.source_addr(),
                                        ip_hdr.destination_addr(),
                                        bytes_to_hex(buf)
                                    );
                                }

                                // filter drasyl control plane messages
                                if is_drasyl_control_packet(buf) {
                                    trace!(
                                        src=?ip_hdr.source_addr(),
                                        dst=?ip_hdr.destination_addr(),
                                        "Dropping drasyl control plane packet: {} -> {} (control traffic filtered)",
                                        ip_hdr.source_addr(),
                                        ip_hdr.destination_addr()
                                    );
                                    continue;
                                }

                                let source = IpNet::from(IpAddr::V4(ip_hdr.source_addr()));
                                if let Some((source_trie_entry_source, source_trie)) = network_inner_clone.trie_tx.load().longest_match(&source) {
                                    trace!(
                                        src=?ip_hdr.source_addr(),
                                        dst=?ip_hdr.destination_addr(),
                                        "Found source trie entry with net {}",
                                        source_trie_entry_source
                                    );
                                    let dest_addr = ip_hdr.destination_addr();

                                    #[cfg(target_os = "macos")]
                                    if ip == dest_addr {
                                        // loopback
                                        if let Err(e) = dev_clone.send(buf).await {
                                            warn!(
                                                src=?ip_hdr.source_addr(),
                                                dst=?ip_hdr.destination_addr(),
                                                tun_device=?dev_clone.name().unwrap_or("unknown".to_string()),
                                                error=?e,
                                                "Failed to send loopback packet to TUN device: {}", e
                                            );
                                        }
                                        continue;
                                    }
                                    let dest = IpNet::from(IpAddr::V4(dest_addr));
                                    if let Some((_, send_handle)) = source_trie.longest_match(&dest)
                                    {
                                        if let Err(e) = tun_tx.try_send((buf.to_vec(), send_handle.clone())) {
                                            warn!(
                                                src=?ip_hdr.source_addr(),
                                                dst=?ip_hdr.destination_addr(),
                                                error=?e,
                                                "Failed to forward packet to drasyl: {}", e
                                            );
                                        }
                                        else {
                                            trace!(
                                                src=?ip_hdr.source_addr(),
                                                dst=?ip_hdr.destination_addr(),
                                                "Successfully forwarded packet to drasyl: {} -> {}",
                                                ip_hdr.source_addr(),
                                                ip_hdr.destination_addr()
                                            );
                                        }
                                    } else {
                                        warn!(
                                            src=?ip_hdr.source_addr(),
                                            dst=?ip_hdr.destination_addr(),
                                            "No outbound route found for destination: {} -> {} (missing destination route in routing table)",
                                            ip_hdr.source_addr(),
                                            ip_hdr.destination_addr()
                                        );
                                    }
                                }
                                else {
                                    warn!(
                                        src=?ip_hdr.source_addr(),
                                        dst=?ip_hdr.destination_addr(),
                                        "No outbound route found for source: {} -> {} (source IP not in routing table)",
                                        ip_hdr.source_addr(),
                                        ip_hdr.destination_addr()
                                    );
                                }
                            }
                        }
                    } => {}
                }
            });
        }

        tokio::select! {
            _ = cancellation_token.cancelled() => {}
            _ = node.cancelled() => {
                cancellation_token.cancel();
            }
        }
    }

    pub(crate) async fn remove_routes(routes_handle: Arc<Handle>, routes: EffectiveRoutingList) {
        Self::update_routes(routes_handle, Some(routes), None).await;
    }

    async fn update_routes(
        routes_handle: Arc<Handle>,
        current_routes: Option<EffectiveRoutingList>,
        desired_routes: Option<EffectiveRoutingList>,
    ) -> EffectiveRoutingList {
        let mut applied_routes = EffectiveRoutingList::default();
        trace!(
            "Routes change: current={:?}; desired={:?}",
            current_routes, desired_routes
        );

        // clean up old routes
        if let Some(current_routes) = current_routes.as_ref() {
            for (dest, route) in current_routes.iter() {
                match desired_routes.as_ref() {
                    Some(desired_routes) if desired_routes.contains(dest) => {
                        applied_routes.add(route.as_applied_route());
                    }
                    _ => {
                        trace!("delete route: {:?}", route);
                        let net_route = route.net_route();
                        if let Err(e) = routes_handle.delete(&net_route).await {
                            warn!("Failed to delete route {:?}: {}", route, e);
                            applied_routes.add(route.as_removing_route());
                        }
                    }
                }
            }
        }

        if let Some(desired_routes) = desired_routes.as_ref() {
            if let Ok(existing_routes) = routes_handle.list().await {
                for (_, route) in desired_routes.iter() {
                    let net_route = route.net_route();
                    let existing = existing_routes.iter().any(|route| {
                        net_route.destination == route.destination
                            && net_route.prefix == route.prefix
                            && net_route.gateway == route.gateway
                    });
                    if existing {
                        trace!("route does already exist: {:?}", route);
                        applied_routes.add(route.as_applied_route());
                    } else {
                        trace!("add route: {:?}", route);
                        if let Err(e) = routes_handle.add(&net_route).await {
                            warn!("Failed to add route {:?}: {}", route, e);
                            applied_routes.add(route.as_pending_route());
                        } else {
                            applied_routes.add(route.as_applied_route());
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

#[cfg(all(feature = "dns", any(target_os = "macos", target_os = "linux")))]
async fn update_hosts_file(inner: Arc<SdnNodeInner>) -> Result<(), Error> {
    // read existing /etc/hosts
    let hosts_content = fs::read_to_string("/etc/hosts")?;
    trace!("read /etc/hosts");

    // filter out existing drasyl entries
    let lines: Vec<&str> = hosts_content
        .lines()
        .filter(|line| !line.contains("# managed by drasyl"))
        .collect();

    // create temporary file next to /etc/hosts
    let temp_path = "/etc/.hosts.drasyl";
    let mut temp_file = fs::File::create(temp_path)?;
    trace!("created temporary file at {}", temp_path);

    // write existing entries
    for line in lines {
        writeln!(temp_file, "{}", line)?;
    }

    for (_, network) in inner.networks.lock().await.iter() {
        if let Some(hostnames) = network.state.as_ref().map(|state| state.hostnames.clone()) {
            for (ip, hostname) in hostnames {
                writeln!(
                    temp_file,
                    "{:<15} {} {}.drasyl.network   # managed by drasyl",
                    ip, hostname, hostname
                )?;
            }
        }
    }
    trace!("added new drasyl entries");

    // write file directly
    fs::rename(temp_path, "/etc/hosts")?;
    trace!("updated /etc/hosts");

    Ok(())
}

#[cfg(all(feature = "dns", any(target_os = "macos", target_os = "linux")))]
pub(crate) fn cleanup_hosts_file() -> Result<(), Error> {
    // read existing /etc/hosts
    let hosts_content = fs::read_to_string("/etc/hosts")?;
    trace!("read /etc/hosts");

    // filter out drasyl entries
    let lines: Vec<&str> = hosts_content
        .lines()
        .filter(|line| !line.contains("# managed by drasyl"))
        .collect();

    // create temporary file next to /etc/hosts
    let temp_path = "/etc/.hosts.drasyl";
    let mut temp_file = fs::File::create(temp_path)?;
    trace!("created temporary file at {}", temp_path);

    // write remaining entries
    for line in lines {
        writeln!(temp_file, "{}", line)?;
    }

    // write file directly
    fs::rename(temp_path, "/etc/hosts")?;
    trace!("cleaned up /etc/hosts");

    Ok(())
}
