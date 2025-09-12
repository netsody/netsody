use crate::agent::{AgentConfig, AgentInner, Error, is_drasyl_control_packet};
use etherparse::Ipv4HeaderSlice;
use ipnet::IpNet;
use p2p::util;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{Level, enabled, error, trace, warn};
use tun_rs::AsyncDevice as TunDevice;

impl AgentInner {
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    pub(crate) fn create_tun_device(config: &AgentConfig) -> Result<Arc<TunDevice>, Error> {
        // create tun device
        // options
        let mtu = config.mtu.unwrap_or(AgentConfig::default_mtu());

        // create tun device
        trace!("Create TUN device");
        let mut dev_builder = tun_rs::DeviceBuilder::new().mtu(mtu);
        if cfg!(any(target_os = "windows", target_os = "linux")) {
            dev_builder = dev_builder.name("drasyl");
        } else if cfg!(target_os = "macos") {
            dev_builder = dev_builder.name("utun112");
        }
        #[cfg(target_os = "linux")]
        let tun_device = Arc::new(dev_builder.multi_queue(true).build_async()?);
        #[cfg(not(target_os = "linux"))]
        let tun_device = Arc::new(dev_builder.build_async()?);
        trace!("TUN device created: {:?}", tun_device.name());

        Ok(tun_device)
    }

    pub(crate) async fn tun_runner(
        inner: Arc<AgentInner>,
        cancellation_token: CancellationToken,
    ) -> Result<(), String> {
        let tun_tx = inner.tun_tx.clone();

        // options
        let tun_threads = util::get_env("TUN_THREADS", 3);
        let mtu = inner.mtu;

        let mut join_set = JoinSet::new();

        let device = inner.tun_device.clone();

        // tun <-> drasyl packet processing
        #[allow(unused_variables)]
        for i in 0..tun_threads {
            // tun -> channel
            #[cfg(target_os = "linux")]
            let device = if i == 0 {
                device.clone()
            } else {
                Arc::new(device.try_clone().unwrap())
            };
            let dev_clone = device.clone();
            let tun_tx = tun_tx.clone();
            let cancellation_token_clone = cancellation_token.clone();
            let inner_clone = inner.clone();
            join_set.spawn(async move {
                tokio::select! {
                    biased;
                    _ = cancellation_token_clone.cancelled() => {
                        trace!("Token cancelled. Exiting tun <-> drasyl packet processing task ({}/{}).", i + 1, tun_threads);
                        Ok(())
                    }
                    result = async move {
                        trace!("tun <-> drasyl packet processing task started ({}/{}).", i + 1, tun_threads);
                        let mut buf = vec![0u8; mtu as usize];
                        loop {
                            match dev_clone.recv(&mut buf).await {
                                Ok(size) => {
                                    let buf = &buf[..size];
                                    if let Ok(ip_hdr) = Ipv4HeaderSlice::from_slice(buf) {
                                        if enabled!(Level::TRACE) {
                                            trace!(
                                                src=?ip_hdr.source_addr(),
                                                dst=?ip_hdr.destination_addr(),
                                                payload_len=?buf.len(),
                                                "Forwarding packet from TUN device to drasyl: {} -> {} ({} bytes)",
                                                ip_hdr.source_addr(),
                                                ip_hdr.destination_addr(),
                                                buf.len()
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
                                        if let Some((source_trie_entry_source, source_trie)) = inner_clone.trie_tx.load().longest_match(&source) {
                                            trace!(
                                                src=?ip_hdr.source_addr(),
                                                dst=?ip_hdr.destination_addr(),
                                                "Found source trie entry with net {}",
                                                source_trie_entry_source
                                            );
                                            let dest_addr = ip_hdr.destination_addr();

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
                                                #[cfg(feature = "dns")]
                                                {
                                                    use crate::agent::dns::AgentDnsInterface;
                                                    use etherparse::ip_number::UDP;
                                                    use etherparse::UdpHeaderSlice;

                                                    // filter DNS messages
                                                    trace!("Filter DNS messages");
                                                    if ip_hdr.protocol() == UDP && inner_clone.dns.is_server_ip(ip_hdr.destination_addr()) {
                                                        // get IP payload
                                                        let payload = &buf[ip_hdr.slice().len()..];
                                                        if let Ok(udp_hdr) = UdpHeaderSlice::from_slice(payload)
                                                            && udp_hdr.destination_port() == 53 {
                                                            trace!("Got potential DNS request: {} -> {}", ip_hdr.source_addr(), ip_hdr.destination_addr());
                                                            // get UDP payload
                                                            let payload = &payload[udp_hdr.slice().len()..];
                                                            if inner_clone.dns.on_packet(payload, ip_hdr.source_addr(), udp_hdr.source_port(), ip_hdr.destination_addr(), udp_hdr.destination_port(), dev_clone.clone()).await {
                                                                trace!("Packet has been processed as a DNS request. Skip further processing.");
                                                                continue;
                                                            }

                                                        }
                                                    }
                                                }

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
                                Err(e) => {
                                    error!("Failed to receive packet from TUN device: {}", e);
                                    return Err(format!("Failed to receive packet from TUN device: {}", e));
                                }
                            }
                        }
                    } => {
                        result
                    }
                }
            });
        }

        while let Some(result) = join_set.join_next().await {
            if let Err(e) = result {
                return Err(format!("TUN task failed: {}", e));
            }
        }

        trace!("TUN runner done.");
        Ok(())
    }
}
