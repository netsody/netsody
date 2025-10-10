use crate::agent::{AgentInner, is_netsody_control_packet};
#[cfg(target_os = "windows")]
use crate::agent::dns::AgentDnsInterface;
use crate::network::Network;
use cfg_if::cfg_if;
use etherparse::Ipv4HeaderSlice;
use ipnet::IpNet;
use p2p::util;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::MutexGuard;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{Level, enabled, error, trace, warn};
use tun_rs::AsyncDevice as TunDevice;
use url::Url;

pub trait AgentNetifInterface {
    async fn apply_desired_state(
        &self,
        inner: Arc<AgentInner>,
        config_url: &Url,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    );

    async fn send(&self, buf: &[u8]) -> io::Result<usize>;

    async fn tun_runner(
        inner: Arc<AgentInner>,
        tun_device: Arc<TunDevice>,
        cancellation_token: CancellationToken,
    ) -> Result<(), String> {
        let tun_tx = inner.tun_tx.clone();

        // options
        let tun_threads = util::get_env("TUN_THREADS", 3);
        let mtu = inner.mtu;

        let mut join_set = JoinSet::new();

        let device = tun_device.clone();

        // tun -> Netsody packet processing
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
            let cancellation_token_clone2 = cancellation_token.clone();
            let inner_clone = inner.clone();
            join_set.spawn(async move {
                tokio::select! {
                    biased;
                    _ = cancellation_token_clone.cancelled() => {
                        trace!("Token cancelled. Exiting tun -> Netsody packet processing task ({}/{}).", i + 1, tun_threads);
                    }
                    result = async move {
                        trace!("tun -> Netsody packet processing task started ({}/{}).", i + 1, tun_threads);
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
                                                "Forwarding packet from TUN device to Netsody: {} -> {} ({} bytes)",
                                                ip_hdr.source_addr(),
                                                ip_hdr.destination_addr(),
                                                buf.len()
                                            );
                                        }

                                        // filter Netsody control plane messages
                                        if is_netsody_control_packet(buf) {
                                            trace!(
                                                src=?ip_hdr.source_addr(),
                                                dst=?ip_hdr.destination_addr(),
                                                "Dropping Netsody control plane packet: {} -> {} (control traffic filtered)",
                                                ip_hdr.source_addr(),
                                                ip_hdr.destination_addr()
                                            );
                                            continue;
                                        }

                                        // Check for loopback connections (source == destination)
                                        if ip_hdr.source_addr() == ip_hdr.destination_addr() {
                                            trace!(
                                                src=?ip_hdr.source_addr(),
                                                dst=?ip_hdr.destination_addr(),
                                                "Loopback packet detected: {} -> {}, sending directly back to TUN device",
                                                ip_hdr.source_addr(),
                                                ip_hdr.destination_addr()
                                            );

                                            // For loopback, send the packet directly back to the TUN device
                                            if let Err(e) = dev_clone.send(buf).await {
                                                warn!(
                                                    src=?ip_hdr.source_addr(),
                                                    dst=?ip_hdr.destination_addr(),
                                                    error=?e,
                                                    "Failed to send loopback packet back to TUN device: {}", e
                                                );
                                            } else {
                                                trace!(
                                                    src=?ip_hdr.source_addr(),
                                                    dst=?ip_hdr.destination_addr(),
                                                    "Successfully sent loopback packet back to TUN device: {} -> {}",
                                                    ip_hdr.source_addr(),
                                                    ip_hdr.destination_addr()
                                                );
                                            }
                                            continue;
                                        }

                                        let dest = IpNet::from(IpAddr::V4(ip_hdr.destination_addr()));
                                        if let Some((dest_trie_entry_source, dest_trie)) = inner_clone.trie_tx.load().longest_match(&dest) {
                                            trace!(
                                                src=?ip_hdr.source_addr(),
                                                dst=?ip_hdr.destination_addr(),
                                                "Found dest trie entry with net {}",
                                                dest_trie_entry_source
                                            );
                                            let source_addr = ip_hdr.source_addr();

                                            let source = IpNet::from(IpAddr::V4(source_addr));
                                            if let Some((_, send_handle)) = dest_trie.longest_match(&source)
                                            {
                                                if let Err(e) = tun_tx.try_send((buf.to_vec(), send_handle.clone())) {
                                                    warn!(
                                                        src=?ip_hdr.source_addr(),
                                                        dst=?ip_hdr.destination_addr(),
                                                        error=?e,
                                                        "Failed to forward packet to Netsody: {}", e
                                                    );
                                                }
                                                else {
                                                    trace!(
                                                        src=?ip_hdr.source_addr(),
                                                        dst=?ip_hdr.destination_addr(),
                                                        "Successfully forwarded packet to Netsody: {} -> {}",
                                                        ip_hdr.source_addr(),
                                                        ip_hdr.destination_addr()
                                                    );
                                                }
                                            } else {
                                                warn!(
                                                    src=?ip_hdr.source_addr(),
                                                    dst=?ip_hdr.destination_addr(),
                                                    "No outbound route found for source: {} -> {} (source IP not in routing table)",
                                                    ip_hdr.source_addr(),
                                                    ip_hdr.destination_addr()
                                                );
                                            }
                                        }
                                        else {
                                            #[cfg(feature = "dns")]
                                            {
                                                use etherparse::ip_number::UDP;
                                                use etherparse::UdpHeaderSlice;

                                                // filter DNS messages
                                                trace!("Check for DNS query to DNS server");
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
                                                // else {
                                                //     use p2p::util::bytes_to_hex;
                                                //     trace!("No DNS query to DNS server. Payload: {}", bytes_to_hex(buf));
                                                // }
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
                                }
                                Err(e) => {
                                    error!("Failed to receive packet from TUN device. Cancel token: {}", e);
                                    cancellation_token_clone2.cancel();
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

cfg_if! {
    if #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))] {
        mod desktop;
        pub use desktop::AgentNetif;
    }
    else if #[cfg(any(target_os = "ios", target_os = "tvos", target_os = "android"))] {
        mod mobile;
        pub use mobile::AgentNetif;
    }
    else {
        use tracing::warn;

        // unsupported platform
        pub struct AgentNetif {}

        impl AgentNetif {
            pub(crate) fn new() -> Self {
                Self {}
            }
        }

        impl AgentNetifInterface for AgentNetif {
            #[allow(unused_variables)]
            async fn apply_desired_state(
                &self,
                inner: Arc<AgentInner>,
                config_url: &Url,
                networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
            ) {
                warn!("NetIf is not supported on this platform. We can not update all networks.");
                for (_, network) in networks.iter_mut() {
                    network.current_state.ip =
                        AppliedStatus::error("NetIf not supported on this platform".to_string());
                }
            }
        }
    }
}
