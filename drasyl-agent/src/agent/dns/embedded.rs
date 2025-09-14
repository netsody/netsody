use crate::agent::PlatformDependent;
use crate::agent::dns::AgentDnsInterface;
use crate::network::Network;
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
use hickory_server::store::forwarder::{ForwardAuthority, ForwardConfig};
use hickory_server::store::in_memory::InMemoryAuthority;
use ipnet::Ipv4Net;
use std::collections::HashMap;
use std::io;
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering::SeqCst;
use tokio::io::AsyncWriteExt;
use tokio::io::BufWriter;
use tokio::process::Command;
use tokio::runtime::Handle;
use tokio::sync::MutexGuard;
use tracing::{Level, debug, enabled, error, instrument, trace};
use tun_rs::AsyncDevice;
use url::Url;

const SCUTIL_DNS_KEY: &str = "/Network/Service/drasyl/DNS";

pub struct AgentDns {
    embedded_catalog: ArcSwap<Catalog>,
    server_ip: AtomicU32,
    upstream_servers: NameServerConfigGroup,
}

impl AgentDns {
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
                use tokio::net::lookup_host;
                use tokio::time::{Duration, timeout};
                use tracing::warn;

                // Create platform DNS servers fallback (used in multiple places)
                let platform_servers = NameServerConfigGroup::from(
                    platform_dependent
                        .dns_servers
                        .iter()
                        .map(|&ip| NameServerConfig::new(SocketAddr::from((ip, 53)), Protocol::Udp))
                        .collect::<Vec<_>>(),
                );

                if !platform_dependent.dot_server.is_empty() {
                    // Resolve DoT server hostname and use TLS
                    trace!(
                        "DoT server configured, resolving hostname '{}'",
                        platform_dependent.dot_server
                    );
                    match timeout(
                        Duration::from_millis(5000),
                        lookup_host((&*platform_dependent.dot_server, 853)),
                    )
                    .await
                    {
                        Ok(Ok(addrs)) => {
                            let ips: Vec<IpAddr> = addrs.map(|addr| addr.ip()).collect();
                            if ips.is_empty() {
                                warn!(
                                    "No IP addresses found for DoT server '{}'. Falling back to DNS servers.",
                                    platform_dependent.dot_server
                                );
                                platform_servers
                            } else {
                                trace!(
                                    "Resolved DoT server '{}' to IPs: {:?}",
                                    platform_dependent.dot_server, ips
                                );
                                NameServerConfigGroup::from_ips_tls(
                                    &ips,
                                    853,
                                    platform_dependent.dot_server.clone(),
                                    true,
                                )
                            }
                        }
                        Ok(Err(e)) => {
                            warn!(
                                "Failed to resolve DoT server '{}': {}. Falling back to DNS servers.",
                                platform_dependent.dot_server, e
                            );
                            platform_servers
                        }
                        Err(_) => {
                            warn!(
                                "Timeout while resolving DoT server '{}'. Falling back to DNS servers.",
                                platform_dependent.dot_server
                            );
                            platform_servers
                        }
                    }
                } else {
                    // Use platform DNS servers if no DoT server configured
                    trace!("No DoT server configured, using DNS servers");
                    platform_servers
                }
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

    #[allow(unused)]
    #[allow(clippy::unreadable_literal)]
    fn build_catalog(
        &self,
        networks: &mut MutexGuard<HashMap<Url, Network>>,
        upstream_servers: &NameServerConfigGroup,
    ) -> Catalog {
        trace!("Building DNS catalog");
        let mut catalog = Catalog::new();

        trace!("Using upstream servers: {:?}", upstream_servers);

        // Add ForwardAuthority for root zone first (catches all queries not handled by specific zones)
        // Only if upstream servers are configured
        if !upstream_servers.is_empty() {
            let root_name = Name::parse(".", None).unwrap();
            let forward_config = ForwardConfig {
                name_servers: upstream_servers.clone(),
                options: Some(ResolverOpts::default()),
            };
            let forward_authority = ForwardAuthority::builder_tokio(forward_config)
                .build()
                .expect("Failed to create ForwardAuthority");
            catalog.upsert(root_name.into(), vec![Arc::new(forward_authority)]);
            trace!(
                "Added ForwardAuthority for root zone with upstream DNS forwarding: {:?}",
                upstream_servers
            );
        } else {
            trace!("No upstream servers configured, skipping ForwardAuthority for root zone");
        }

        // Add local drasyl.network zone
        let origin: Name = Name::parse("drasyl.network.", None).unwrap();
        let mut authority = InMemoryAuthority::empty(origin.clone(), ZoneType::External, false);

        for network in networks.values() {
            if let Some(hostnames) = network.state.as_ref().map(|state| state.hostnames.clone()) {
                for (ip, hostname) in hostnames {
                    trace!("Adding DNS A record: {}.drasyl.network -> {}", hostname, ip);
                    authority.upsert_mut(
                        Record::from_rdata(
                            Name::parse(format!("{hostname}.drasyl.network.").as_str(), None)
                                .unwrap(),
                            60,
                            RData::A(A(ip)),
                        )
                        .set_dns_class(DNSClass::IN)
                        .clone(),
                        0,
                    );
                }
            }
        }
        catalog.upsert(authority.origin().clone().into(), vec![Arc::new(authority)]);

        catalog
    }
}

impl AgentDnsInterface for AgentDns {
    fn server_ip(&self) -> Option<Ipv4Addr> {
        Some(Ipv4Addr::from(self.server_ip.load(SeqCst)))
    }

    fn is_server_ip(&self, ip: Ipv4Addr) -> bool {
        if enabled!(Level::TRACE) {
            trace!(
                "Checking if IP {} is the DNS server IP {}",
                ip,
                Ipv4Addr::from(self.server_ip.load(SeqCst))
            );
        }
        let server_ip = self.server_ip.load(SeqCst);
        server_ip != 0 && server_ip == ip.to_bits()
    }

    async fn shutdown(&self) {
        trace!("Shutting down DNS");
        #[cfg(target_os = "macos")]
        {
            if let Err(e) = scutil_remove().await {
                error!("Failed to remove DNS configuration: {}", e);
            }
        }
    }

    async fn update_network_hostnames(&self, networks: &mut MutexGuard<'_, HashMap<Url, Network>>) {
        // we do not support updating hostnames for a single network
        self.update_all_hostnames(networks).await;
    }

    async fn update_all_hostnames(&self, networks: &mut MutexGuard<'_, HashMap<Url, Network>>) {
        trace!("Update all hostnames");

        // update DNS entries
        self.embedded_catalog.store(Arc::new(
            self.build_catalog(networks, &self.upstream_servers),
        ));

        let mut i = 0;
        for (_, network) in networks.iter() {
            if !network.disabled
                && let Some(state) = network.state.as_ref()
                && i == 0
            {
                // Calculate DNS server IP: it's the IP address in the current subnet BEFORE the broadcast address
                let network = Ipv4Net::new(state.ip, state.subnet.prefix_len())
                    .expect("Invalid IP/netmask combination");
                let broadcast = network.broadcast();
                // Decrement the broadcast address by 1 to get the DNS server IP
                let dns_server = Ipv4Addr::from(u32::from(broadcast).saturating_sub(1));
                trace!("DNS server IP calculated: {}", dns_server);

                self.server_ip.store(dns_server.to_bits(), SeqCst);

                #[cfg(target_os = "macos")]
                {
                    // Add DNS configuration with scutil
                    let domains = vec!["drasyl.network"];
                    if let Err(e) = scutil_add(&dns_server, &domains).await {
                        error!("Failed to add DNS configuration: {}", e);
                    }
                }

                i += 1;
            }
        }
    }

    async fn on_packet(
        &self,
        message_bytes: &[u8],
        src: Ipv4Addr,
        src_port: u16,
        dst: Ipv4Addr,
        dst_port: u16,
        dev: Arc<AsyncDevice>,
    ) -> bool {
        trace!(
            src=?src,
            src_port=?src_port,
            dst=?dst,
            dst_port=?dst_port,
            len=?message_bytes.len(),
            "Received DNS packet from {}:{} ({} bytes)",
            src,
            src_port,
            message_bytes.len()
        );

        trace!("Processing DNS packet using embedded DNS");
        let mut decoder = BinDecoder::new(message_bytes);

        let src: SocketAddr = (IpAddr::V4(src), src_port).into();
        let dst: SocketAddr = (IpAddr::V4(dst), dst_port).into();

        // method to handle the request
        let catalog = self.embedded_catalog.load();
        let inner_handle_request = |message: MessageRequest, response_handler: ResponseHandle| async move {
            if message.message_type() == MessageType::Response {
                trace!("Dropping DNS response message to prevent reflection attacks");
                return;
            }
            trace!("Processing DNS query message");

            let id = message.id();
            let qflags = message.header().flags();
            let qop_code = message.op_code();
            let message_type = message.message_type();
            let is_dnssec = message.edns().is_some_and(|edns| edns.flags().dnssec_ok);
            trace!(
                id=?id,
                // flags=?qflags,
                op_code=?qop_code,
                message_type=?message_type,
                dnssec=?is_dnssec,
                "Parsed DNS message details"
            );

            let protocol = Protocol::Udp;

            let request = Request::new(message, src, protocol);

            debug!(
                "request:{id} src:{proto}://{addr}#{port} type:{message_type} dnssec:{is_dnssec} {op} qflags:{qflags}",
                id = id,
                proto = protocol,
                addr = src.ip(),
                port = src.port(),
                message_type = message_type,
                is_dnssec = is_dnssec,
                op = qop_code,
                qflags = qflags
            );

            for query in request.queries().iter() {
                trace!(
                    query=?query.name(),
                    qtype=?query.query_type(),
                    class=?query.query_class(),
                    "Processing DNS query"
                );
                debug!(
                    "query:{query}:{qtype}:{class}",
                    query = query.name(),
                    qtype = query.query_type(),
                    class = query.query_class()
                );
            }

            trace!("Handling DNS request with catalog");
            catalog.handle_request(&request, response_handler).await;
            trace!("DNS request handling completed");
        };

        let reporter = ResponseHandle {
            src: dst,
            dst: src,
            dev,
        };

        match MessageRequest::read(&mut decoder) {
            Ok(message) => {
                trace!("Successfully decoded DNS message");
                inner_handle_request(message, reporter).await;
            }
            Err(e) => {
                error!("Failed to decode DNS message: {}", e);
            }
        }
        trace!("DNS packet processing completed");
        true
    }
}

#[derive(Clone)]
pub struct ResponseHandle {
    src: SocketAddr,
    dst: SocketAddr,
    dev: Arc<AsyncDevice>,
}

impl ResponseHandle {
    /// Selects an appropriate maximum serialized size for the given response.
    fn max_size_for_response<'a>(
        &self,
        response: &MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> u16 {
        // Use EDNS, if available.
        if let Some(edns) = response.get_edns() {
            edns.max_payload()
        } else {
            // No EDNS, use the recommended max from RFC6891.
            hickory_proto::udp::MAX_RECEIVE_BUFFER_SIZE as u16
        }
    }

    /// Clears the buffer, encodes a SERVFAIL response in it, and returns a matching
    /// ResponseInfo.
    fn encode_fallback_servfail_response(
        id: u16,
        buffer: &mut Vec<u8>,
    ) -> Result<ResponseInfo, ProtoError> {
        buffer.clear();
        let mut encoder = BinEncoder::new(buffer);
        encoder.set_max_size(512);
        let mut header = Header::new();
        header.set_id(id);
        header.set_response_code(ResponseCode::ServFail);
        header.emit(&mut encoder)?;

        let mut header1 = Header::new();
        header1.set_response_code(ResponseCode::ServFail);
        Ok(header1.into())
    }
}

#[async_trait::async_trait]
impl ResponseHandler for ResponseHandle {
    #[instrument(fields(id = %response.header().id()), skip_all)]
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> io::Result<ResponseInfo> {
        let id = response.header().id();
        trace!("Starting DNS response encoding for ID: {}", id);
        debug!(
            id,
            response_code = %response.header().response_code(),
            "sending response",
        );

        let mut buffer = Vec::with_capacity(512);

        let encode_result = {
            let mut encoder = BinEncoder::new(&mut buffer);

            // Set an appropriate maximum on the encoder.
            let max_size = self.max_size_for_response(&response);
            trace!(
                "setting response max size: {max_size} for protocol: {:?}",
                Protocol::Udp
            );
            encoder.set_max_size(max_size);

            response.destructive_emit(&mut encoder)
        };

        let info = encode_result.or_else(|error| {
            error!(%error, "error encoding message");
            trace!("Falling back to SERVFAIL response due to encoding error");
            Self::encode_fallback_servfail_response(id, &mut buffer)
        })?;

        // Create a UDP packet with the DNS response
        let src_ip = match self.src.ip() {
            IpAddr::V4(ip) => ip,
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "src: Only IPv4 supported",
                ));
            }
        };

        let dst_ip = match self.dst.ip() {
            IpAddr::V4(ip) => ip,
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "dst: Only IPv4 supported",
                ));
            }
        };

        let builder = PacketBuilder::ipv4(
            src_ip.octets(), // Source IP (DNS server)
            dst_ip.octets(), // Destination IP
            64,              // TTL
        )
        .udp(
            self.src.port(), // Source Port (DNS Server)
            self.dst.port(), // Destination Port
        );

        // Serialize the packet
        let packet_size = builder.size(buffer.len());
        let mut packet = Vec::with_capacity(packet_size);
        builder
            .write(&mut packet, &buffer)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

        // Send the packet to the TUN device
        self.dev.send(&packet).await?;

        Ok(info)
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
async fn scutil_add(dns_ip: &Ipv4Addr, domains: &[&str]) -> Result<(), String> {
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

/// Removes DNS configuration using scutil (macOS).
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(String)` with error message on failure
async fn scutil_remove() -> Result<(), String> {
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
