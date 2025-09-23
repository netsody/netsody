use crate::agent::dns::AgentDnsInterface;
#[cfg(target_os = "macos")]
use crate::agent::dns::macos::{scutil_add, scutil_exists, scutil_remove};
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
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering::SeqCst;
use tokio::sync::MutexGuard;
use tracing::{Level, debug, enabled, error, instrument, trace};
use tun_rs::AsyncDevice;
use url::Url;

pub struct AgentDns {
    embedded_catalog: ArcSwap<Catalog>,
    server_ip: AtomicU32,
    upstream_servers: NameServerConfigGroup,
}

impl AgentDns {
    #[allow(unused_variables)]
    pub(crate) fn new(platform_dependent: Arc<PlatformDependent>) -> Self {
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

    #[allow(unused)]
    #[allow(clippy::unreadable_literal)]
    fn build_catalog(
        &self,
        networks: &mut MutexGuard<HashMap<Url, Network>>,
        upstream_servers: &NameServerConfigGroup,
    ) -> Catalog {
        trace!("Building DNS catalog");
        let mut catalog = Catalog::new();

        #[cfg(target_os = "android")]
        {
            use hickory_server::store::forwarder::{ForwardAuthority, ForwardConfig};

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
        }

        // Add local netsody.me zone
        let origin: Name = Name::parse("netsody.me.", None).unwrap();
        let mut authority = InMemoryAuthority::empty(origin.clone(), ZoneType::External, false);

        for network in networks.values() {
            if let Some(hostnames) = &network.desired_state.hostnames.applied {
                for (ip, hostname) in hostnames.0.iter() {
                    trace!("Adding DNS A record: {}.netsody.me -> {}", hostname, ip);
                    authority.upsert_mut(
                        Record::from_rdata(
                            Name::parse(format!("{hostname}.netsody.me.").as_str(), None).unwrap(),
                            60,
                            RData::A(A(*ip)),
                        )
                        .set_dns_class(DNSClass::IN)
                        .clone(),
                        0,
                    );
                }
            }
        }
        catalog.upsert(authority.origin().clone(), vec![Arc::new(authority)]);

        catalog
    }

    async fn update_all_networks(&self, networks: &mut MutexGuard<'_, HashMap<Url, Network>>) {
        trace!("Update all hostnames");

        // update DNS entries
        self.embedded_catalog.store(Arc::new(
            self.build_catalog(networks, &self.upstream_servers),
        ));

        // Update network states first
        for (_, network) in networks.iter_mut() {
            network.current_state.hostnames = network.desired_state.hostnames.clone();
        }

        // "assign" IP address to the DNS server if needed
        let ip = networks.values().find_map(|network| {
            if !network.disabled {
                network.current_state.ip.applied
            } else {
                None
            }
        });

        if let Some(ip) = ip {
            // Calculate DNS server IP: it's the IP address in the current subnet BEFORE the broadcast address
            let broadcast = ip.broadcast();
            // Decrement the broadcast address by 1 to get the DNS server IP
            let dns_server = Ipv4Addr::from(u32::from(broadcast).saturating_sub(1));
            trace!("DNS server IP calculated: {}", dns_server);

            self.server_ip.store(dns_server.to_bits(), SeqCst);

            #[cfg(target_os = "macos")]
            {
                // Check if any network needs DNS
                let any_network_needs_dns = networks.values().any(|network| {
                    !network.disabled && network.current_state.hostnames.applied.is_some()
                });

                // Check current DNS server state
                let dns_server_exists = match scutil_exists().await {
                    Ok(exists) => exists,
                    Err(e) => {
                        error!("Failed to check DNS server existence: {}", e);
                        for (_, network) in networks.iter_mut() {
                            network.current_state.hostnames =
                                AppliedStatus::error(format!("Failed to check DNS server: {}", e));
                        }
                        return;
                    }
                };

                if any_network_needs_dns && !dns_server_exists {
                    // Need DNS server but it doesn't exist -> add it
                    trace!("Adding DNS server because networks need DNS and server doesn't exist");
                    let domains = vec!["netsody.me"];
                    if let Err(e) = scutil_add(&dns_server, &domains).await {
                        error!("Failed to add DNS server: {}", e);
                        for (_, network) in networks.iter_mut() {
                            network.current_state.hostnames =
                                AppliedStatus::error(format!("Failed to add DNS server: {}", e));
                        }
                    }
                } else if !any_network_needs_dns && dns_server_exists {
                    // Don't need DNS server but it exists -> remove it
                    trace!("Removing DNS server because no networks need DNS but server exists");
                    if let Err(e) = scutil_remove().await {
                        error!("Failed to remove DNS server: {}", e);
                        for (_, network) in networks.iter_mut() {
                            network.current_state.hostnames =
                                AppliedStatus::error(format!("Failed to remove DNS server: {}", e));
                        }
                    }
                }
            }
        } else {
            // No IP available - set error on all networks that need DNS
            for (_, network) in networks.iter_mut() {
                if network.current_state.hostnames.applied.is_some() {
                    network.current_state.hostnames = AppliedStatus::error(
                        "Failed to add DNS server: No DNS server IP found".to_string(),
                    );
                }
            }
        }
    }
}

impl AgentDnsInterface for AgentDns {
    async fn apply_desired_state(
        &self,
        _inner: Arc<AgentInner>,
        config_url: &Url,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        #[cfg(target_os = "macos")]
        {
            use tracing::warn;

            // check if DNS server still exists
            let server_exists = scutil_exists().await;
            for (_, network) in networks.iter_mut() {
                if network.current_state.hostnames.applied.is_some() && server_exists == Ok(false) {
                    warn!("DNS server has been removed by externally.");
                    network.current_state.hostnames = AppliedStatus::error(
                        "DNS server has been removed by externally.".to_string(),
                    );
                }
            }
        }

        // we do not support updating a single network. We have to update all networks.
        if let Some(network) = networks.get_mut(config_url) {
            trace!("Update network in DNS");

            if network.current_state.hostnames != network.desired_state.hostnames {
                trace!(
                    "DNS mismatch: current={:?} desired={:?}",
                    &network.current_state.hostnames, network.desired_state.hostnames
                );
                self.update_all_networks(networks).await;
            }
        }
    }

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
