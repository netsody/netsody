use crate::agent::dns::{AgentDns, NETSODY_DOMAIN};
use crate::agent::housekeeping::HOUSEKEEPING_INTERVAL_MS;
use crate::network::Network;
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
use tokio::sync::MutexGuard;
use tracing::{Level, debug, enabled, error, instrument, trace};
use tun_rs::AsyncDevice;
use url::Url;

impl AgentDns {
    /// Build a DNS catalog with configured hostnames and optional upstream forwarding.
    ///
    /// This method constructs a DNS catalog that:
    /// - On Android: Forwards non-netsody queries to upstream DNS servers
    /// - On all platforms: Resolves *.netsody.me hostnames to configured IPs
    ///
    /// # Arguments
    /// * `networks` - Network configurations containing hostname mappings
    /// * `upstream_servers` - Upstream DNS servers for forwarding (Android only)
    ///
    /// # Returns
    /// A configured DNS catalog ready for query handling
    #[allow(unused)]
    #[allow(clippy::unreadable_literal)]
    pub(crate) fn build_catalog(
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
        let origin: Name = Name::parse(&format!("{}.", NETSODY_DOMAIN), None).unwrap();
        let mut authority = InMemoryAuthority::empty(origin.clone(), ZoneType::External, false);

        for network in networks.values() {
            if let Some(hostnames) = &network.desired_state.hostnames.applied {
                for (ip, hostname) in hostnames.0.iter() {
                    trace!("Adding DNS A record: {}.{} -> {}", hostname, NETSODY_DOMAIN, ip);
                    // Use short TTL based on housekeeping interval to ensure timely updates
                    // when network config changes, as platform resolvers may cache DNS records
                    let dns_ttl = (HOUSEKEEPING_INTERVAL_MS / 1000) as u32;
                    authority.upsert_mut(
                        Record::from_rdata(
                            Name::parse(&format!("{}.{}.", hostname, NETSODY_DOMAIN), None).unwrap(),
                            dns_ttl,
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

    /// Get the current DNS server IP address if configured.
    ///
    /// # Returns
    /// The DNS server IP, or None if not configured (stored as 0)
    pub(crate) fn server_ip(&self) -> Option<Ipv4Addr> {
        let ip_bits = self.server_ip.load(SeqCst);
        if ip_bits == 0 {
            None
        } else {
            Some(Ipv4Addr::from(ip_bits))
        }
    }

    /// Check if the given IP address matches the configured DNS server IP.
    ///
    /// # Arguments
    /// * `ip` - IP address to check
    ///
    /// # Returns
    /// `true` if the IP matches the DNS server IP, `false` otherwise
    pub(crate) fn is_server_ip(&self, ip: Ipv4Addr) -> bool {
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

    /// Handle a DNS packet received on the TUN interface.
    ///
    /// This method processes DNS queries using the embedded DNS server and
    /// sends responses back through the TUN device.
    ///
    /// # Arguments
    /// * `message_bytes` - DNS message data
    /// * `src` - Source IP address
    /// * `src_port` - Source port
    /// * `dst` - Destination IP address (DNS server)
    /// * `dst_port` - Destination port (usually 53)
    /// * `dev` - TUN device for sending responses
    ///
    /// # Returns
    /// `true` if packet was handled, `false` otherwise
    pub(crate) async fn on_packet(
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
