use crate::agent::dns::AgentDns;
use crate::network::Network;
use etherparse::PacketBuilder;
use hickory_proto::ProtoError;
use hickory_proto::op::{Header, MessageType, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};
use hickory_proto::xfer::Protocol;
use hickory_server::authority::{Authority, Catalog, MessageRequest, MessageResponse, ZoneType};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::store::in_memory::InMemoryAuthority;
use std::collections::HashMap;
use std::io;
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::io::BufWriter;
use tokio::process::Command;
use tokio::sync::MutexGuard;
use tracing::{debug, error, trace};
use tun_rs::AsyncDevice;
use url::Url;

impl AgentDns {
    pub(crate) async fn update_network_hostnames_embedded(
        &self,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        // we do not support updating hostnames for a single network
        self.update_all_hostnames_embedded(networks).await;
    }

    pub(crate) async fn update_all_hostnames_embedded(
        &self,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    ) {
        // update DNS entries
        self.embedded_catalog
            .store(Arc::new(Self::build_catalog(networks)));

        for (_, network) in networks.iter() {
            if let Some(state) = network.state.as_ref() {
                if let Some(dns_server) = AgentDns::server_ip_for(state.ip, state.subnet.prefix_len()) {
                    // Add DNS configuration with scutil
                    let domains = vec!["drasyl.network", "stis25.uhh-net.de"];
                    if let Err(e) = scutil_add(&dns_server, &domains).await {
                        error!("Failed to add DNS configuration: {}", e);
                    }
                }
            }
        }
    }

    pub(crate) async fn on_packet_embedded(
        &self,
        message_bytes: &[u8],
        src: Ipv4Addr,
        src_port: u16,
        dst: Ipv4Addr,
        dst_port: u16,
        dev: Arc<AsyncDevice>,
    ) -> bool {
        let mut decoder = BinDecoder::new(message_bytes);
        trace!("Created binary decoder for DNS message");

        let src: SocketAddr = (IpAddr::V4(src), src_port).into();
        let dst: SocketAddr = (IpAddr::V4(dst), dst_port).into();
        trace!("Created source socket address: {}", src);

        // method to handle the request
        let catalog = self.embedded_catalog.load();
        trace!("Cloned DNS catalog for request handling");
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
            trace!("Using UDP protocol for DNS message");

            let request = Request::new(message, src, protocol);
            trace!("Created DNS request object");

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
            dev
        };
        trace!("Created response handler for source {}", src);

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

    pub(crate) async fn shutdown_embedded(&self) {
        if let Err(e) = scutil_remove().await {
            error!("Failed to remove DNS configuration: {}", e);
        }
    }

    #[allow(unused)]
    #[allow(clippy::unreadable_literal)]
    pub fn build_catalog(networks: &mut MutexGuard<HashMap<Url, Network>>) -> Catalog {
        let mut catalog = Catalog::new();

        let origin: Name = Name::parse("drasyl.network.", None).unwrap();
        let mut authority = InMemoryAuthority::empty(origin.clone(), ZoneType::Primary, false);
        for network in networks.values() {
            if let Some(hostnames) = network.state.as_ref().map(|state| state.hostnames.clone()) {
                for (ip, hostname) in hostnames {
                    authority.upsert_mut(
                        Record::from_rdata(
                            Name::parse(format!("{hostname}.drasyl.network.").as_str(), None)
                                .unwrap(),
                            300,
                            RData::A(A(ip)),
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
            Self::encode_fallback_servfail_response(id, &mut buffer)
        })?;

        // Create a UDP packet with the DNS response
        let src_ip = match self.src.ip() {
            IpAddr::V4(ip) => ip,
            _ => {
                return Err(Error::new(ErrorKind::InvalidInput, "src: Only IPv4 supported"));
            }
        };
        let dst_ip = match self.dst.ip() {
            IpAddr::V4(ip) => ip,
            _ => {
                return Err(Error::new(ErrorKind::InvalidInput, "dst: Only IPv4 supported"));
            }
        };

        let builder = PacketBuilder::ipv4(
            src_ip.octets(),   // Source IP (DNS server)
            dst_ip.octets(),   // Destination IP
            64,     // TTL
        )
        .udp(
            self.src.port(),   // Source Port (DNS Server)
            self.dst.port(),   // Destination Port
        );

        // Serialize the packet
        let mut packet = Vec::with_capacity(builder.size(buffer.len()));
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
pub async fn scutil_add(dns_ip: &Ipv4Addr, domains: &[&str]) -> Result<(), String> {
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
    script.push_str("set State:/Network/Service/drasyl/DNS\n");
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
pub async fn scutil_remove() -> Result<(), String> {
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

    let script = "remove State:/Network/Service/drasyl/DNS\nquit\n";

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
