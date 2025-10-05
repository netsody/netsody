use crate::sp::TransportProt::TCP;
use crate::sp::TransportProt::UDP;
use crate::sp::error::Error;
use crate::sp::tcp::TcpConnection;
use crate::sp::{MAX_HOP_COUNT, Peer, PeersList, SuperPeerOpts, TransportProt};
use bytes::Bytes;
use futures::SinkExt;
use p2p::crypto::{AgreementPubKey, AgreementSecKey};
use p2p::identity::PubKey;
use p2p::message::{
    AckMessage, HelloSuperPeerMessage, LongHeader, MessageType, UniteMessage,
    log_hello_super_peer_message,
};
use papaya::HashMap as PapayaHashMap;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::SeqCst;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, UdpSocket};
use tokio_util::codec::LengthDelimitedCodec;
use tokio_util::sync::CancellationToken;
use tracing::{debug, instrument, trace};

pub struct SuperPeerInner {
    pub(crate) opts: SuperPeerOpts,
    coarse_timer: AtomicU64,
    pub(crate) peers_list: PeersList,
    pub(crate) udp4_socket: Option<UdpSocket>,
    pub(crate) udp6_socket: Option<UdpSocket>,
    pub(crate) tcp4_listener: Option<TcpListener>,
    pub(crate) tcp6_listener: Option<TcpListener>,
    pub(crate) tcp_connections: PapayaHashMap<SocketAddr, Arc<TcpConnection>>,
    pub(crate) agreement_sk: Option<AgreementSecKey>,
    pub(crate) agreement_pk: Option<AgreementPubKey>,
    pub(crate) cancellation_token: CancellationToken,
}

impl SuperPeerInner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        opts: SuperPeerOpts,
        udp4_socket: Option<UdpSocket>,
        udp6_socket: Option<UdpSocket>,
        tcp4_listener: Option<TcpListener>,
        tcp6_listener: Option<TcpListener>,
        agreement_sk: Option<AgreementSecKey>,
        agreement_pk: Option<AgreementPubKey>,
        cancellation_token: CancellationToken,
    ) -> Self {
        assert!(opts.max_peers.is_power_of_two());

        let peers_list = PeersList::new(opts.max_peers);
        Self {
            opts,
            coarse_timer: AtomicU64::new(Self::clock()),
            peers_list,
            udp4_socket,
            udp6_socket,
            tcp4_listener,
            tcp6_listener,
            tcp_connections: PapayaHashMap::new(),
            agreement_sk,
            agreement_pk,
            cancellation_token,
        }
    }

    #[instrument(fields(src = %src), skip_all)]
    pub async fn on_udp_datagram(
        &self,
        src: SocketAddr,
        buf: &mut [u8],
        response_buf: &mut [u8],
    ) -> Result<(), Error> {
        self.on_packet(src, UDP, buf, response_buf).await
    }

    #[instrument(fields(src = %src), skip_all)]
    pub async fn on_tcp_segment(
        &self,
        src: SocketAddr,
        buf: &mut [u8],
        response_buf: &mut [u8],
    ) -> Result<(), Error> {
        self.on_packet(src, TCP, buf, response_buf).await
    }

    pub(crate) async fn on_packet(
        &self,
        src: SocketAddr,
        prot: TransportProt,
        buf: &mut [u8],
        response_buf: &mut [u8],
    ) -> Result<(), Error> {
        // long header
        let (long_header, body_slice) = LongHeader::parse(buf)?;

        // network id
        if long_header.network_id != self.opts.network_id {
            return Err(Error::NetworkIdInvalid(long_header.network_id));
        }

        // recipient
        if long_header.recipient == self.opts.id.pk {
            if long_header.is_armed() ^ self.opts.arm_messages {
                return Err(if self.opts.arm_messages {
                    Error::MessageUnarmed
                } else {
                    Error::MessageArmed
                });
            }

            // the guard makes it necessary to put the following in a separate scope
            let ack_len = {
                let guard = self.peers_list.peers_guard();
                let peer = self.peers_list.get_or_insert_peer(
                    &long_header.sender,
                    &long_header.pow,
                    self,
                    &guard,
                )?;

                // pow
                if peer.has_invalid_pow() {
                    return Err(Error::PowInvalid);
                }

                // only HELLO is allowed
                if long_header.message_type != MessageType::HELLO {
                    return Err(Error::MessageTypeUnexpected(long_header.message_type));
                }

                // HELLO body
                let hello = HelloSuperPeerMessage::parse(body_slice, long_header, peer.rx_key())?;

                self.on_hello(src, prot, response_buf, long_header, peer, hello)?
            };

            self.send(long_header.sender, prot, src, &response_buf[..ack_len])
                .await?;

            Ok(())
        } else {
            // try forwarding
            trace!("Not for us, try forwarding.");

            // only ACK/APP/HELLO are allowed
            if long_header.message_type != MessageType::ACK
                && long_header.message_type != MessageType::APP
                && long_header.message_type != MessageType::HELLO
            {
                return Err(Error::MessageTypeUnexpected(long_header.message_type));
            }

            let message_type = long_header.message_type;

            #[cfg(feature = "prometheus")]
            {
                use crate::prometheus::record_message_metric;
                record_message_metric(message_type, &long_header.sender, true, true);
            }

            // sender wants to forward to themselves :)
            if long_header.recipient == long_header.sender {
                return Err(Error::LoopbackForwarding);
            }

            // verify if hop count is exceeded
            if long_header.hop_count > MAX_HOP_COUNT {
                debug!(
                    "Forwarding failed as hop count limit exceeded from peer {} to {}.",
                    long_header.sender, long_header.recipient
                );
                return Ok(());
            }

            let sender_key = long_header.sender;
            let recipient_key = long_header.recipient;

            // the guard makes it necessary to put the following in a separate scope
            let result = {
                // search recipient
                let guard = self.peers_list.peers_guard();
                if let Some(recipient) = self.peers_list.get_peer(&recipient_key, &guard) {
                    long_header.hop_count += 1;

                    // forward message
                    if let Some((prot, addr)) = recipient.endpoint() {
                        Some((recipient_key, prot, addr, buf))
                    } else {
                        None
                    }
                } else {
                    trace!("Recipient unknown. Discard packet.");
                    None
                }
            };

            if let Some((recipient_key, prot, dst, buf)) = result {
                #[cfg(feature = "prometheus")]
                {
                    use crate::prometheus::{PROMETHEUS_RELAYED_BYTES, record_message_metric};
                    record_message_metric(message_type, &recipient_key, false, true);
                    if message_type == MessageType::APP {
                        PROMETHEUS_RELAYED_BYTES
                            .with_label_values(&[sender_key.to_string(), recipient_key.to_string()])
                            .inc_by(buf.len() as f64);
                    }
                }

                self.relay_message(sender_key, recipient_key, message_type, prot, dst, buf)
                    .await?;

                if message_type == MessageType::APP {
                    return self.try_unite(&sender_key, &recipient_key).await;
                }
            }

            Ok(())
        }
    }

    #[instrument(fields(peer = %sender_key), skip_all)]
    async fn relay_message(
        &self,
        sender_key: PubKey,
        recipient_key: PubKey,
        message_type: MessageType,
        prot: TransportProt,
        dst: SocketAddr,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        self.send(recipient_key, prot, dst, buf).await?;
        debug!("Forwarded message of type {message_type} from {sender_key} to {recipient_key}");
        Ok(())
    }

    #[instrument(fields(peer = %long_header.sender), skip_all)]
    fn on_hello(
        &self,
        src: SocketAddr,
        prot: TransportProt,
        response_buf: &mut [u8],
        long_header: &LongHeader,
        peer: &Peer,
        hello: &HelloSuperPeerMessage,
    ) -> Result<usize, Error> {
        log_hello_super_peer_message(long_header, hello);

        #[cfg(feature = "prometheus")]
        {
            use crate::prometheus::record_message_metric;
            record_message_metric(MessageType::HELLO, &long_header.sender, true, false);
        }

        // time
        let time = self.current_time();

        let hello_time = hello.time.get();
        let time_diff = time.saturating_sub(hello_time);
        if time_diff > (self.opts.hello_max_age * 1_000) {
            return Err(Error::HelloTimeInvalid(long_header.sender, time_diff));
        }

        // update peer information
        peer.hello_tx(time, src, prot, &hello.endpoints);

        trace!("Got HELLO. Reply with ACK");

        #[cfg(feature = "prometheus")]
        {
            use crate::prometheus::record_message_metric;
            record_message_metric(MessageType::ACK, &long_header.sender, false, false);
        }

        // reply with ACK
        Ok(AckMessage::build(
            response_buf,
            &self.opts.network_id,
            &self.opts.id.pk,
            &self.opts.id.pow,
            peer.tx_key(),
            &long_header.sender,
            hello_time,
        )?)
    }

    #[instrument(fields(peer = %sender_key), skip_all)]
    async fn try_unite(&self, sender_key: &PubKey, recipient_key: &PubKey) -> Result<(), Error> {
        let time = self.cached_time();

        // check if we want (and can) help both peers to communicate directly
        if !self
            .peers_list
            .send_unites(sender_key, recipient_key, time, self.opts.send_unites)
        {
            return Ok(());
        }

        // the guard makes it necessary to but the following in a separate scope
        let (sender_send, recipient_send) = {
            // check if sender is known
            let guard = self.peers_list.peers_guard();
            if let (Some(sender), Some(recipient)) = (
                self.peers_list.get_peer(sender_key, &guard),
                self.peers_list.get_peer(recipient_key, &guard),
            ) {
                if let (Some((sender_prot, sender_addr)), Some((recipient_prot, recipient_addr))) =
                    (sender.endpoint(), recipient.endpoint())
                {
                    // send sender all information we have to reach recipient
                    let recipient_candidates: &[u8] = &recipient.contact_candidates();
                    let sender_unite = UniteMessage::build(
                        &self.opts.network_id,
                        &self.opts.id.pk,
                        &self.opts.id.pow,
                        sender.tx_key(),
                        sender_key,
                        recipient_key,
                        recipient_candidates,
                    )?;

                    // send recipient all information we have to reach sender
                    let sender_candidates: &[u8] = &sender.contact_candidates();
                    let recipient_unite = UniteMessage::build(
                        &self.opts.network_id,
                        &self.opts.id.pk,
                        &self.opts.id.pow,
                        recipient.tx_key(),
                        recipient_key,
                        sender_key,
                        sender_candidates,
                    )?;

                    let sender_send = (sender_prot, sender_addr, sender_unite);
                    let recipient_send = (recipient_prot, recipient_addr, recipient_unite);

                    (Some(sender_send), Some(recipient_send))
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            }
        };

        if let (Some(sender_send), Some(recipient_send)) = (sender_send, recipient_send) {
            #[cfg(feature = "prometheus")]
            {
                use crate::prometheus::record_message_metric;
                record_message_metric(MessageType::UNITE, sender_key, false, false);
                record_message_metric(MessageType::UNITE, recipient_key, false, false);
            }

            self.send(*sender_key, sender_send.0, sender_send.1, &sender_send.2)
                .await?;
            self.send(
                *recipient_key,
                recipient_send.0,
                recipient_send.1,
                &recipient_send.2,
            )
            .await?;

            debug!("United {sender_key} and {recipient_key}");
        }

        Ok(())
    }

    async fn send(
        &self,
        recipient_key: PubKey,
        prot: TransportProt,
        dst: SocketAddr,
        buf: &[u8],
    ) -> Result<(), Error> {
        match (prot, dst) {
            (UDP, SocketAddr::V4(dst)) => self.send_udp4(recipient_key, buf, &dst).await,
            (UDP, SocketAddr::V6(dst)) => self.send_udp6(recipient_key, buf, &dst).await,
            (TCP, dst) => self.send_tcp(recipient_key, buf.to_vec(), &dst).await,
        }
    }

    async fn send_udp4(
        &self,
        recipient_key: PubKey,
        buf: &[u8],
        dst: &SocketAddrV4,
    ) -> Result<(), Error> {
        if let Some(udp4_socket) = &self.udp4_socket {
            udp4_socket
                .send_to(buf, dst)
                .await
                .map_err(Error::SendFailed)?;
            trace!("Sent to peer {recipient_key} to dst udp://{dst}.");
        }

        Ok(())
    }

    async fn send_udp6(
        &self,
        recipient_key: PubKey,
        buf: &[u8],
        dst: &SocketAddrV6,
    ) -> Result<(), Error> {
        if let Some(udp6_socket) = &self.udp6_socket {
            udp6_socket
                .send_to(buf, dst)
                .await
                .map_err(Error::SendFailed)?;
            trace!("Sent to peer {recipient_key} to dst udp://{dst}.");
        }

        Ok(())
    }

    pub(crate) fn tcp_codec() -> LengthDelimitedCodec {
        LengthDelimitedCodec::builder()
            .length_field_length(2)
            .new_codec()
    }

    async fn send_tcp(
        &self,
        recipient_key: PubKey,
        buf: Vec<u8>,
        dst: &SocketAddr,
    ) -> Result<(), Error> {
        if let Some(tcp_connection) = self.tcp_connections.pin_owned().get(dst) {
            tcp_connection
                .writer
                .lock()
                .await
                .send(Bytes::from(buf))
                .await
                .map_err(Error::SendFailed)?;
            tcp_connection.set_last_activity(self.cached_time());
            trace!("Sent to peer {recipient_key} to dst tcp://{dst}.");
        }

        Ok(())
    }

    pub fn cached_time(&self) -> u64 {
        self.coarse_timer.load(SeqCst)
    }

    pub(crate) fn current_time(&self) -> u64 {
        self.coarse_timer.store(Self::clock(), SeqCst);
        self.cached_time()
    }

    pub(crate) fn clock() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64
    }
}
