use crate::crypto::SessionKey;
use crate::identity::PubKey;
use crate::message::HelloSuperPeerMessage;
use crate::node::housekeeping::TcpPathGuard;
use crate::node::inner::NodeInner;
use crate::node::{Error, Node};
use crate::peer::TransportProt::TCP;
use crate::peer::{Peer, PeerPath, TransportProt};
use arc_swap::ArcSwapOption;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::Mutex;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use tokio_util::sync::CancellationToken;
use tracing::{error, instrument, trace, warn};

impl NodeInner {
    fn tcp_codec() -> LengthDelimitedCodec {
        LengthDelimitedCodec::builder()
            .length_field_length(2)
            .new_codec()
    }

    pub(crate) async fn send_super_peer_tcp(
        &self,
        stream: &Arc<Mutex<FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>>>,
        msg: Vec<u8>,
        peer_key: &PubKey,
    ) -> Result<TransportProt, Error> {
        match stream.lock().await.send(Bytes::from(msg)).await {
            Err(e) => {
                error!("Failed to send message to super peer via TCP, shutting it down: {e}");
                if let Some(Peer::SuperPeer(super_peer)) = self.peers_list.peers.pin().get(peer_key)
                    && let Some(tcp_path) = super_peer.tcp_connection().as_ref()
                {
                    tcp_path.cancel_connection();
                }
            }
            Ok(_) => {
                trace!("Sent to super peer via TCP.");
            }
        }

        Ok(TCP)
    }

    #[instrument(fields(peer = %guard.pub_key), skip_all)]
    pub(crate) async fn tcp_connector(
        time: u64,
        tcp_addr: String,
        tx_key: Option<SessionKey>,
        cancellation_token: Arc<CancellationToken>,
        guard: TcpPathGuard,
    ) {
        let peer_key = guard.pub_key;
        trace!("Connect to super peer tcp://{tcp_addr}");
        match TcpStream::connect(tcp_addr.clone()).await {
            Ok(stream) => {
                if let Err(e) = stream.set_nodelay(true) {
                    warn!("Failed to set TCP_NODELAY: {e}");
                }

                Self::tcp_stream_handler(
                    peer_key,
                    time,
                    tcp_addr,
                    guard.inner.clone(),
                    tx_key,
                    stream,
                    cancellation_token,
                )
                .await;
            }
            Err(e) => {
                warn!("Failed to connect to super peer tcp://{tcp_addr}: {e}");
            }
        }
    }

    async fn tcp_stream_handler(
        peer_key: PubKey,
        time: u64,
        tcp_addr: String,
        inner: Arc<NodeInner>,
        tx_key: Option<SessionKey>,
        stream: TcpStream,
        cancellation_token: Arc<CancellationToken>,
    ) {
        trace!("TCP connection to {tcp_addr} established");
        let peer_addr = stream.peer_addr().unwrap();
        let (read_half, write_half) = stream.into_split();
        let mut reader = FramedRead::new(read_half, Self::tcp_codec());
        let mut writer = FramedWrite::new(write_half, Self::tcp_codec());

        // immediately after connection establishment send HELLO
        // get local addresses
        let my_addrs = match Node::my_addrs() {
            Ok(my_addrs) => my_addrs,
            Err(e) => {
                warn!("my_addrs failed: {e}");
                return;
            }
        };
        let my_addrs: Vec<IpAddr> = my_addrs.into_iter().map(|(_, ip)| ip).collect();

        // endpoints
        let endpoints: Vec<u8> = match inner.my_endpoint_candidates(&my_addrs) {
            Ok(endpoints) => endpoints,
            Err(e) => {
                warn!("my_endpoint_candidates failed: {e}");
                return;
            }
        };

        #[cfg(feature = "prometheus")]
        {
            use crate::prometheus::{
                PROMETHEUS_LABEL_HELLO, PROMETHEUS_LABEL_TX, PROMETHEUS_MESSAGES,
            };
            PROMETHEUS_MESSAGES
                .with_label_values(&[
                    PROMETHEUS_LABEL_HELLO,
                    &peer_key.to_string(),
                    PROMETHEUS_LABEL_TX,
                ])
                .inc();
        }

        let hello = match HelloSuperPeerMessage::build(
            &inner.network_id,
            &inner.opts.id.pk,
            &inner.opts.id.pow,
            tx_key.as_ref(),
            &peer_key,
            time,
            &endpoints,
        ) {
            Ok(hello) => hello,
            Err(e) => {
                warn!("building HELLO message failed: {e}");
                return;
            }
        };

        if let Err(e) = writer.send(Bytes::from(hello)).await {
            warn!(
                "Failed to send HELLO to super peer {peer_key} via tcp://{tcp_addr} immediately after connection establishment: {}",
                e
            );
            return;
        }

        trace!(
            "Sent HELLO to super peer {peer_key} via tcp://{tcp_addr} immediately after connection establishment."
        );

        if let Some(Peer::SuperPeer(super_peer)) = inner.peers_list.peers.pin().get(&peer_key)
            && let Some(tcp_path) = super_peer.tcp_connection().as_ref()
        {
            tcp_path.hello_tx(time);
            tcp_path.set_stream(writer);
        }

        let tcp_inner = inner.clone();
        let mut response_buf = vec![0u8; tcp_inner.opts.mtu];
        loop {
            tokio::select! {
                biased;
                _ = cancellation_token.cancelled() => {
                    break;
                }
                next = reader.next() => {
                    match next {
                        Some(Ok(bytes)) => {
                            // process segment
                            if let Err(e) = tcp_inner
                                .on_tcp_segment(peer_addr, &mut bytes.to_vec(), &mut response_buf, peer_key)
                                .await
                            {
                                error!("Error processing segment: {e}");
                                if let Some(Peer::SuperPeer(super_peer)) =
                                    tcp_inner.peers_list.peers.pin_owned().get(&peer_key)
                                    && let Some(tcp_path) = super_peer.tcp_connection().as_ref() {
                                        tcp_path.cancel_connection();
                                    }
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            error!("Error receiving segment: {e}");
                            break;
                        }
                        None => {
                            error!(tcp_addr);
                            break;
                        }
                    }
                },
            }
        }
    }

    #[instrument(fields(src = %src, remote_peer = %remote_peer), skip_all)]
    pub async fn on_tcp_segment(
        &self,
        src: SocketAddr,
        buf: &mut [u8],
        response_buf: &mut [u8],
        remote_peer: PubKey,
    ) -> Result<(), Error> {
        self.on_packet(src, buf, response_buf, None, Some(remote_peer))
            .await
    }
}

#[derive(Debug, Default)]
pub struct TcpConnection {
    cancellation_token: Arc<CancellationToken>,
    pub(crate) stream_store:
        ArcSwapOption<Mutex<FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>>>,
    pub path: PeerPath,
}

impl TcpConnection {
    pub(crate) fn new(cancellation_token: Arc<CancellationToken>) -> Self {
        Self {
            cancellation_token,
            ..Default::default()
        }
    }

    pub(crate) fn median_lat(&self) -> Option<u64> {
        self.path.median_lat()
    }

    pub(crate) fn ack_age(&self, time: u64) -> Option<u64> {
        self.path.ack_age(time)
    }

    pub(crate) fn hello_tx(&self, time: u64) {
        self.path.hello_tx(time);
    }

    pub(crate) fn ack_rx(&self, time: u64, src: SocketAddr, hello_time: u64) {
        self.path.ack_rx(time, src, hello_time);
    }

    pub(crate) fn set_stream(&self, stream: FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>) {
        self.stream_store.store(Some(Arc::new(Mutex::new(stream))));
    }

    pub fn cancel_connection(&self) {
        trace!("Cancel TCP connection");
        self.cancellation_token.cancel();
    }

    pub fn has_stream(&self) -> bool {
        self.stream_store.load().is_some()
    }

    pub fn is_reachable(&self, time: u64, hello_timeout: u64) -> bool {
        self.path.is_reachable(time, hello_timeout)
    }
}
