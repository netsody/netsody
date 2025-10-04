use crate::sp::inner::SuperPeerInner;
use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::SeqCst;
use tokio::net::TcpListener;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use tokio_util::sync::CancellationToken;
use tracing::{error, trace, warn};

type TcpWriter = FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>;
type TcpReader = FramedRead<OwnedReadHalf, LengthDelimitedCodec>;

pub struct TcpConnection {
    inner: Arc<SuperPeerInner>,
    src: SocketAddr,
    pub(crate) writer: Arc<Mutex<TcpWriter>>,
    last_activity: AtomicU64,
}

impl TcpConnection {
    pub(crate) fn set_last_activity(&self, time: u64) {
        self.last_activity.store(time, SeqCst);
    }

    pub(crate) fn is_inactive(&self, time: u64, hello_timeout: u64) -> bool {
        time - self.last_activity.load(SeqCst) > (hello_timeout * 1_000)
    }
}

pub struct TcpConnectionGuard(pub Arc<TcpConnection>);

impl Drop for TcpConnectionGuard {
    fn drop(&mut self) {
        trace!(
            "TcpConnectionGuard dropped. Remove TCP connection {}",
            self.0.src
        );
        self.0.inner.tcp_connections.pin().remove(&self.0.src);
    }
}

impl Deref for TcpConnectionGuard {
    type Target = TcpConnection;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl SuperPeerInner {
    pub(crate) async fn tcp4_listener(
        inner: Arc<SuperPeerInner>,
        cancellation_token: CancellationToken,
    ) {
        if let Some(tcp_listener) = &inner.tcp4_listener {
            Self::tcp_listener_inner(inner.clone(), cancellation_token, tcp_listener).await;
        }
    }

    pub(crate) async fn tcp6_listener(
        inner: Arc<SuperPeerInner>,
        cancellation_token: CancellationToken,
    ) {
        if let Some(tcp_listener) = &inner.tcp6_listener {
            Self::tcp_listener_inner(inner.clone(), cancellation_token, tcp_listener).await;
        }
    }

    async fn tcp_listener_inner(
        inner: Arc<SuperPeerInner>,
        cancellation_token: CancellationToken,
        tcp_listener: &TcpListener,
    ) {
        loop {
            tokio::select! {
                biased;
                _ = cancellation_token.cancelled() => break,
                // wait for next connection
                result = tcp_listener.accept() => {
                    if let Ok((stream, src)) = result {
                        if let Err(e) = stream.set_nodelay(true) {
                            warn!("Failed to set TCP_NODELAY: {e}");
                        }

                        trace!("New TCP connection from {src}");
                        let (read_half, write_half) = stream.into_split();
                        let reader = FramedRead::new(read_half, SuperPeerInner::tcp_codec());
                        let mut writer = FramedWrite::new(write_half, SuperPeerInner::tcp_codec());

                        // Check if we already have N active connections
                        if inner.tcp_connections.len() >= inner.opts.max_peers as usize {
                            // Too many connections - reject this one
                            if let Err(e) = writer.close().await {
                                error!("Error shutting down connection: {e}");
                            }
                        }

                        let writer = Arc::new(Mutex::new(writer));

                        let tcp_connection = Arc::new(TcpConnection {
                                inner: inner.clone(),
                                src,
                                writer,
                                last_activity: AtomicU64::new(inner.cached_time()),
                            });

                        let _ = inner.tcp_connections.pin().insert(
                            src,
                            tcp_connection.clone(),
                        );

                        tokio::spawn(Self::tcp_reader(cancellation_token.clone(), reader, TcpConnectionGuard(tcp_connection.clone())));
                    }
                }
            }
        }
    }

    async fn tcp_reader(
        cancellation_token: CancellationToken,
        mut reader: TcpReader,
        tcp_connection: TcpConnectionGuard,
    ) {
        let inner = tcp_connection.inner.clone();
        let src = tcp_connection.src;
        let mut response_buf = vec![0u8; inner.opts.mtu];
        loop {
            tokio::select! {
                biased;
                _ = cancellation_token.cancelled() => break,
                // read segment
                result = reader.next() => {
                    match result {
                        Some(Ok(bytes)) => {
                            // process segment
                            if let Err(e) = inner
                                .on_tcp_segment(src, &mut bytes.to_vec(), &mut response_buf)
                                .await
                            {
                                error!("Error processing packet: {e}");

                                if let Err(e) = tcp_connection.writer.lock().await.close().await {
                                    error!("Error shutting down connection: {e}");
                                }
                                break;
                            }

                            // Update activity time after successful read
                            if let Some(connection) = inner.tcp_connections.pin().get(&src) {
                                connection.set_last_activity(inner.cached_time());
                            }
                        }
                        Some(Err(e)) => {
                            error!("Error receiving segment: {e}");
                            break;
                        }
                        None => {
                            trace!("TCP connection closed by peer {src}");
                            break;
                        }
                    }
                }
            }
        }

        // connection closed, delete corresponding last tcp HELLOs
        // iterate over all peers in inner.peers_list.peers.pin() and clear last_tcp hello where src matches
        let peers_guard = inner.peers_list.peers.guard();
        for (pub_key, peer) in inner.peers_list.peers.iter(&peers_guard) {
            if peer.clear_tcp_hello_if_matches(src) {
                trace!(
                    "Cleared last_tcp_hello for peer {} due to closed TCP connection from {}",
                    pub_key, src
                );
            }
        }
    }
}
