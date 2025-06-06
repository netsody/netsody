use crate::sp::inner::SuperPeerInner;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tracing::error;

impl SuperPeerInner {
    pub(crate) async fn udp4_reader(
        inner: Arc<SuperPeerInner>,
        cancellation_token: CancellationToken,
    ) {
        if let Some(udp_socket) = &inner.udp4_socket {
            Self::udp_reader_inner(inner.clone(), cancellation_token, udp_socket).await;
        }
    }

    pub(crate) async fn udp6_reader(
        inner: Arc<SuperPeerInner>,
        cancellation_token: CancellationToken,
    ) {
        if let Some(udp_socket) = &inner.udp6_socket {
            Self::udp_reader_inner(inner.clone(), cancellation_token, udp_socket).await;
        }
    }

    async fn udp_reader_inner(
        inner: Arc<SuperPeerInner>,
        cancellation_token: CancellationToken,
        udp_socket: &UdpSocket,
    ) {
        let mut buf = vec![0u8; inner.opts.mtu];
        let mut response_buf = vec![0u8; inner.opts.mtu];
        loop {
            tokio::select! {
                biased;
                _ = cancellation_token.cancelled() => break,
                result = udp_socket.recv_from(&mut buf) => {
                    let (size, src) = match result {
                        Ok(result) => result,
                        Err(e) => {
                            error!("Error receiving datagram: {e}");
                            continue;
                        }
                    };

                    if let Err(e) = inner
                        .on_udp_datagram(src, &mut buf[..size], &mut response_buf)
                        .await
                    {
                        error!("Error processing packet: {e}");
                        continue;
                    }
                }
            }
        }
    }
}
