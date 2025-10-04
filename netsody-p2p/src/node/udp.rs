use crate::node::Error;
use crate::node::housekeeping::UdpBindingGuard;
use crate::node::inner::NodeInner;
use std::fmt::{Display, Formatter};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tracing::{error, instrument};
use tracing::{trace, warn};

impl NodeInner {
    // from phantun/phantun/src/utils.rs
    #[allow(unused_variables)]
    pub(crate) fn new_udp_reuseport(
        local_addr: SocketAddr,
        iface: String,
    ) -> Result<UdpSocket, io::Error> {
        let udp_sock = socket2::Socket::new(
            if local_addr.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            },
            socket2::Type::DGRAM,
            None,
        )?;
        #[cfg(not(target_os = "windows"))]
        udp_sock.set_reuse_port(true)?;
        #[cfg(not(target_os = "windows"))]
        udp_sock.set_cloexec(true)?;
        udp_sock.set_nonblocking(true)?;
        udp_sock.bind(&socket2::SockAddr::from(local_addr))?;
        #[cfg(any(target_os = "linux", target_os = "fuchsia"))]
        if !iface.is_empty() {
            trace!("Bind socket for {} to device {}", local_addr, iface);
            udp_sock.bind_device(Some(iface.as_bytes()))?;
        }
        let udp_sock: std::net::UdpSocket = udp_sock.into();
        udp_sock.try_into()
    }

    pub(crate) async fn udp_reader(guard: UdpBindingGuard) {
        let inner = guard.inner.clone();
        let udp_binding = guard.udp_binding.clone();
        let udp_cancellation = udp_binding.cancellation_token.clone();
        let mut buf = vec![0u8; inner.opts.mtu];
        let mut response_buf = vec![0u8; inner.opts.mtu];
        loop {
            tokio::select! {
                biased;
                _ = udp_cancellation.cancelled() => {
                    trace!("UDP binding cancelled: {udp_binding}");
                    break;
                }
                result = udp_binding.socket.recv_from(&mut buf) => {
                    let (size, src) = match result {
                        Ok(result) => result,
                        Err(e) => {
                            error!("Error receiving datagram: {e}");
                            continue;
                        }
                    };

                    // process datagram
                    if let Err(e) = inner
                        .on_udp_datagram(src, &mut buf[..size], &mut response_buf, udp_binding.clone())
                        .await
                    {
                        warn!("Error processing packet: {e}");
                        continue;
                    }
                }
            }
        }
    }

    #[instrument(fields(src = %src, dst = %binding.local_addr), skip_all)]
    pub async fn on_udp_datagram(
        &self,
        src: SocketAddr,
        buf: &mut [u8],
        response_buf: &mut [u8],
        binding: Arc<UdpBinding>,
    ) -> Result<(), Error> {
        self.on_packet(src, buf, response_buf, Some(binding.clone()), None)
            .await
    }
}

#[doc(hidden)]
#[derive(Debug)]
pub struct UdpBinding {
    pub(crate) cancellation_token: Arc<CancellationToken>,
    pub(crate) socket: Arc<UdpSocket>,
    pub local_addr: SocketAddr,
    pub(crate) reader_task_died: AtomicBool,
}

impl UdpBinding {
    pub fn new(cancellation_token: CancellationToken, socket: UdpSocket) -> Self {
        let local_addr = socket.local_addr().unwrap();
        Self {
            cancellation_token: Arc::new(cancellation_token),
            socket: Arc::new(socket),
            local_addr,
            reader_task_died: AtomicBool::new(false),
        }
    }

    pub fn cancel_binding(&self) {
        trace!("Cancel UDP binding");
        self.cancellation_token.cancel();
    }
}

impl Display for UdpBinding {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.local_addr)
    }
}
