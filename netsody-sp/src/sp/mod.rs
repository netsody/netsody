mod error;
mod housekeeping;
mod inner;
mod opts;
mod peers;
mod tcp;
mod udp;

pub use crate::sp::inner::SuperPeerInner;
pub use error::*;
pub use opts::*;
use p2p::crypto::{convert_ed25519_pk_to_curve25519_pk, convert_ed25519_sk_to_curve25519_sk};
pub use peers::*;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinSet;
use tokio_util::sync::{CancellationToken, WaitForCancellationFuture};
use tracing::{error, info, instrument, trace};

pub struct SuperPeer {
    inner: Arc<SuperPeerInner>,
}

impl Drop for SuperPeer {
    fn drop(&mut self) {
        trace!("Drop super peer. Cancel token.");
        self.inner.cancellation_token.cancel();
    }
}

impl SuperPeer {
    #[instrument(skip_all)]
    pub async fn bind(opts: SuperPeerOpts) -> Result<Self, Error> {
        if opts.udp4_listen.is_none()
            && opts.udp6_listen.is_none()
            && opts.tcp4_listen.is_none()
            && opts.tcp6_listen.is_none()
        {
            return Err(Error::NeitherUdpNorTcpServers);
        }

        // generate agreement keys
        let (agreement_sk, agreement_pk) = if opts.arm_messages {
            (
                Some(convert_ed25519_sk_to_curve25519_sk(&opts.id.sk.into())?),
                Some(convert_ed25519_pk_to_curve25519_pk(&opts.id.pk.into())?),
            )
        } else {
            (None, None)
        };

        // start udp4 server
        let udp4_socket = if let Some(udp4_listen) = opts.udp4_listen {
            let udp4_socket = UdpSocket::bind(udp4_listen)
                .await
                .map_err(Error::Udp4BindError)?;
            info!("Bound UDP4 server to {}", udp4_socket.local_addr()?);
            Some(udp4_socket)
        } else {
            None
        };

        // start udp6 server
        let udp6_socket = if let Some(udp6_listen) = opts.udp6_listen {
            let udp6_socket = UdpSocket::bind(udp6_listen)
                .await
                .map_err(Error::Udp6BindError)?;
            info!("Bound UDP6 server to {}", udp6_socket.local_addr()?);
            Some(udp6_socket)
        } else {
            None
        };

        // start tcp4 server
        let tcp4_listener = if let Some(tcp4_listen) = opts.tcp4_listen {
            let tcp4_listener = TcpListener::bind(tcp4_listen)
                .await
                .map_err(Error::Tcp4BindError)?;
            info!("Bound TCP4 server to {}", tcp4_listener.local_addr()?);
            Some(tcp4_listener)
        } else {
            None
        };

        // start tcp6 server
        let tcp6_listener = if let Some(tcp6_listen) = opts.tcp6_listen {
            let tcp6_listener = TcpListener::bind(tcp6_listen)
                .await
                .map_err(Error::Tcp6BindError)?;
            info!("Bound TCP6 server to {}", tcp6_listener.local_addr()?);
            Some(tcp6_listener)
        } else {
            None
        };

        let cancellation_token = CancellationToken::new();
        let inner = Arc::new(SuperPeerInner::new(
            opts,
            udp4_socket,
            udp6_socket,
            tcp4_listener,
            tcp6_listener,
            agreement_sk,
            agreement_pk,
            cancellation_token.clone(),
        ));

        let mut join_set = JoinSet::new();

        // housekeeping task
        join_set.spawn(SuperPeerInner::housekeeping_runner(
            inner.clone(),
            cancellation_token.child_token(),
        ));

        // udp servers
        join_set.spawn(SuperPeerInner::udp4_reader(
            inner.clone(),
            cancellation_token.child_token(),
        ));
        join_set.spawn(SuperPeerInner::udp6_reader(
            inner.clone(),
            cancellation_token.child_token(),
        ));

        // tcp servers
        join_set.spawn(SuperPeerInner::tcp4_listener(
            inner.clone(),
            cancellation_token.child_token(),
        ));
        join_set.spawn(SuperPeerInner::tcp6_listener(
            inner.clone(),
            cancellation_token.child_token(),
        ));

        let monitoring_token = cancellation_token.clone();
        tokio::spawn(async move {
            while let Some(result) = join_set.join_next().await {
                if let Err(e) = result {
                    error!("Task failed. Cancel token: {e}");
                    monitoring_token.cancel();
                    break;
                } else if !monitoring_token.is_cancelled() {
                    trace!("Task prematurely finished. Cancel token.");
                    monitoring_token.cancel();
                }
            }
            trace!("Monitoring task cancelled.");
        });

        Ok(Self { inner })
    }

    pub fn peers_list(&self) -> &PeersList {
        &self.inner.peers_list
    }

    pub fn cancelled(&self) -> WaitForCancellationFuture<'_> {
        self.inner.cancellation_token.cancelled()
    }
}
