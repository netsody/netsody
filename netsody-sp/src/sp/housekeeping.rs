use crate::sp::PeersList;
use crate::sp::error::Error;
use crate::sp::inner::SuperPeerInner;
use futures::SinkExt;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{error, instrument};

impl SuperPeerInner {
    pub(crate) async fn housekeeping_runner(
        inner: Arc<SuperPeerInner>,
        cancellation_token: CancellationToken,
    ) {
        let mut interval =
            tokio::time::interval(Duration::from_millis(inner.opts.housekeeping_interval));

        loop {
            tokio::select! {
                biased;
                _ = cancellation_token.cancelled() => break,
                _ = interval.tick() => {
                    if let Err(e) = inner.housekeeping().await {
                        error!("Error in housekeeping: {e}");
                    }
                }
            }
        }
    }

    #[instrument(skip_all)]
    async fn housekeeping(&self) -> Result<(), Error> {
        self.peers_list.housekeeping(self);
        self.close_inactive_tcp_connections().await;

        #[cfg(feature = "prometheus")]
        self.housekeeping_prometheus();

        Ok(())
    }

    async fn close_inactive_tcp_connections(&self) {
        let time = self.current_time();

        let guard = self.tcp_connections.owned_guard();
        for (key, connection) in self.tcp_connections.iter(&guard) {
            if connection.is_inactive(time, self.opts.hello_timeout)
                && let Some(connection) = self.tcp_connections.remove(key, &guard)
                && let Err(e) = connection.writer.lock().await.close().await
            {
                error!("Error shutting down connection: {e}");
            }
        }
    }
}

impl PeersList {
    fn housekeeping(&self, inner: &SuperPeerInner) {
        let time = inner.cached_time();

        // remove stale peers
        let peers_guard = self.peers.guard();
        self.peers.retain(
            |_, peer| !peer.is_stale(time, inner.opts.hello_timeout),
            &peers_guard,
        );

        if inner.opts.send_unites > 0 {
            // remove expired unite attempts
            let unite_guard = self.unite_attempts.guard();
            self.unite_attempts.retain(
                |_, &last_time| time - last_time < inner.opts.send_unites as u64,
                &unite_guard,
            );

            if inner.opts.send_unites as u64 > (inner.opts.hello_timeout * 1_000) {
                self.unite_attempts.retain(
                    |(key1, _), _| self.peers.contains_key(key1, &peers_guard),
                    &unite_guard,
                );
            }
        }
    }
}
