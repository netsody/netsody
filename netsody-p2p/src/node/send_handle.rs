use crate::crypto::SessionKey;
use crate::identity::PubKey;
use crate::message::{AppMessage, ShortHeader, ShortId};
use crate::node::inner::NodeInner;
use crate::node::udp::UdpBinding;
use crate::node::{COMPRESSION, Error};
use crate::peer::{NodePeer, Peer, SuperPeer};
use arc_swap::{ArcSwap, ArcSwapOption, Guard};
use lz4_flex::compress_prepend_size;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::{Arc, Weak};
use tokio::net::UdpSocket;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::Mutex;
use tokio_util::codec::{FramedWrite, LengthDelimitedCodec};
use tracing::{debug, instrument, trace, warn};

#[derive(Default)]
pub(crate) struct SendHandlesList {
    send_handles: std::sync::Mutex<HashMap<PubKey, Weak<SendHandle>>>,
}

impl SendHandlesList {
    pub(crate) fn contains_key(&self, key: &PubKey) -> bool {
        self.send_handles
            .lock()
            .expect("Mutex poisoned")
            .contains_key(key)
    }

    pub(crate) fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(PubKey, Arc<SendHandle>),
    {
        let guard = self.send_handles.lock().expect("Mutex poisoned");
        for (k, v) in guard.iter() {
            if let Some(strong) = v.upgrade() {
                f(*k, strong);
            }
        }
    }

    pub(crate) fn get_or_insert(
        &self,
        key: &PubKey,
        inner: Arc<NodeInner>,
    ) -> Result<Arc<SendHandle>, Error> {
        let mut send_handles = self.send_handles.lock().unwrap();
        Ok(
            if let Some(send_handle) = send_handles.get(key).and_then(std::sync::Weak::upgrade) {
                send_handle
            } else {
                let send_handle = Arc::new(SendHandle::new(inner, *key)?);
                send_handles.insert(*key, Arc::downgrade(&send_handle));
                send_handle
            },
        )
    }

    pub(crate) fn garbage_collect(&self) {
        let mut guard = self.send_handles.lock().unwrap();
        guard.retain(|_, weak| weak.upgrade().is_some());
    }
}

pub(crate) struct SendHandleState {
    pub(crate) best_addr: Option<SocketAddr>,
    pub(crate) udp_socket: Option<Arc<UdpSocket>>,
    pub(crate) app_tx: Arc<AtomicU64>,
    pub(crate) tx_key: Option<SessionKey>,
    pub(crate) short_id: Option<ShortId>,
    pub(crate) sp_tcp_stream: Option<Arc<Mutex<FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>>>>,
    pub(crate) sp_udp_sockets: Vec<(SocketAddr, Arc<UdpSocket>)>,
}

impl SendHandleState {
    pub fn sp_socket(
        super_peer: &SuperPeer,
        udp_sockets: &[Arc<UdpBinding>],
    ) -> Vec<(SocketAddr, Arc<UdpSocket>)> {
        let guard = super_peer.udp_paths.guard();
        if let Some((key, _)) = super_peer.best_udp_path(&guard) {
            let mut entries = Vec::new();
            let socket = udp_sockets
                .iter()
                .find(|udp_binding| matches!(udp_binding.socket.local_addr(), Ok(a) if a == key.local_addr()))
                .unwrap()
                .socket
                .clone();
            entries.push((key.remote_addr(), socket));
            entries
        } else {
            let mut entries = Vec::new();
            for (key, _) in &super_peer.udp_paths.pin() {
                let socket = udp_sockets
                    .iter()
                    .find(|udp_binding| matches!(udp_binding.socket.local_addr(), Ok(a) if a == key.local_addr()))
                    .unwrap()
                    .socket.clone();
                entries.push((key.remote_addr(), socket));
            }
            entries
        }
    }
}

/// A handle for efficient message sending to a specific peer.
///
/// The `SendHandle` maintains all necessary routing and cryptographic information for sending
/// messages to a particular peer. This allows for optimized message delivery by caching
/// connection details and encryption keys, avoiding the need to look them up for each message.
///
/// # Features
///
/// * Caches routing information for the target peer
/// * Maintains cryptographic keys for secure communication
/// * Provides efficient message sending without repeated lookups
/// * Automatically handles both direct and relayed message delivery
///
/// # Example
///
/// ```rust
/// use netsody_p2p::node::{Node, PubKey};
///
/// async fn example(node: &Node, recipient: &PubKey) -> Result<(), Box<dyn std::error::Error>> {
///     // Get a send handle for the recipient
///     let send_handle = node.send_handle(recipient)?;
///     
///     // Send a message using the handle
///     send_handle.send(b"Hello, peer!").await?;
///     
///     Ok(())
/// }
/// ```
///
/// # Performance
///
/// Using a `SendHandle` is more efficient than calling [`super::Node::send_to`] repeatedly,
/// as it avoids the overhead of looking up peer information and cryptographic keys
/// for each message. It's particularly beneficial when sending multiple messages
/// to the same peer.
pub struct SendHandle {
    pub(crate) inner: ArcSwapOption<NodeInner>,
    pub recipient: PubKey,
    state_store: ArcSwap<SendHandleState>,
}

impl SendHandle {
    #[instrument(fields(peer = %recipient), skip_all)]
    pub fn new(inner: Arc<NodeInner>, recipient: PubKey) -> Result<Self, Error> {
        trace!("Create SendHandle");

        // Check if trying to send to self
        if recipient == inner.opts.id.pk {
            return Err(Error::SendToSelf);
        }
        let peers = inner.peers_list.peers.pin();
        let peer = if let Some(peer) = peers.get(&recipient) {
            peer
        } else {
            if inner.opts.max_peers != 0 && peers.len() >= inner.opts.max_peers as usize {
                return Err(Error::PeersListCapacityExceeded(inner.opts.max_peers));
            }

            let node_peer = NodePeer::new(
                None,
                &recipient,
                inner.opts.min_pow_difficulty,
                inner.opts.arm_messages,
                inner.agreement_sk,
                inner.agreement_pk,
                inner.cached_time(),
                inner.peers_list.default_route(),
            )?;
            inner
                .peers_list
                .rx_short_ids
                .pin()
                .insert(node_peer.rx_short_id(), recipient);

            peers.get_or_insert(recipient, Peer::NodePeer(node_peer))
        };

        let default_route = inner.peers_list.default_route();
        let Peer::SuperPeer(super_peer) = peers.get(default_route).unwrap() else {
            unreachable!()
        };

        if let Peer::NodePeer(node_peer) = peer {
            Ok(SendHandle {
                inner: ArcSwapOption::new(Some(inner.clone())),
                recipient,
                state_store: ArcSwap::from_pointee(
                    node_peer.new_send_handle_state(inner.clone(), super_peer),
                ),
            })
        } else {
            return Err(Error::RecipientIsSuperPeer(recipient));
        }
    }

    fn state(&self) -> Guard<Arc<SendHandleState>> {
        self.state_store.load()
    }

    pub(crate) fn update_state(&self, new_state: SendHandleState) {
        self.state_store.swap(Arc::new(new_state));
    }

    #[instrument(fields(peer = %self.recipient), skip_all)]
    pub async fn send(&self, bytes: &[u8]) -> Result<(), Error> {
        trace!(bytes_len = %bytes.len(), "Send message");
        let guard: Guard<Option<Arc<NodeInner>>> = self.inner.load();
        if let Some(inner) = guard.as_ref() {
            let bytes = if COMPRESSION {
                &compress_prepend_size(bytes)
            } else {
                bytes
            };

            let state = self.state();
            let best_addr = state.best_addr;
            let short_id = state.short_id;
            let udp_socket = &state.udp_socket;
            let sp_tcp_stream = &state.sp_tcp_stream;
            let sp_udp_sockets = &state.sp_udp_sockets;

            #[cfg(feature = "prometheus")]
            {
                use crate::prometheus::{
                    PROMETHEUS_LABEL_APP, PROMETHEUS_LABEL_TX, PROMETHEUS_MESSAGES,
                };
                PROMETHEUS_MESSAGES
                    .with_label_values(&[
                        PROMETHEUS_LABEL_APP,
                        &self.recipient.to_string(),
                        PROMETHEUS_LABEL_TX,
                    ])
                    .inc();
            }

            // TODO: Consider using a buffer pool to avoid repeated allocations.
            let app = if best_addr.is_none() || short_id.is_none() {
                AppMessage::build(
                    &inner.network_id,
                    &inner.opts.id.pk,
                    &inner.opts.id.pow,
                    state.tx_key.as_ref(),
                    &self.recipient,
                    bytes,
                )?
            } else {
                ShortHeader::build(short_id.unwrap(), state.tx_key.as_ref(), bytes)?
            };

            if app.len() > inner.opts.mtu {
                return Err(Error::AppLenInvalid(app.len(), inner.opts.mtu));
            }

            let time = inner.cached_time();
            state.app_tx.store(time, SeqCst);

            // TODO: Instead of writing directly to the network, consider writing to a send buffer that a separate thread sends to the network.

            // direct path?
            if let Some(my_addr) = state.best_addr {
                #[cfg(feature = "prometheus")]
                {
                    use crate::prometheus::{
                        PROMETHEUS_BYTES, PROMETHEUS_LABEL_DIRECT, PROMETHEUS_LABEL_TX,
                    };
                    PROMETHEUS_BYTES
                        .with_label_values(&[
                            self.recipient.to_string(),
                            PROMETHEUS_LABEL_TX.to_string(),
                            PROMETHEUS_LABEL_DIRECT.to_string(),
                        ])
                        .inc_by(bytes.len() as f64);
                }

                udp_socket
                    .as_ref()
                    .unwrap()
                    .send_to(&app, my_addr)
                    .await
                    .map_err(|e| Error::SendingDirectError(e, my_addr))?;

                debug!("Sent APP via udp://{}", my_addr);
            } else {
                #[cfg(feature = "prometheus")]
                {
                    use crate::prometheus::{
                        PROMETHEUS_BYTES, PROMETHEUS_LABEL_RELAYED, PROMETHEUS_LABEL_TX,
                    };
                    PROMETHEUS_BYTES
                        .with_label_values(&[
                            self.recipient.to_string(),
                            PROMETHEUS_LABEL_TX.to_string(),
                            PROMETHEUS_LABEL_RELAYED.to_string(),
                        ])
                        .inc_by(bytes.len() as f64);
                }

                // relay
                // get best super peer
                let default_route = inner.peers_list.default_route();

                // First try TCP if available
                if let Some(stream) = sp_tcp_stream {
                    inner
                        .send_super_peer_tcp(stream, app, default_route)
                        .await?;
                } else {
                    // Fall forward to UDP
                    let mut result = false;
                    for (sp_resolved_addr, sp_udp_socket) in sp_udp_sockets {
                        if let Err(e) = sp_udp_socket.send_to(&app, sp_resolved_addr).await {
                            warn!(
                                "Failed to relay APP via super peer {} -> {}: {e}",
                                sp_udp_socket.local_addr().unwrap(),
                                sp_resolved_addr
                            );
                        } else {
                            trace!(
                                "Relayed APP via super peer {} -> {}",
                                sp_udp_socket.local_addr().unwrap(),
                                sp_resolved_addr
                            );

                            result = true;
                            break;
                        }
                    }
                    if !result {
                        warn!("Failed to relay APP via super peer.");
                        return Err(Error::SendingRelayedError(self.recipient, *default_route));
                    }
                }
            }

            Ok(())
        } else {
            Err(Error::SendHandleClosed)
        }
    }
}
