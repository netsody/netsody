use crate::sp::inner::SuperPeerInner;
use ahash::RandomState;
use arc_swap::ArcSwapOption;
use p2p::crypto;
use p2p::crypto::SessionKey;
use p2p::crypto::{compute_kx_session_keys, convert_ed25519_pk_to_curve25519_pk};
use p2p::identity::Pow;
use p2p::identity::PubKey;
use p2p::message::HELLO_ENDPOINT_LEN;
use p2p::message::{Endpoint, EndpointsList};
use papaya::{Guard, HashMap as PapayaHashMap};
use std::collections::HashSet;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PeersError {
    #[error("Peers list capacity ({0}) exceeded")]
    CapacityExceeded(u64),

    #[error("Crypto error: {0}")]
    CryptoError(#[from] crypto::Error),

    #[error("Agreement pk not present")]
    AgreementPkNotPresent,

    #[error("Agreement sk not present")]
    AgreementSkNotPresent,
}

#[derive(Debug)]
struct SessionKeys {
    tx: SessionKey,
    rx: SessionKey,
}

impl SessionKeys {
    fn new(keys: (SessionKey, SessionKey)) -> SessionKeys {
        SessionKeys {
            tx: keys.1,
            rx: keys.0,
        }
    }
}

#[derive(Debug)]
struct LastHello {
    time: u64,
    src: SocketAddr,
    prot: TransportProt,
    endpoints: Vec<u8>,
}

#[derive(Debug)]
pub struct Peer {
    valid_pow: bool,
    session_keys: Option<SessionKeys>,
    last_tcp_hello_ptr: ArcSwapOption<LastHello>,
    last_udp_hello_ptr: ArcSwapOption<LastHello>,
}

impl Peer {
    pub(crate) fn has_invalid_pow(&self) -> bool {
        !self.valid_pow
    }

    pub(crate) fn hello_tx(
        &self,
        time: u64,
        src: SocketAddr,
        prot: TransportProt,
        endpoints: &[u8],
    ) {
        match prot {
            TransportProt::TCP => {
                self.last_tcp_hello_ptr.store(Some(Arc::new(LastHello {
                    time,
                    src,
                    prot,
                    endpoints: endpoints.into(),
                })));
            }
            TransportProt::UDP => {
                self.last_udp_hello_ptr.store(Some(Arc::new(LastHello {
                    time,
                    src,
                    prot,
                    endpoints: endpoints.into(),
                })));
            }
        }
    }

    pub(crate) fn is_stale(&self, time: u64, hello_timeout: u64) -> bool {
        let mut last_hello_time = self.last_hello().as_ref().map_or(0, |h| h.time);
        if time < last_hello_time {
            // TODO: This can be removed once we've switched to a monotonically increasing time source.
            last_hello_time = time;
        }
        let age = time - last_hello_time;
        age > (hello_timeout * 1_000)
    }

    pub(crate) fn contact_candidates(&self) -> Vec<u8> {
        self.last_hello().as_ref().map_or(vec![0], |last_hello| {
            if last_hello.prot == TransportProt::UDP {
                let mut buf = vec![0u8; last_hello.endpoints.len() + HELLO_ENDPOINT_LEN];
                buf[..last_hello.endpoints.len()].copy_from_slice(last_hello.endpoints.as_slice());

                // add HELLO src
                let endpoint: Endpoint = (&last_hello.src).into();
                endpoint.to_bytes(&mut buf[last_hello.endpoints.len()..]);

                buf
            } else {
                last_hello.endpoints.clone()
            }
        })
    }

    fn last_hello(&self) -> arc_swap::Guard<Option<Arc<LastHello>>> {
        let tcp_hello = self.last_tcp_hello_ptr.load();
        if tcp_hello.is_some() {
            tcp_hello
        } else {
            self.last_udp_hello_ptr.load()
        }
    }

    pub(crate) fn endpoint(&self) -> Option<(TransportProt, SocketAddr)> {
        self.last_hello()
            .as_ref()
            .map(|last_hello| (last_hello.prot, last_hello.src))
    }

    pub(crate) fn tx_key(&self) -> Option<&SessionKey> {
        self.session_keys.as_ref().map(|keys| &keys.tx)
    }

    pub(crate) fn rx_key(&self) -> Option<&SessionKey> {
        self.session_keys.as_ref().map(|keys| &keys.rx)
    }

    pub(crate) fn hello_endpoints(&self) -> HashSet<SocketAddr> {
        match self.last_hello().as_ref() {
            Some(hello) => {
                let endpoints = hello.endpoints.as_slice();
                let list = EndpointsList::from(endpoints);
                list.0.into_iter().map(SocketAddr::from).collect()
            }
            None => HashSet::new(),
        }
    }

    /// Clear the last TCP hello message if it matches the given source address
    pub(crate) fn clear_tcp_hello_if_matches(&self, src: SocketAddr) -> bool {
        if let Some(last_tcp_hello) = self.last_tcp_hello_ptr.load().as_ref()
            && last_tcp_hello.src == src {
                self.last_tcp_hello_ptr.store(None);
                return true;
            }
        false
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum TransportProt {
    TCP,
    UDP,
}

impl fmt::Display for TransportProt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::TCP => "tcp",
                Self::UDP => "udp",
            }
        )
    }
}

#[derive(Default)]
pub struct PeersList {
    pub(crate) peers: PapayaHashMap<PubKey, Peer, RandomState>,
    pub(crate) unite_attempts: PapayaHashMap<(PubKey, PubKey), u64>,
}

impl PeersList {
    pub(crate) fn new(max_peers: u64) -> Self {
        Self {
            peers: PapayaHashMap::builder()
                .capacity(max_peers as usize)
                .hasher(RandomState::new())
                .build(),
            unite_attempts: Default::default(),
        }
    }

    pub(crate) fn peers_guard(&self) -> impl Guard + '_ {
        self.peers.guard()
    }

    pub(crate) fn get_peer<'guard>(
        &self,
        pk: &PubKey,
        guard: &'guard impl Guard,
    ) -> Option<&'guard Peer> {
        self.peers.get(pk, guard)
    }

    pub(crate) fn get_or_insert_peer<'guard>(
        &self,
        pk: &PubKey,
        pow: &Pow,
        inner: &SuperPeerInner,
        guard: &'guard impl Guard,
    ) -> Result<&'guard Peer, PeersError> {
        if let Some(peer) = self.peers.get(pk, guard) {
            Ok(peer)
        } else {
            if self.peers.len() >= inner.opts.max_peers as usize {
                return Err(PeersError::CapacityExceeded(inner.opts.max_peers));
            }

            let valid_pow = Pow::validate(pk, pow, inner.opts.min_pow_difficulty);
            let peer = Peer {
                valid_pow,
                session_keys: if inner.opts.arm_messages && valid_pow {
                    let agreement_pk = convert_ed25519_pk_to_curve25519_pk(&(*pk).into())?;
                    Some(SessionKeys::new(compute_kx_session_keys(
                        &inner
                            .agreement_pk
                            .ok_or(PeersError::AgreementPkNotPresent)?,
                        &inner
                            .agreement_sk
                            .ok_or(PeersError::AgreementSkNotPresent)?,
                        &agreement_pk,
                    )?))
                } else {
                    None
                },
                last_tcp_hello_ptr: Default::default(),
                last_udp_hello_ptr: Default::default(),
            };
            Ok(self.peers.get_or_insert(*pk, peer, guard))
        }
    }

    pub(crate) fn send_unites(
        &self,
        sender: &PubKey,
        recipient: &PubKey,
        time: u64,
        send_unites: i32,
    ) -> bool {
        // disabled
        if send_unites < 0 {
            return false;
        }

        // always send
        if send_unites == 0 {
            return true;
        }

        let key = (*sender, *recipient);
        let swapped_key = (*recipient, *sender);

        let guard = self.unite_attempts.guard();
        if let Some(last_time) = self.unite_attempts.get(&key, &guard)
            && time - *last_time < (send_unites * 1_000) as u64
        {
            return false;
        }

        let _ = self.unite_attempts.insert(key, time, &guard);
        let _ = self.unite_attempts.insert(swapped_key, time, &guard);

        true
    }
}

impl fmt::Display for PeersList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let now = SuperPeerInner::clock();

        writeln!(f, "{:<64} {:<3} {:<7} HelloSrc", "Node", "PoW", "HelloRx")?;

        let guard = self.peers.guard();
        let mut peer_count = 0;
        for (key, peer) in self.peers.iter(&guard) {
            peer_count += 1;
            // Format endpoints list
            let hello_endpoints = peer
                .hello_endpoints()
                .iter()
                .map(|e| format!("udp://{e}"))
                .collect::<Vec<_>>()
                .join(" ");
            let src = if let Some((prot, src)) = &peer.endpoint() {
                format!("{prot}://{src} {hello_endpoints}")
            } else {
                hello_endpoints.to_string()
            };

            write!(
                f,
                "{:<64} {:<3} {:<7} {}",
                key.to_string(),
                if peer.valid_pow { "ok" } else { "nok" },
                if let Some(last_hello) = peer.last_hello().as_ref() {
                    ((now - last_hello.time) / 1_000).to_string()
                } else {
                    String::new()
                },
                src,
            )?;
            writeln!(f)?;
        }

        // Show total number of peers
        writeln!(f, "Total Peers: {}", peer_count)?;

        Ok(())
    }
}
