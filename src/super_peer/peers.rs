use crate::identity::validate_proof_of_work;
use crate::messages::{Endpoint, HELLO_ENDPOINT_LEN};
use crate::super_peer::SuperPeerInner;
use crate::utils::crypto::{
    AEGIS_KEYBYTES, CryptoError, ED25519_PUBLICKEYBYTES, compute_kx_session_keys,
    convert_ed25519_pk_to_curve22519_pk,
};
use crate::utils::hex::bytes_to_hex;
use ahash::RandomState;
use arc_swap::ArcSwapOption;
use papaya::{Guard, HashMap};
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PeersError {
    #[error("Peers list capacity ({0}) exceeded")]
    CapacityExceeded(u64),

    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),

    #[error("Agreement pk not present")]
    AgreementPkNotPresent,

    #[error("Agreement sk not present")]
    AgreementSkNotPresent,
}

#[derive(Debug)]
struct SessionKeys {
    tx: [u8; AEGIS_KEYBYTES],
    rx: [u8; AEGIS_KEYBYTES],
}

impl SessionKeys {
    fn new(keys: ([u8; AEGIS_KEYBYTES], [u8; AEGIS_KEYBYTES])) -> SessionKeys {
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
pub(in crate::super_peer) struct Peer {
    valid_pow: bool,
    session_keys: Option<SessionKeys>,
    last_hello_ptr: ArcSwapOption<LastHello>,
}

impl Peer {
    pub(in crate::super_peer) fn has_invalid_pow(&self) -> bool {
        !self.valid_pow
    }

    pub(in crate::super_peer) fn hello_tx(
        &self,
        time: u64,
        src: SocketAddr,
        prot: TransportProt,
        endpoints: &[u8],
    ) {
        self.last_hello_ptr.store(Some(Arc::new(LastHello {
            time,
            src,
            prot,
            endpoints: endpoints.into(),
        })));
    }

    pub(in crate::super_peer) fn is_stale(&self, time: u64, hello_timeout: u64) -> bool {
        let age = time - self.last_hello().as_ref().map_or(0, |h| h.time);
        age > (hello_timeout * 1_000)
    }

    pub(in crate::super_peer) fn contact_candidates(&self) -> Vec<u8> {
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
        self.last_hello_ptr.load()
    }

    pub(in crate::super_peer) fn endpoint(&self) -> Option<(TransportProt, SocketAddr)> {
        self.last_hello()
            .as_ref()
            .map(|last_hello| (last_hello.prot, last_hello.src))
    }

    pub(in crate::super_peer) fn tx_key(&self) -> Option<&[u8; AEGIS_KEYBYTES]> {
        self.session_keys.as_ref().map(|keys| &keys.tx)
    }

    pub(in crate::super_peer) fn rx_key(&self) -> Option<&[u8; AEGIS_KEYBYTES]> {
        self.session_keys.as_ref().map(|keys| &keys.rx)
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub(in crate::super_peer) enum TransportProt {
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
pub(in crate::super_peer) struct PeersList {
    peers: HashMap<[u8; ED25519_PUBLICKEYBYTES], Peer, RandomState>,
    unite_attempts: HashMap<([u8; ED25519_PUBLICKEYBYTES], [u8; ED25519_PUBLICKEYBYTES]), u64>,
}

impl PeersList {
    pub(in crate::super_peer) fn new(max_peers: u64) -> Self {
        Self {
            peers: HashMap::builder()
                .capacity(max_peers as usize)
                .hasher(RandomState::new())
                .build(),
            unite_attempts: Default::default(),
        }
    }

    pub(in crate::super_peer) fn housekeeping(&self, inner: &SuperPeerInner) {
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

    pub(in crate::super_peer) fn peers_guard(&self) -> impl Guard + '_ {
        self.peers.guard()
    }

    pub(in crate::super_peer) fn get_peer<'guard>(
        &self,
        pk: &[u8; ED25519_PUBLICKEYBYTES],
        guard: &'guard impl Guard,
    ) -> Option<&'guard Peer> {
        self.peers.get(pk, guard)
    }

    pub(in crate::super_peer) fn get_or_insert_peer<'guard>(
        &self,
        pk: &[u8; ED25519_PUBLICKEYBYTES],
        pow: &[u8; 4],
        inner: &SuperPeerInner,
        guard: &'guard impl Guard,
    ) -> Result<&'guard Peer, PeersError> {
        if let Some(peer) = self.peers.get(pk, guard) {
            Ok(peer)
        } else {
            if self.peers.len() >= inner.opts.max_peers as usize {
                return Err(PeersError::CapacityExceeded(inner.opts.max_peers));
            }

            let valid_pow = validate_proof_of_work(pk, pow, inner.opts.min_pow_difficulty);
            let peer = Peer {
                valid_pow,
                session_keys: if inner.opts.arm_messages && valid_pow {
                    let agreement_pk = convert_ed25519_pk_to_curve22519_pk(pk)?;
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
                last_hello_ptr: Default::default(),
            };
            Ok(self.peers.get_or_insert(*pk, peer, guard))
        }
    }

    pub(in crate::super_peer) fn send_unites(
        &self,
        sender: &[u8; ED25519_PUBLICKEYBYTES],
        recipient: &[u8; ED25519_PUBLICKEYBYTES],
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
        if let Some(last_time) = self.unite_attempts.get(&key, &guard) {
            if time - *last_time < send_unites as u64 {
                return false;
            }
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
        for (key, peer) in self.peers.iter(&guard) {
            // Format endpoints list
            let src = if let Some((prot, src)) = &peer.endpoint() {
                format!("{prot}://{src}")
            } else {
                String::new()
            };

            write!(
                f,
                "{:<64} {:<3} {:<7} {}",
                bytes_to_hex(key),
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

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::crypto::sha256;
    use crate::utils::hex::{bytes_to_hex, hex_to_bytes};

    #[test]
    fn test_valid_pow() {
        // A known public key
        let pk = hex_to_bytes("35e7078109e597e07f65947f49fa5d15de153a1c6d8fb28aea7024091a9a7e21");

        // A PoW with enough leading zeros (8 bits = 1 byte)
        let valid_pow = (-2144843651i32).to_be_bytes(); // Should start with 00

        // A PoW without enough leading zeros
        let invalid_pow = 0x7FFFFFFFu32.to_be_bytes(); // Starts with 7F

        assert!(
            validate_proof_of_work(&pk, &valid_pow, 24),
            "PoW should be valid"
        );

        assert!(
            !validate_proof_of_work(&pk, &invalid_pow, 24),
            "PoW should be invalid"
        );

        // Optional: Output the hash for verification
        let pk_hex: String = bytes_to_hex(&pk);
        let data = format!("{}{}", pk_hex, u32::from_be_bytes(valid_pow));
        let hash = sha256(data.as_bytes());
        println!("Hash for valid PoW: {hash:02x?}");
    }
}
