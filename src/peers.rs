use crate::utils::crypto;
use crate::utils::hex;
use dashmap::DashMap;
use log::debug;
use std::fmt;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub enum PeersManagerError {
    CapacityExceeded,
}

impl fmt::Display for PeersManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeersManagerError::CapacityExceeded => {
                write!(f, "Peers list capacity ({}) exceeded", *crate::MAX_PEERS)
            }
        }
    }
}

#[derive(Debug)]
pub struct Peer {
    last_hello_time: u64,
    last_hello_src: Option<SocketAddr>,
    endpoints: Vec<SocketAddr>,
    pow_validation_time: u64,
    pow_valid: bool,
}

impl Peer {
    pub fn is_online(&self, now: u64) -> bool {
        let age = now - self.last_hello_time;
        age <= *crate::HELLO_ONLINE_TIMEOUT
    }

    pub fn is_pow_validation_outdated(&self, now: u64) -> bool {
        let age = now - self.last_hello_time;
        age > *crate::POW_VALIDATION_TIMEOUT
    }

    pub fn last_hello_src(&self) -> Option<SocketAddr> {
        self.last_hello_src
    }

    pub fn endpoints(&self) -> &Vec<SocketAddr> {
        &self.endpoints
    }

    pub fn contact_candidates(&self) -> Vec<SocketAddr> {
        self.last_hello_src()
            .into_iter()
            .chain(self.endpoints().iter().cloned())
            .collect()
    }
}

pub struct PeersManager {
    peers: DashMap<[u8; crypto::ED25519_PUBLICKEYBYTES], Peer>,
    unite_attempts: DashMap<
        (
            [u8; crypto::ED25519_PUBLICKEYBYTES],
            [u8; crypto::ED25519_PUBLICKEYBYTES],
        ),
        u64,
    >,
}

impl PeersManager {
    pub fn new() -> Self {
        PeersManager {
            peers: DashMap::new(),
            unite_attempts: DashMap::new(),
        }
    }

    pub fn hello_received(
        &self,
        public_key: &[u8; crypto::ED25519_PUBLICKEYBYTES],
        last_hello_src: SocketAddr,
        last_hello_time: u64,
        endpoints: Vec<SocketAddr>,
    ) -> Result<(), PeersManagerError> {
        if let Some(mut peer) = self.peers.get_mut(public_key) {
            peer.last_hello_time = last_hello_time;
            peer.last_hello_src = Some(last_hello_src);
            peer.endpoints = endpoints;
        } else {
            if self.peers.len() >= *crate::MAX_PEERS as usize {
                return Err(PeersManagerError::CapacityExceeded);
            }

            self.peers.insert(
                *public_key,
                Peer {
                    last_hello_time,
                    last_hello_src: Some(last_hello_src),
                    endpoints,
                    pow_validation_time: 0,
                    pow_valid: false,
                },
            );
        }

        Ok(())
    }

    pub fn housekeeping(&self, now: u64) {
        // remove offline peers
        self.peers.retain(|_, peer| peer.is_online(now));

        if *crate::SEND_UNITES > 0 {
            // remove expired unite attempts
            self.unite_attempts
                .retain(|_, &mut last_time| now - last_time < *crate::SEND_UNITES as u64);

            if *crate::SEND_UNITES as u64 > *crate::HELLO_ONLINE_TIMEOUT {
                self.unite_attempts
                    .retain(|(key1, _), _| self.peers.contains_key(key1));
            }
        }

        debug!("{}", self);
    }

    pub fn get_peer(
        &self,
        public_key: &[u8; crypto::ED25519_PUBLICKEYBYTES],
    ) -> Option<dashmap::mapref::one::Ref<'_, [u8; crypto::ED25519_PUBLICKEYBYTES], Peer>> {
        self.peers.get(public_key)
    }

    pub fn valid_pow(
        &self,
        public_key: &[u8; crypto::ED25519_PUBLICKEYBYTES],
        pow: &[u8; 4],
        now: u64,
    ) -> Result<bool, PeersManagerError> {
        // already verified?
        if let Some(peer) = self.peers.get(public_key) {
            if !peer.is_pow_validation_outdated(now) {
                return Ok(peer.pow_valid);
            }
        }

        // calculate proof of work difficulty
        let public_key_hex: String = public_key.iter().map(|b| format!("{:02x}", b)).collect();
        let input = format!("{}{}", public_key_hex, i32::from_be_bytes(*pow));
        let hash = crypto::sha256(input.as_bytes()).unwrap();

        // count leading zero bits
        let mut leading_zeros: u8 = 0;
        for &byte in hash.iter() {
            if byte == 0 {
                leading_zeros += 8;
            } else {
                leading_zeros += byte.leading_zeros() as u8;
                break;
            }
        }

        let is_valid = leading_zeros >= *crate::MIN_POW_DIFFICULTY;

        // save result
        if let Some(mut peer) = self.peers.get_mut(public_key) {
            peer.pow_validation_time = now;
            peer.pow_valid = is_valid;
        } else {
            if self.peers.len() >= *crate::MAX_PEERS as usize {
                return Err(PeersManagerError::CapacityExceeded);
            }

            self.peers.insert(
                *public_key,
                Peer {
                    last_hello_time: 0,
                    last_hello_src: None,
                    endpoints: Vec::new(),
                    pow_validation_time: now,
                    pow_valid: is_valid,
                },
            );
        }

        Ok(is_valid)
    }

    pub fn send_unites(
        &self,
        sender: &[u8; crypto::ED25519_PUBLICKEYBYTES],
        recipient: &[u8; crypto::ED25519_PUBLICKEYBYTES],
        now: u64,
    ) -> bool {
        // disabled
        if *crate::SEND_UNITES < 0 {
            return false;
        }

        // always send
        if *crate::SEND_UNITES == 0 {
            return true;
        }

        let key = (*sender, *recipient);
        let swapped_key = (*sender, *recipient);

        if let Some(last_time) = self.unite_attempts.get(&key) {
            if now - *last_time < *crate::SEND_UNITES as u64 {
                return false;
            }
        }

        self.unite_attempts.insert(key, now);
        self.unite_attempts.insert(swapped_key, now);

        true
    }
}

impl fmt::Display for PeersManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        writeln!(f, "Peers:")?;
        let mut count = 0;
        self.peers.iter().try_for_each(|item| {
            count += 1;
            let sender = item.key();
            let peer = item.value();
            let sender_hex = hex::bytes_to_hex(sender);

            let time_diff = now - peer.last_hello_time;
            let pow_age = now - peer.pow_validation_time;
            let is_online = peer.is_online(now);

            writeln!(f, "├─ {}:", sender_hex)?;
            writeln!(f, "│  ├─ Last hello time : {} ms ago", time_diff)?;
            writeln!(
                f,
                "│  ├─ Last hello src  : {}",
                peer.last_hello_src
                    .map_or("None".to_string(), |addr| addr.to_string())
            )?;
            writeln!(
                f,
                "│  ├─ Status          : {}",
                if is_online { "online" } else { "offline" }
            )?;
            writeln!(f, "│  │─ Endpoints       :")?;
            for (i, endpoint) in peer.endpoints.iter().enumerate() {
                if i == peer.endpoints.len() - 1 {
                    writeln!(f, "│  │  └─ {}", endpoint)?;
                } else {
                    writeln!(f, "│  │  ├─ {}", endpoint)?;
                }
            }
            writeln!(
                f,
                "│  ├─ PoW valid       : {} (validated {} ms ago)",
                peer.pow_valid, pow_age
            )?;

            // Add unite times
            writeln!(f, "│  └─ UNITE attempts  :")?;
            {
                let mut count = 0;
                self.unite_attempts.iter().for_each(|entry| {
                    let ((key, other), last_time) = entry.pair();
                    if key == sender {
                        count += 1;
                        let other = hex::bytes_to_hex(other);
                        let age = now - *last_time;
                        writeln!(f, "│     ├─ {} ({} ms ago)", other, age).unwrap();
                    }
                });
                if count == 0 {
                    writeln!(f, "│     └─ None")?;
                }
            }

            Ok(())
        })?;
        if count != 1 {
            write!(f, "└─ {} peers", count)?;
        } else {
            write!(f, "└─ 1 peer")?;
        }
        Ok(())
    }
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let time_diff = now - self.last_hello_time;
        write!(
            f,
            "{} (last HELLO {} ms ago)",
            self.last_hello_src
                .map_or("None".to_string(), |addr| addr.to_string()),
            time_diff
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::hex::hex_to_bytes;

    #[test]
    fn test_valid_pow() {
        let peers = PeersManager::new();

        // Ein bekannter public key
        let public_key =
            hex_to_bytes("35e7078109e597e07f65947f49fa5d15de153a1c6d8fb28aea7024091a9a7e21");

        // Ein POW mit genügend führenden Nullen (8 Bits = 1 Byte)
        let valid_pow = (-2144843651i32).to_be_bytes(); // Sollte mit 00 anfangen

        // Ein POW ohne genügend führende Nullen
        let invalid_pow = 0x7FFFFFFFu32.to_be_bytes(); // Fängt mit 7F an

        assert!(
            peers.valid_pow(&public_key, &valid_pow, 0),
            "POW sollte gültig sein"
        );

        // assert!(
        //     !peers.valid_pow(&public_key, &invalid_pow, 0),
        //     "POW sollte ungültig sein"
        // );

        // Optional: Ausgabe des Hashes zur Verifizierung
        let pk_hex: String = public_key.iter().map(|b| format!("{:02x}", b)).collect();
        let data = format!("{}{}", pk_hex, u32::from_be_bytes(valid_pow));
        let hash = crypto::sha256(data.as_bytes());
        println!("Hash für gültiges POW: {:02x?}", hash);
    }
}
