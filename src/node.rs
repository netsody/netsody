use crate::peers::PeersManager;
use std::net::UdpSocket;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::identity::derive_public_key;
use crate::utils::{crypto, hex};
use std::sync::atomic::{AtomicU64, Ordering};
use log::info;
use std::{fmt, io};
use crate::{identity, IDENTITY_FILE, NETWORK_ID, SERVER_LISTEN};

#[derive(Debug)]
pub enum NodeError {
    IdentityFileError(io::Error),
    BindError(io::Error),
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeError::IdentityFileError(e) => {
                write!(f, "Identity file error: {}", e)
            }
            NodeError::BindError(e) => {
                write!(f, "Bind error: {}", e)
            }
        }
    }
}


pub struct Node {
    network_id: [u8; 4],
    secret_key: [u8; crypto::ED25519_SECRETKEYBYTES],
    public_key: [u8; crypto::ED25519_PUBLICKEYBYTES],
    pow: [u8; 4],
    socket: UdpSocket,
    peers: PeersManager,
    now: AtomicU64,
}

impl Node {
    pub fn new() -> Result<Node, NodeError> {
        match identity::load_identity(&IDENTITY_FILE) {
            Ok((secret_key, pow)) => {
                let public_key = derive_public_key(&secret_key);
                info!("I'm node {}", hex::bytes_to_hex(&public_key));

                match UdpSocket::bind(&SERVER_LISTEN.to_string()) {
                    Ok(socket) => {
                        info!("UDP socket bound to {}", socket.local_addr().unwrap());

                        Ok(Node {
                            network_id: *NETWORK_ID,
                            secret_key,
                            public_key: public_key,
                            pow,
                            socket,
                            peers: PeersManager::new(),
                            now: AtomicU64::new(Self::clock()),
                        })
                    }
                    Err(e) => Err(NodeError::BindError(e))
                }
            }
            Err(e) => Err(NodeError::IdentityFileError(e))
        }
    }

    pub fn housekeeping(&self) {
        // update now time
        self.now.store(Self::clock(), Ordering::Relaxed);

        self.peers.housekeeping(self.now());
    }

    pub fn network_id(&self) -> &[u8; 4] {
        &self.network_id
    }

    pub fn secret_key(&self) -> &[u8; crypto::ED25519_SECRETKEYBYTES] {
        &self.secret_key
    }

    pub fn public_key(&self) -> &[u8; crypto::ED25519_PUBLICKEYBYTES] {
        &self.public_key
    }

    pub fn pow(&self) -> &[u8; 4] {
        &self.pow
    }

    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    pub fn peers(&self) -> &PeersManager {
        &self.peers
    }

    pub fn now(&self) -> u64 {
        self.now.load(Ordering::Relaxed)
    }

    fn clock() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }
}
