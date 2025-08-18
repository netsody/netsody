use derive_builder::Builder;
use p2p::identity::Identity;
use p2p::message::NetworkId;
use p2p::node::{
    ARM_MESSAGES_DEFAULT, HELLO_MAX_AGE_DEFAULT, HELLO_TIMEOUT_DEFAULT, MIN_POW_DIFFICULTY_DEFAULT,
    MTU_DEFAULT,
};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

pub const MAX_HOP_COUNT: u8 = 7u8;
pub const NETWORK_ID_DEFAULT: i32 = 1;
pub const UDP4_LISTEN_DEFAULT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 22527);
pub const UDP6_LISTEN_DEFAULT: SocketAddrV6 =
    SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 22527, 0, 0);
pub const TCP4_LISTEN_DEFAULT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8443);
pub const TCP6_LISTEN_DEFAULT: SocketAddrV6 =
    SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 8443, 0, 0);
pub const SEND_UNITES_DEFAULT: i32 = 5 * 1_000; // milliseconds, set to -1 disables UNITE sending
pub const MAX_PEERS_DEFAULT: u64 = 1 << 13; // 2**13 = 8192; set to 0 removes peers limit
pub const HOUSEKEEPING_INTERVAL_DEFAULT: u64 = 5 * 1_000;

#[derive(Clone, Builder)]
pub struct SuperPeerOpts {
    pub id: Identity,
    #[builder(default = "NETWORK_ID_DEFAULT.to_be_bytes()")]
    pub network_id: NetworkId,
    #[builder(default = "Some(UDP4_LISTEN_DEFAULT)")]
    pub udp4_listen: Option<SocketAddrV4>,
    #[builder(default = "Some(UDP6_LISTEN_DEFAULT)")]
    pub udp6_listen: Option<SocketAddrV6>,
    #[builder(default = "Some(TCP4_LISTEN_DEFAULT)")]
    pub tcp4_listen: Option<SocketAddrV4>,
    #[builder(default = "Some(TCP6_LISTEN_DEFAULT)")]
    pub tcp6_listen: Option<SocketAddrV6>,
    #[builder(default = "ARM_MESSAGES_DEFAULT")]
    pub arm_messages: bool,
    #[builder(default = "SEND_UNITES_DEFAULT")]
    pub send_unites: i32,
    #[builder(default = "MAX_PEERS_DEFAULT")]
    pub max_peers: u64,
    #[builder(default = "MIN_POW_DIFFICULTY_DEFAULT")]
    pub min_pow_difficulty: u8,
    #[builder(default = "HELLO_TIMEOUT_DEFAULT")]
    pub hello_timeout: u64,
    #[builder(default = "HELLO_MAX_AGE_DEFAULT")]
    pub hello_max_age: u64,
    #[builder(default = "MTU_DEFAULT")]
    pub mtu: usize,
    #[builder(default = "HOUSEKEEPING_INTERVAL_DEFAULT")]
    pub housekeeping_interval: u64,
}
