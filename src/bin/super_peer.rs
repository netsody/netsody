use drasyl::identity::Identity;
use drasyl::super_peer::{
    ARM_MESSAGES_DEFAULT, HELLO_MAX_AGE_DEFAULT, HELLO_TIMEOUT_DEFAULT, MAX_PEERS_DEFAULT,
    MIN_POW_DIFFICULTY_DEFAULT, NETWORK_ID_DEFAULT, SEND_UNITS_DEFAULT, SuperPeer, SuperPeerError,
    SuperPeerOptsBuilder, TCP4_LISTEN_DEFAULT, TCP6_LISTEN_DEFAULT, UDP4_LISTEN_DEFAULT,
    UDP6_LISTEN_DEFAULT,
};
use drasyl::utils::hex::bytes_to_hex;
use drasyl::utils::net::{get_addrs, listening_addrs};
use drasyl::utils::system;
use log::info;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

#[tokio::main]
async fn main() -> Result<(), SuperPeerError> {
    env_logger::init();

    let identity_file = system::get_env("IDENTITY_FILE", "super_peer.identity".to_string());
    let network_id = system::get_env("NETWORK_ID", NETWORK_ID_DEFAULT).to_be_bytes();
    let udp4_listen = system::get_env("UDP4_LISTEN", UDP4_LISTEN_DEFAULT.to_string());
    let udp6_listen = system::get_env("UDP6_LISTEN", UDP6_LISTEN_DEFAULT.to_string());
    let tcp4_listen = system::get_env("TCP4_LISTEN", TCP4_LISTEN_DEFAULT.to_string());
    let tcp6_listen = system::get_env("TCP6_LISTEN", TCP6_LISTEN_DEFAULT.to_string());
    let arm_messages = system::get_env("ARM_MESSAGES", ARM_MESSAGES_DEFAULT);
    let send_unites = system::get_env("SEND_UNITES", SEND_UNITS_DEFAULT); // milliseconds, set to -1 disables UNITE sending
    let max_peers = system::get_env("MAX_PEERS", MAX_PEERS_DEFAULT); // set to 0 removes peers limit
    let min_pow_difficulty = system::get_env("MIN_POW_DIFFICULTY", MIN_POW_DIFFICULTY_DEFAULT);
    let hello_timeout = system::get_env("HELLO_TIMEOUT", HELLO_TIMEOUT_DEFAULT); // milliseconds
    let hello_max_age = system::get_env("HELLO_MAX_AGE", HELLO_MAX_AGE_DEFAULT); // milliseconds

    let udp4_listen: Option<SocketAddrV4> = if udp4_listen.is_empty() {
        None
    } else {
        Some(
            udp4_listen
                .to_owned()
                .parse()
                .unwrap_or_else(|_| panic!("Invalid UDP4 listen address: {udp4_listen}")),
        )
    };

    let udp6_listen: Option<SocketAddrV6> = if udp6_listen.is_empty() {
        None
    } else {
        Some(
            udp6_listen
                .to_owned()
                .parse()
                .unwrap_or_else(|_| panic!("Invalid UDP6 listen address: {udp6_listen}")),
        )
    };

    let tcp4_listen: Option<SocketAddrV4> = if tcp4_listen.is_empty() {
        None
    } else {
        Some(
            tcp4_listen
                .to_owned()
                .parse()
                .unwrap_or_else(|_| panic!("Invalid TCP4 listen address: {tcp4_listen}")),
        )
    };

    let tcp6_listen: Option<SocketAddrV6> = if tcp6_listen.is_empty() {
        None
    } else {
        Some(
            tcp6_listen
                .to_owned()
                .parse()
                .unwrap_or_else(|_| panic!("Invalid TCP6 listen address: {tcp6_listen}")),
        )
    };

    // identity
    let id = Identity::load_or_generate(&identity_file, min_pow_difficulty)
        .expect("Failed to load identity");
    info!("I am {}", bytes_to_hex(&id.pk));

    // urls
    let my_addrs = get_addrs()?;
    let network_id_str = i32::from_be_bytes(network_id);
    let public_key = bytes_to_hex(&id.pk);

    let tcp_port_str = if let Some(port) = tcp6_listen
        .map(|a| a.port())
        .or_else(|| tcp4_listen.map(|a| a.port()))
    {
        format!("&tcpPort={port}")
    } else {
        String::new()
    };

    for listen_addr in [
        udp4_listen.map(SocketAddr::V4),
        udp6_listen.map(SocketAddr::V6),
    ]
    .into_iter()
    .flatten()
    {
        let (ip, port) = match listen_addr {
            SocketAddr::V4(addr) => (IpAddr::V4(*addr.ip()), addr.port()),
            SocketAddr::V6(addr) => (IpAddr::V6(*addr.ip()), addr.port()),
        };
        for listening_addr in listening_addrs(&ip, &my_addrs) {
            info!(
                "  udp://{}:{}?publicKey={}&networkId={}{}",
                listening_addr, port, public_key, network_id_str, tcp_port_str
            );
        }
    }

    // build super peer
    let opts = SuperPeerOptsBuilder::default()
        .id(id)
        .network_id(network_id)
        .udp4_listen(udp4_listen)
        .udp6_listen(udp6_listen)
        .tcp4_listen(tcp4_listen)
        .tcp6_listen(tcp6_listen)
        .arm_messages(arm_messages)
        .send_unites(send_unites)
        .max_peers(max_peers)
        .min_pow_difficulty(min_pow_difficulty)
        .hello_timeout(hello_timeout)
        .hello_max_age(hello_max_age)
        .build()
        .expect("Failed to build super peer opts");

    // bind super peer
    SuperPeer::bind(opts).await?;

    Ok(())
}
