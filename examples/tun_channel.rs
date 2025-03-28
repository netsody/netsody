use drasyl::identity::Identity;
use drasyl::messages::ARM_HEADER_LEN;
use drasyl::node::{Node, NodeOptsBuilder};
use drasyl::utils::crypto::ED25519_PUBLICKEYBYTES;
use drasyl::utils::hex::{bytes_to_hex, hex_to_bytes};
use drasyl::utils::system;
use log::info;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tun_rs::DeviceBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    env_logger::init();

    let peer = hex_to_bytes::<ED25519_PUBLICKEYBYTES>(
        system::get_env(
            "PEER",
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        )
        .as_str(),
    );
    println!("peer : {}", bytes_to_hex(&peer));
    let ip: Ipv4Addr = format!("10.0.0.{}", system::get_env("IP", 1))
        .parse()
        .expect("Invalid IPv4 address"); // milliseconds
    println!("ip   : {ip}");

    let identity_file = system::get_env("IDENTITY_FILE", "node.identity".to_string());
    let network_id = system::get_env("NETWORK_ID", 1i32).to_be_bytes();
    let arm_messages = system::get_env("ARM_MESSAGES", true);
    let udp_listen = system::get_env("UDP_LISTEN", "0.0.0.0:-1".to_string());
    let max_peers = system::get_env("MAX_PEERS", 10_000); // set to 0 removes peers limit
    let min_pow_difficulty = system::get_env("MIN_POW_DIFFICULTY", 24);
    let hello_timeout = system::get_env("HELLO_TIMEOUT", 30 * 1000); // milliseconds
    let hello_max_age = system::get_env("HELLO_MAX_AGE", 60_000); // milliseconds
    let super_peers = system::get_env("SUPER_PEERS", "udp://sp-fkb1.drasyl.org:22527?publicKey=c0900bcfabc493d062ecd293265f571edb70b85313ba4cdda96c9f77163ba62d&networkId=1 udp://sp-rjl1.drasyl.org:22527?publicKey=5b4578909bf0ad3565bb5faf843a9f68b325dd87451f6cb747e49d82f6ce5f4c&networkId=1 udp://sp-nyc1.drasyl.org:22527?publicKey=bf3572dba7ebb6c5ccd037f3a978707b5d7c5a9b9b01b56b4b9bf059af56a4e0&networkId=1 udp://sp-sgp1.drasyl.org:22527?publicKey=ab7a1654d463f9986530bed00569cc895697827b802153b8ef1598579713045f&networkId=1".to_string());
    let recv_buf_cap = system::get_env("RECV_BUF_CAP", 64); // messages
    let process_unites = system::get_env("PROCESS_UNITES", true);
    let hello_endpoints = system::get_env("HELLO_ENDPOINTS", String::new());
    let hello_addresses_excluded = system::get_env("HELLO_ADDRESSES_EXCLUDED", ip.to_string());
    let housekeeping_delay = system::get_env("HOUSEKEEPING_DELAY", 5 * 1000); // milliseconds
    let channel_cap = system::get_env("CHANNEL_CAP", 256);

    // identity
    let id = Identity::load_or_generate(&identity_file, min_pow_difficulty)
        .expect("Failed to load identity");
    info!("I am {}", bytes_to_hex(&id.pk));

    // build node
    let opts = NodeOptsBuilder::default()
        .id(id)
        .network_id(network_id)
        .arm_messages(arm_messages)
        .udp_listen(udp_listen)
        .max_peers(max_peers)
        .min_pow_difficulty(min_pow_difficulty)
        .hello_timeout(hello_timeout)
        .hello_max_age(hello_max_age)
        .super_peers(super_peers)
        .recv_buf_cap(recv_buf_cap)
        .process_unites(process_unites)
        .hello_endpoints(hello_endpoints)
        .hello_addresses_excluded(hello_addresses_excluded)
        .housekeeping_delay(housekeeping_delay)
        .build()
        .expect("Failed to build node opts");

    // bind node
    let node = Node::bind(opts).await.expect("Failed to bind node");
    let node = Arc::new(node);

    let tun_mtu = if arm_messages {
        1472 - 4 - ARM_HEADER_LEN as u16 /* - 11 for COMPRESSION */ - 27
    } else {
        1472 - 4 /* - 11 for COMPRESSION */ - 27
    };
    let dev = DeviceBuilder::new()
        .ipv4(ip, 24, None)
        .mtu(tun_mtu)
        .build_async()?;
    let dev = Arc::new(dev);

    let (tun_tx, mut drasyl_rx) = mpsc::channel::<Vec<u8>>(channel_cap);
    let (drasyl_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(channel_cap);

    // tun -> channel
    let dev_clone = dev.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; tun_mtu as usize];
        while let Ok(size) = dev_clone.recv(&mut buf).await {
            tun_tx
                .send(buf[..size].to_vec())
                .await
                .expect("Error sending message to tun_tx");
        }
    });

    // channel -> tun
    let dev_clone = dev.clone();
    tokio::spawn(async move {
        while let Some(buf) = tun_rx.recv().await {
            if let Err(e) = dev_clone.send(&buf).await {
                eprintln!("Error sending message to tun: {e}");
            }
        }
    });

    // drasyl -> channel
    let node_clone = node.clone();
    tokio::spawn(async move {
        while let Ok((buf, _)) = node_clone.recv_from().await {
            drasyl_tx
                .send(buf)
                .await
                .expect("Error sending message to drasyl_tx");
        }
    });

    // channel -> drasyl
    let send_handle = node.send_handle(&peer).expect("Error creating send handle");
    while let Some(buf) = drasyl_rx.recv().await {
        send_handle
            .send(&buf)
            .await
            .expect("Error sending message to drasyl");
    }

    Ok(())
}
