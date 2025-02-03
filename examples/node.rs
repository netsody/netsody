use drasyl::identity::Identity;
use drasyl::node::{Node, NodeOptsBuilder};
use drasyl::utils::crypto::ED25519_PUBLICKEYBYTES;
use drasyl::utils::hex::bytes_to_hex;
use drasyl::utils::{hex, system};
use hex::hex_to_bytes;
use log::{error, info};
use std::io::{Write, stdin, stdout};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    env_logger::init();

    let identity_file = system::get_env("IDENTITY_FILE", "node.identity".to_string());
    let network_id = system::get_env("NETWORK_ID", 1i32).to_be_bytes();
    let arm_messages = system::get_env("ARM_MESSAGES", true);
    let udp_listen = system::get_env("UDP_LISTEN", "0.0.0.0:-1".to_string());
    let max_peers = system::get_env("MAX_PEERS", 10 * 1000); // set to 0 removes peers limit
    let min_pow_difficulty = system::get_env("MIN_POW_DIFFICULTY", 24);
    let hello_timeout = system::get_env("HELLO_TIMEOUT", 30 * 1000); // milliseconds
    let hello_max_age = system::get_env("HELLO_MAX_AGE", 60 * 1000); // milliseconds
    let super_peers = system::get_env("SUPER_PEERS", "udp://sp-fkb1.drasyl.org:22527?publicKey=c0900bcfabc493d062ecd293265f571edb70b85313ba4cdda96c9f77163ba62d&networkId=1 udp://sp-rjl1.drasyl.org:22527?publicKey=5b4578909bf0ad3565bb5faf843a9f68b325dd87451f6cb747e49d82f6ce5f4c&networkId=1 udp://sp-nyc1.drasyl.org:22527?publicKey=bf3572dba7ebb6c5ccd037f3a978707b5d7c5a9b9b01b56b4b9bf059af56a4e0&networkId=1 udp://sp-sgp1.drasyl.org:22527?publicKey=ab7a1654d463f9986530bed00569cc895697827b802153b8ef1598579713045f&networkId=1".to_string());
    let recv_buf_cap = system::get_env("RECV_BUF_CAP", 64); // messages
    let process_unites = system::get_env("PROCESS_UNITES", true);
    let hello_endpoints = system::get_env("HELLO_ENDPOINTS", String::new());
    let housekeeping_delay = system::get_env("HOUSEKEEPING_DELAY", 5 * 1000); // milliseconds

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
        .housekeeping_delay(housekeeping_delay)
        .build()
        .expect("Failed to build node opts");

    // bind node
    let node = Node::bind(opts).await.expect("Failed to bind node");

    let node = Arc::new(node);

    // recv task
    let recv_node = node.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1472];
        loop {
            // read message
            let (size, src) = match recv_node.recv_from(&mut buf).await {
                Ok(result) => result,
                Err(e) => {
                    error!("Error receiving message: {}", e);
                    continue;
                }
            };

            // process message
            let buf_str = String::from_utf8_lossy(&buf[..size]);
            println!("{}: {} ({} bytes)", bytes_to_hex(&src), buf_str, size);
        }
    });

    // send task
    let mut last_recipient =
        "46d4013856a52275d96359fca1dfe43912737ec51aaab0139005d45620f9b0d3".to_string();
    loop {
        // Get recipient, using last recipient as default if available
        let mut recipient = String::new();
        if last_recipient.is_empty() {
            print!("Enter recipient public key: ");
        } else {
            print!("Enter recipient public key [{last_recipient}]: ");
        }
        stdout().flush().unwrap();
        stdin().read_line(&mut recipient).unwrap();
        recipient = recipient.trim().to_string();

        // Use last recipient if empty input
        if recipient.is_empty() && !last_recipient.is_empty() {
            recipient = last_recipient.clone();
        }

        // If no recipient was entered, repeat the loop
        if recipient.is_empty() {
            println!("No recipient entered.");
            continue;
        }

        // Get message text
        let mut message = String::new();
        print!("Enter message: ");
        stdout().flush().unwrap();
        stdin().read_line(&mut message).unwrap();
        message = message.trim().to_string();

        // Send message if we have both recipient and message
        if !recipient.is_empty() {
            let recipient_bytes = hex_to_bytes::<ED25519_PUBLICKEYBYTES>(recipient.as_str());
            if let Err(e) = node.send_to(&recipient_bytes, message.as_bytes()).await {
                println!("Error sending message: {e}");
            }
            last_recipient = recipient;
        }
    }
}
