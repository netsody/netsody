use drasyl_p2p::identity::{Identity, PubKey};
use drasyl_p2p::node::{MessageSink, Node, NodeOptsBuilder, SUPER_PEERS_DEFAULT};
use drasyl_p2p::peer::SuperPeerUrl;
use drasyl_p2p::util;
use std::io::{Write, stdin, stdout};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, mpsc};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let identity_file = util::get_env("IDENTITY_FILE", "node.identity".to_string());
    let arm_messages = util::get_env("ARM_MESSAGES", true);
    let udp_addrs = util::get_env("UDP_ADDRS", String::new());
    let udp_port = util::get_env("UDP_PORT", String::new());
    let max_peers = util::get_env("MAX_PEERS", 8192); // set to 0 removes peers limit
    let min_pow_difficulty = util::get_env("MIN_POW_DIFFICULTY", 24);
    let hello_timeout = util::get_env("HELLO_TIMEOUT", 30 * 1000); // milliseconds
    let hello_max_age = util::get_env("HELLO_MAX_AGE", 60 * 1000); // milliseconds
    let super_peers = SuperPeerUrl::parse_list(&util::get_env(
        "SUPER_PEERS",
        SUPER_PEERS_DEFAULT
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" "),
    ))
    .expect("Invalid super peer urls");
    let recv_buf_cap = util::get_env("RECV_BUF_CAP", 64); // messages
    let process_unites = util::get_env("PROCESS_UNITES", true);
    let housekeeping_interval = util::get_env("HOUSEKEEPING_INTERVAL", 5 * 1000); // milliseconds

    // identity
    let id = Identity::load_or_generate(&identity_file, min_pow_difficulty)
        .expect("Failed to load identity");
    println!("I am {}", id.pk);

    // build node
    let (recv_buf_tx, recv_buf_rx) = mpsc::channel::<(PubKey, Vec<u8>)>(recv_buf_cap);
    let recv_buf_rx = Arc::new(Mutex::new(recv_buf_rx));
    let opts = NodeOptsBuilder::default()
        .id(id)
        .arm_messages(arm_messages)
        .udp_addrs(
            udp_addrs
                .split_whitespace()
                .map(str::parse::<IpAddr>)
                .collect::<Result<Vec<_>, _>>()
                .expect("Invalid udp addresses"),
        )
        .udp_port(if udp_port.trim().is_empty() {
            None
        } else {
            udp_port.parse::<u16>().ok()
        })
        .max_peers(max_peers)
        .min_pow_difficulty(min_pow_difficulty)
        .hello_timeout(hello_timeout)
        .hello_max_age(hello_max_age)
        .super_peers(super_peers)
        .process_unites(process_unites)
        .housekeeping_interval(housekeeping_interval)
        .message_sink(Arc::new(ChannelSink(recv_buf_tx)))
        .build()
        .expect("Failed to build node opts");

    // bind node
    let node = Arc::new(Node::bind(opts).await.expect("Failed to bind node"));

    // Start background tasks
    let node_clone = node.clone();
    let recv_buf_rx_clone = recv_buf_rx.clone();

    tokio::spawn(async move {
        tokio::select! {
            _ = node.cancelled() => {},
            _ = recv_task(recv_buf_rx_clone) => {},
        }
    });

    // Run send task in foreground
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
            if let Err(e) = node_clone
                .send_to(
                    &PubKey::from_str(&recipient).expect("Invalid pub key"),
                    message.as_bytes(),
                )
                .await
            {
                eprintln!("Error sending message: {e}");
            }
            last_recipient = recipient;
        }
    }
}

#[allow(clippy::type_complexity)]
async fn recv_task(receiver: Arc<Mutex<Receiver<(PubKey, Vec<u8>)>>>) {
    while let Some((src, buf)) = receiver.lock().await.recv().await {
        let buf_str = String::from_utf8_lossy(&buf);
        println!("{}: {} ({} bytes)", src, buf_str, buf.len());
    }
}

pub struct ChannelSink(pub Sender<(PubKey, Vec<u8>)>);

impl MessageSink for ChannelSink {
    fn accept(&self, sender: PubKey, message: Vec<u8>) {
        match self.0.try_send((sender, message)) {
            Ok(_) => {}
            Err(e) => eprintln!("Received APP dropped: {e}"),
        }
    }
}
