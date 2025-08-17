use p2p::identity::{Identity, PubKey};
use p2p::node::{MessageSink, Node, NodeOptsBuilder};
use std::env;
use std::hint::spin_loop;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc::Sender;
use tokio::sync::{Mutex, mpsc};
use tracing::info;

// cargo run --package drasyl-bench --bin drasyl --release
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();

    if let Some(server) = args.get(1) {
        client(server).await
    } else {
        server().await
    }
}

async fn server() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    // identity
    let id = Identity::load_or_generate("server.identity", 24).expect("Failed to load identity");
    info!("I am {}", id.pk);

    // build node
    let (recv_buf_tx, recv_buf_rx) = mpsc::channel::<(PubKey, Vec<u8>)>(64);
    let recv_buf_rx = Arc::new(Mutex::new(recv_buf_rx));
    let opts = NodeOptsBuilder::default()
        .id(id.clone())
        .message_sink(Arc::new(ChannelSink(recv_buf_tx)))
        .build()
        .expect("Failed to build node opts");

    // bind node
    let _ = Node::bind(opts).await.expect("Failed to bind node");

    let profile = if cfg!(debug_assertions) {
        ""
    } else {
        " --release"
    };
    println!(
        "Listening. To connect, use:\ncargo run --package drasyl-bench --bin drasyl{} {}",
        profile, id.pk
    );

    while let Some((src, buf)) = recv_buf_rx.lock().await.recv().await {
        // process message
        println!("{}: {} bytes received", src, buf.len());
    }

    Ok(())
}

async fn client(server: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let server = PubKey::from_str(server)?;
    let bytes = vec![0];

    // identity
    let id = Identity::load_or_generate("client.identity", 24).expect("Failed to load identity");
    info!("I am {}", id.pk);

    // build node
    let opts = NodeOptsBuilder::default()
        .id(id.clone())
        .build()
        .expect("Failed to build node opts");

    // bind node
    let node = Node::bind(opts).await.expect("Failed to bind node");

    // wait some time to allow node to join network
    // time::sleep(Duration::from_secs(5)).await;

    let start = Instant::now();
    if let Err(e) = node.send_to(&server, &bytes).await {
        println!("Error sending message: {e}");
    }

    // we do not have an interface that notifies us...
    loop {
        if node.direct_path(&server) {
            break;
        }
        spin_loop();
    }
    let duration = start.elapsed();
    println!("result={}", duration.as_micros());

    Ok(())
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
