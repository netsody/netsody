use iroh::{Endpoint, SecretKey};
use iroh_base::ticket::NodeTicket;
use std::env;
use std::str::FromStr;
use std::time::Instant;
use tracing::{info, warn};

const ALPN: &[u8] = b"DRASYLBENCHV0";

// cargo run --package drasyl-bench --bin iroh --release
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();

    if let Some(ticket) = args.get(1) {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .init();
        client(ticket).await
    } else {
        server().await
    }
}

async fn server() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let secret_key = get_or_create_secret()?;
    let endpoint = Endpoint::builder()
        .discovery_n0()
        .alpns(vec![ALPN.to_vec()])
        .secret_key(secret_key)
        .bind()
        .await?;

    let mut node = endpoint.node_addr().await?.clone();
    node.relay_url.take(); // ensure no direct connection will be established
    node.direct_addresses.clear(); // direct addresses should be negotiated
    let ticket = NodeTicket::new(node);

    let profile = if cfg!(debug_assertions) {
        ""
    } else {
        " --release"
    };
    println!(
        "Listening. To connect, use:\ncargo run --package drasyl-bench --bin iroh{} {}",
        profile, ticket
    );

    loop {
        let Some(connecting) = endpoint.accept().await else {
            break;
        };
        let connection = match connecting.await {
            Ok(connection) => connection,
            Err(cause) => {
                warn!("error accepting connection: {}", cause);
                // if accept fails, we want to continue accepting connections
                continue;
            }
        };
        let remote_node_id = &connection.remote_node_id()?;
        info!("got connection from {}", remote_node_id);
        // loop {
        //
        // }
        break;
    }
    Ok(())
}

async fn client(ticket: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let secret_key = get_or_create_secret()?;
    let endpoint = Endpoint::builder()
        .discovery_n0()
        .alpns(vec![])
        .secret_key(secret_key)
        .bind()
        .await?;

    let ticket = NodeTicket::from_str(ticket)?;
    let node = ticket.node_addr();

    let start = Instant::now();
    // FIXME: check for direct connection
    let _connection = endpoint.connect(node.clone(), ALPN).await?;
    // loop {
    //     connection.send_datagram(bytes::Bytes::from(b"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_vec()))?;
    // }

    let duration = start.elapsed();
    println!("result={}", duration.as_micros());

    Ok(())
}

/// Get the secret key or generate a new one.
///
/// Print the secret key to stderr if it was generated, so the user can save it.
fn get_or_create_secret() -> Result<SecretKey, Box<dyn std::error::Error + Send + Sync + 'static>> {
    match env::var("IROH_SECRET") {
        Ok(secret) => Ok(SecretKey::from_str(&secret)?),
        Err(_) => {
            let key = SecretKey::generate(rand::rngs::OsRng);
            info!("using secret key {}", key);
            Ok(key)
        }
    }
}
