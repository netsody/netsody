use clap::{Parser, Subcommand};
use drasyl::identity::Identity;
use drasyl::util;
use drasyl_sdn::node::SdnNode;
use drasyl_sdn::rest_api::{RestApi, load_auth_token};
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::sync::Arc;
use tokio::signal;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "drasyl-sdn")]
#[command(about = "An SDN client for the drasyl network")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Runs the SDN node
    Run {
        #[arg(num_args = 1..)]
        urls: Vec<String>,
    },
    /// Shows the status of the running SDN node
    Status,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run { urls } => run_sdn_node(urls).await,
        Commands::Status => show_status().await,
    }
}

async fn run_sdn_node(
    urls: Vec<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    // options
    let identity_file = util::get_env("IDENTITY_FILE", "drasyl.identity".to_string());
    let min_pow_difficulty = util::get_env("MIN_POW_DIFFICULTY", 24);

    // identity
    let id = Identity::load_or_generate(&identity_file, min_pow_difficulty)
        .expect("Failed to load identity");
    info!("I am {}", id.pk);

    let node = Arc::new(SdnNode::start(id, urls).await);
    let rest_api = RestApi::new(node.clone());

    let node_clone = node.clone();

    tokio::select! {
        biased;
        _ = async {
            #[cfg(unix)]
            {
                let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
                let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())?;
                tokio::select! {
                    _ = sigterm.recv() => {
                        info!("Shutdown initiated via SIGTERM.");
                    }
                    _ = sigint.recv() => {
                        info!("Shutdown initiated via SIGINT.");
                    }
                }
            }
            #[cfg(not(unix))]
            {
                signal::ctrl_c().await?;
                info!("Shutdown initiated via Ctrl+C.");
            }
            Ok::<_, std::io::Error>(())
        } => {
            node_clone.shutdown().await;
        }
        _ = rest_api.bind() => {}
        _ = node.cancelled() => {},
    }

    Ok(())
}

async fn show_status() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let client = Client::builder(TokioExecutor::new()).build_http();
    let token_file = util::get_env(
        "AUTH_FILE",
        drasyl_sdn::rest_api::AUTH_FILE_DEFAULT.to_string(),
    );
    let auth_token = load_auth_token(&token_file)
        .map_err(|e| format!("Failed to load auth token {}: {}", token_file, e))?;

    let uri = "http://localhost:22527/status"
        .parse::<hyper::Uri>()
        .map_err(|e| format!("Failed to parse URI: {}", e))?;
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("Authorization", format!("Bearer {}", auth_token))
        .body(Empty::<bytes::Bytes>::new())?;

    let response = client.request(req).await?;
    let status_code = response.status();

    if status_code.is_success() {
        let body_bytes = response.into_body().collect().await?.to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec())?;
        let status: drasyl_sdn::rest_api::Status = serde_json::from_str(&body_str)?;

        println!("{}", status);
    } else {
        eprintln!("Failed to retrieve status: HTTP {}", status_code);
        std::process::exit(1);
    }

    Ok(())
}
