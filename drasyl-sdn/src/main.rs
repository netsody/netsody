use clap::{Parser, Subcommand};
use drasyl::util;
use drasyl_sdn::node::{SdnNode, SdnNodeConfig};
use drasyl_sdn::rest_api::{RestApiClient, RestApiServer};
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info, trace};

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
    Run,
    /// Shows the status of the running SDN node
    Status,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run => run_sdn_node().await,
        Commands::Status => show_status().await,
    }
}

async fn run_sdn_node() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    // config
    let config_path = util::get_env("CONFIG", "config.toml".to_string());
    let config = SdnNodeConfig::load_or_generate(&config_path).expect("Failed to load SDN config");

    // identity
    info!("I am {}", config.id.pk);

    let node = Arc::new(SdnNode::start(config).await);
    let rest_api = RestApiServer::new(node.clone());

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
            trace!("Shutdown initiated via SIGTERM.");
            node_clone.shutdown().await;
        }
        res = rest_api.bind() => {
            match res {
                Ok(_) => {
                    trace!("rest_api shut down");
                }
                Err(e) => {
                    error!("rest_api failed to bind: {}", e);
                }
            }
        }
        _ = node.cancelled() => {
            trace!("Node cancelled.");
        },
    }

    Ok(())
}

async fn show_status() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let client = RestApiClient::new();

    match client.status().await {
        Ok(status) => {
            println!("{}", status);
        }
        Err(e) => {
            eprintln!("Failed to retrieve status: {e}");
            std::process::exit(1);
        }
    }

    Ok(())
}
