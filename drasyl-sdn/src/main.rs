use clap::arg;
use clap::{Parser, Subcommand};
use drasyl_sdn::node::{SdnNode, SdnNodeConfig};
use drasyl_sdn::rest_api::{RestApiClient, RestApiServer};
use drasyl_sdn::version_info::VersionInfo;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::signal;
use tracing::{error, info, trace};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::writer::BoxMakeWriter;

// Custom writer for file logging
struct FileWriter(Arc<Mutex<File>>);

impl Write for FileWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}

impl Clone for FileWriter {
    fn clone(&self) -> Self {
        FileWriter(self.0.clone())
    }
}

#[derive(Parser, Debug)]
#[command(name = "drasyl")]
#[command(about = "drasyl provides secure, software-defined overlay networks")]
struct Cli {
    /// Path to a log file [defaults to stdout]
    #[arg(long, value_name = "file", global = true)]
    log_file: Option<PathBuf>,
    /// Log filter in `RUST_LOG` syntax (e.g. `info`, or `drasyl=warn,drasyl_sdn=trace`).
    /// If set, this overrides `RUST_LOG`.
    #[arg(long, value_name = "level", default_value = "info", global = true)]
    log_level: Option<String>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Runs the drasyl daemon
    Run {
        /// Path to config file
        #[arg(long, value_name = "file", default_value = "config.toml")]
        config: PathBuf,
        /// Path to authentication token file
        #[arg(long, value_name = "file", default_value = "auth.token")]
        token: PathBuf,
    },
    /// Shows the status of the running drasyl daemon
    Status {
        /// Path to authentication token file
        #[arg(long, value_name = "file", default_value = "auth.token")]
        token: PathBuf,
    },
    /// Shows the version of the drasyl daemon
    Version,
    /// Adds a network to the running drasyl daemon
    Add {
        /// Path to authentication token file
        #[arg(long, value_name = "file", default_value = "auth.token")]
        token: PathBuf,
        /// The URL of the network to add
        url: String,
    },
    /// Removes a network from the running drasyl daemon
    Remove {
        /// Path to authentication token file
        #[arg(long, value_name = "file", default_value = "auth.token")]
        token: PathBuf,
        /// The URL of the network to remove
        url: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let cli = Cli::parse();

    let filter = if let Some(f) = cli.log_level {
        EnvFilter::try_new(f)?
    } else {
        EnvFilter::from_default_env()
    };

    // Optional path to the log file (e.g. from LOG_FILE env var)
    let maybe_file = cli
        .log_file
        .and_then(|path| OpenOptions::new().append(true).create(true).open(path).ok());

    // Configure subscriber: file logger if available, otherwise console
    if let Some(file) = maybe_file {
        // Wrap the file handle in Arc<Mutex<...>> for thread-safe sharing
        let file = Arc::new(Mutex::new(file));
        // Create a writer factory that returns a BufWriter<FileWriter>
        let make_writer = {
            let file = file.clone();
            move || BufWriter::new(FileWriter(file.clone()))
        };

        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(BoxMakeWriter::new(make_writer))
            .init();
    } else {
        // Fallback to console logger
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }

    match cli.command {
        Commands::Run { config, token } => run_sdn_node(config, token).await,
        Commands::Status { token } => show_status(token).await,
        Commands::Version => show_version(),
        Commands::Add { token, url } => add_network(token, &url).await,
        Commands::Remove { token, url } => remove_network(token, &url).await,
    }
}

async fn run_sdn_node(
    config_path: PathBuf,
    token_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    // config
    let config = SdnNodeConfig::load_or_generate(config_path.to_str().unwrap())
        .expect("Failed to load SDN config");

    // identity
    info!("I am {}", config.id.pk);

    let token_path = token_path.to_str().expect("Invalid token path").to_owned();
    let node = Arc::new(SdnNode::start(config, token_path).await);
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
                    let msg = format!("rest_api failed to bind: {e}");
                    error!("{}", msg);
                    return Err(msg.into());
                }
            }
        }
        _ = node.cancelled() => {
            trace!("Node cancelled.");
        },
    }

    Ok(())
}

/// display detailed version information for the drasyl-sdn application
fn show_version() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let info = VersionInfo::new();

    // format and output version information
    println!("Version  : {0} ({1})", info.version, info.full_commit());
    println!("Built    : {0}", info.build_timestamp);
    println!("Profile  : {0}", info.profile());
    println!("Features : {0}", info.features);

    Ok(())
}

async fn show_status(
    token_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let token_path = token_path.to_str().expect("Invalid token path").to_owned();
    let client = RestApiClient::new(token_path);

    match client.status().await {
        Ok(status) => {
            println!("{status}");
        }
        Err(e) => {
            eprintln!("Failed to retrieve status: {e}");
            std::process::exit(1);
        }
    }

    Ok(())
}

async fn add_network(
    token_path: PathBuf,
    url: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let token_path = token_path.to_str().expect("Invalid token path").to_owned();
    let client = RestApiClient::new(token_path);

    match client.add_network(url).await {
        Ok(response) => {
            if response.success {
                println!("{}", response.message);
            } else {
                eprintln!("{}", response.message);
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Failed to add network: {e}");
            std::process::exit(1);
        }
    }

    Ok(())
}

async fn remove_network(
    token_path: PathBuf,
    url: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let token_path = token_path.to_str().expect("Invalid token path").to_owned();
    let client = RestApiClient::new(token_path);

    match client.remove_network(url).await {
        Ok(response) => {
            if response.success {
                println!("{}", response.message);
            } else {
                eprintln!("{}", response.message);
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Failed to remove network: {e}");
            std::process::exit(1);
        }
    }

    Ok(())
}
