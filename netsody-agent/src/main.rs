use clap::arg;
use clap::{Parser, Subcommand};
use netsody_agent::agent::{Agent, AgentConfig, PlatformDependent};
use netsody_agent::rest_api::{RestApiClient, RestApiServer};
use netsody_agent::version_info::VersionInfo;
#[cfg(target_os = "windows")]
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
#[cfg(target_os = "windows")]
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::signal;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
#[cfg(target_os = "windows")]
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler,
    service_control_handler::ServiceControlHandlerResult,
    service_dispatcher,
};

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
#[command(name = "netsody")]
#[command(
    about = "Netsody provides secure, software-defined overlay networks, connecting all your devices"
)]
struct Cli {
    /// Path to a log file [defaults to stdout]
    #[arg(long, value_name = "file", global = true)]
    log_file: Option<PathBuf>,
    /// Log filter in `RUST_LOG` syntax (e.g. `info`, or `netsody=warn,netsody_agent=trace`).
    /// If set, this overrides `RUST_LOG`.
    #[arg(long, value_name = "level", default_value = "info", global = true)]
    log_level: Option<String>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Runs the Netsody agent
    Run {
        /// Path to config file
        #[arg(long, value_name = "file", default_value = "config.toml")]
        config: PathBuf,
        /// Path to authentication token file
        #[arg(long, value_name = "file", default_value = "auth.token")]
        token: PathBuf,
    },
    #[cfg(target_os = "windows")]
    /// Runs the Netsody agent as a Windows service
    RunService {
        /// Path to config file
        #[arg(long, value_name = "file", default_value = "config.toml")]
        config: PathBuf,
        /// Path to authentication token file
        #[arg(long, value_name = "file", default_value = "auth.token")]
        token: PathBuf,
    },
    /// Shows the status of the running Netsody agent
    Status {
        /// Path to authentication token file
        #[arg(long, value_name = "file", default_value = "auth.token")]
        token: PathBuf,
        /// Include secrets in the output (default: secrets are masked)
        #[arg(long)]
        include_secrets: bool,
    },
    /// Shows the version of the Netsody agent
    Version,
    /// Adds a network to the running Netsody agent
    Add {
        /// Path to authentication token file
        #[arg(long, value_name = "file", default_value = "auth.token")]
        token: PathBuf,
        /// The URL of the network to add
        url: String,
    },
    /// Removes a network from the running Netsody agent
    Remove {
        /// Path to authentication token file
        #[arg(long, value_name = "file", default_value = "auth.token")]
        token: PathBuf,
        /// The URL of the network to remove
        url: String,
    },
    /// Disables a network in the running Netsody agent
    Disable {
        /// Path to authentication token file
        #[arg(long, value_name = "file", default_value = "auth.token")]
        token: PathBuf,
        /// The URL of the network to disable
        url: String,
    },
    /// Enables a network in the running Netsody agent
    Enable {
        /// Path to authentication token file
        #[arg(long, value_name = "file", default_value = "auth.token")]
        token: PathBuf,
        /// The URL of the network to enable
        url: String,
    },
}

fn setup_logging(
    log_file: Option<PathBuf>,
    log_level: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let filter = if let Some(f) = log_level {
        EnvFilter::try_new(f)?
    } else {
        EnvFilter::from_default_env()
    };

    // Optional path to the log file (e.g. from LOG_FILE env var)
    let maybe_file =
        log_file.and_then(|path| OpenOptions::new().append(true).create(true).open(path).ok());

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
            .with_ansi(false)
            .init();
    } else {
        // Fallback to console logger
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .init();
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let cli = Cli::parse();

    setup_logging(cli.log_file, cli.log_level)?;

    match cli.command {
        Commands::Run { config, token } => run_agent(config, token, None),
        #[cfg(target_os = "windows")]
        Commands::RunService { config, token } => run_agent_win(config, token),
        Commands::Status {
            token,
            include_secrets,
        } => show_status(token, include_secrets),
        Commands::Version => show_version(),
        Commands::Add { token, url } => add_network(token, &url),
        Commands::Remove { token, url } => remove_network(token, &url),
        Commands::Disable { token, url } => disable_network(token, &url),
        Commands::Enable { token, url } => enable_network(token, &url),
    }
}

fn run_agent(
    config_path: PathBuf,
    token_path: PathBuf,
    cancellation_token: Option<CancellationToken>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    // config
    let config_path = config_path.to_str().unwrap();
    let config = AgentConfig::load_or_generate(config_path).expect("Failed to load agent config");

    // identity
    info!("I am {}", config.id.pk);

    let rt = Runtime::new().unwrap();

    let result = rt.block_on(async {
        {
            let token_path = token_path.to_str().expect("Invalid token path").to_owned();
            let agent = Arc::new(
                Agent::start(
                    config,
                    config_path.to_string(),
                    token_path,
                    PlatformDependent {},
                )
                .await
                .expect("Failed to start agent"),
            );
            let rest_api = RestApiServer::new(agent.clone());

            let agent_clone = agent.clone();
            let cancellation_token = cancellation_token.unwrap_or_default();

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
                agent_clone.shutdown().await;
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
                _ = agent.cancelled() => {
                    trace!("Node cancelled.");
                },
                _ = cancellation_token.cancelled() => {
                    trace!("Cancellation token cancelled");
                }
            }
        }

        Ok(())
    });
    trace!("Runtime finished");
    result
}

#[cfg(target_os = "windows")]
define_windows_service!(ffi_service_main, run_agent_win_entry);

#[cfg(target_os = "windows")]
fn run_agent_win_entry(arguments: Vec<OsString>) {
    let cancellation_token = CancellationToken::new();
    let child_token = cancellation_token.child_token();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                // Handle stop event and return control back to the system.
                cancellation_token.cancel();
                ServiceControlHandlerResult::NoError
            }
            // All services must accept Interrogate even if it's a no-op.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // Register system service event handler
    let status_handle = service_control_handler::register("netsody", event_handler).unwrap();

    // Tell the system that the service is running now
    status_handle
        .set_service_status(ServiceStatus {
            // Should match the one from system service registry
            service_type: ServiceType::OWN_PROCESS,
            // The new state
            current_state: ServiceState::Running,
            // Accept stop events when running
            controls_accepted: ServiceControlAccept::STOP,
            // Used to report an error when starting or stopping only, otherwise must be zero
            exit_code: ServiceExitCode::Win32(0),
            // Only used for pending states, otherwise must be zero
            checkpoint: 0,
            // Only used for pending states, otherwise must be zero
            wait_hint: Duration::default(),
            // Unused for setting status
            process_id: None,
        })
        .expect("Failed to set service status to running");

    // Retrieve config_path and token_path from global state
    if let (Some(config_path), Some(token_path)) = (
        CONFIG_PATH.lock().unwrap().as_ref(),
        TOKEN_PATH.lock().unwrap().as_ref(),
    ) {
        // Start the actual agent
        if let Err(e) = run_agent(config_path.clone(), token_path.clone(), Some(child_token)) {
            error!("Failed to start agent: {}", e);
        }
    } else {
        error!("Configuration paths not available in service context");
    }

    // Tell the system that the service is stopped now
    status_handle
        .set_service_status(ServiceStatus {
            // Should match the one from system service registry
            service_type: ServiceType::OWN_PROCESS,
            // The new state
            current_state: ServiceState::Stopped,
            // Accept stop events when running
            controls_accepted: ServiceControlAccept::empty(),
            // Used to report an error when starting or stopping only, otherwise must be zero
            exit_code: ServiceExitCode::Win32(0),
            // Only used for pending states, otherwise must be zero
            checkpoint: 0,
            // Only used for pending states, otherwise must be zero
            wait_hint: Duration::default(),
            // Unused for setting status
            process_id: None,
        })
        .expect("Failed to set service status to stopped");
}

#[cfg(target_os = "windows")]
static CONFIG_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);
#[cfg(target_os = "windows")]
static TOKEN_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

#[cfg(target_os = "windows")]
fn run_agent_win(
    config_path: PathBuf,
    token_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    // Store config_path and token_path in global state
    *CONFIG_PATH.lock().unwrap() = Some(config_path);
    *TOKEN_PATH.lock().unwrap() = Some(token_path);

    // Register generated `ffi_service_main` with the system and start the service, blocking
    // this thread until the service is stopped.
    service_dispatcher::start("netsody", ffi_service_main)?;

    Ok(())
}

/// display detailed version information for the netsody-agent application
fn show_version() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let info = VersionInfo::new();

    // format and output version information
    println!("Version  : {0} ({1})", info.version, info.full_commit());
    println!("Built    : {0}", info.build_timestamp);
    println!("Profile  : {0}", info.profile());
    println!("Features : {0}", info.features);

    Ok(())
}

fn show_status(
    token_path: PathBuf,
    include_secrets: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let rt = Runtime::new().unwrap();

    rt.block_on(async {
        let token_path = token_path.to_str().expect("Invalid token path").to_owned();
        let client = RestApiClient::new(token_path);

        match client.status().await {
            Ok(status) => {
                // Ignore any I/O errors (including broken pipe when piping to head, tail, etc.)
                use std::io::Write;
                let status_text = status.to_string_with_secrets(include_secrets);
                let _ = writeln!(std::io::stdout(), "{}", status_text);
            }
            Err(e) => {
                eprintln!("Failed to retrieve status: {e}");
                std::process::exit(1);
            }
        }

        Ok(())
    })
}

fn add_network(
    token_path: PathBuf,
    url: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let rt = Runtime::new().unwrap();

    rt.block_on(async {
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
    })
}

fn remove_network(
    token_path: PathBuf,
    url: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let rt = Runtime::new().unwrap();

    rt.block_on(async {
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
    })
}

fn disable_network(
    token_path: PathBuf,
    url: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let rt = Runtime::new().unwrap();

    rt.block_on(async {
        let token_path = token_path.to_str().expect("Invalid token path").to_owned();
        let client = RestApiClient::new(token_path);

        match client.disable_network(url).await {
            Ok(response) => {
                if response.success {
                    println!("{}", response.message);
                } else {
                    eprintln!("{}", response.message);
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("Failed to disable network: {e}");
                std::process::exit(1);
            }
        }

        Ok(())
    })
}

fn enable_network(
    token_path: PathBuf,
    url: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let rt = Runtime::new().unwrap();

    rt.block_on(async {
        let token_path = token_path.to_str().expect("Invalid token path").to_owned();
        let client = RestApiClient::new(token_path);

        match client.enable_network(url).await {
            Ok(response) => {
                if response.success {
                    println!("{}", response.message);
                } else {
                    eprintln!("{}", response.message);
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("Failed to enable network: {e}");
                std::process::exit(1);
            }
        }

        Ok(())
    })
}
