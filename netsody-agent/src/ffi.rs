use crate::agent::{Agent, AgentConfig, Error, PlatformDependent};
use crate::network::Network;
use crate::version_info::VersionInfo;
use std::ffi::{CStr, CString, c_char, c_void};
use std::os::raw::c_int;
use std::sync::{Arc, OnceLock};
use tokio::runtime::Runtime;
use tracing::{Level, trace, warn};
use tracing_subscriber::FmtSubscriber;
use tun_rs::AsyncDevice as TunDevice;
use url::Url;

// -1..-100
const ERR_UTF8: c_int = -1;
const ERR_IO: c_int = -2;
const ERR_INVALID_URL: c_int = -3;
const ERR_NETWORK_NOT_FOUND: c_int = -4;
const ERR_NETWORK_ALREADY_EXISTS: c_int = -5;
const ERR_NETWORK_ALREADY_ENABLED: c_int = -6;
const ERR_NETWORK_ALREADY_DISABLED: c_int = -7;

// -101..
impl From<Error> for c_int {
    fn from(value: Error) -> Self {
        match value {
            Error::HttpClientError(_) => -101,
            Error::HttpUriError(_) => -102,
            Error::HyperError(_) => -103,
            Error::Utf8Error(_) => -104,
            Error::IOError(_) => -105,
            Error::TomlError(_) => -106,
            Error::HttpError(_) => -107,
            Error::UrlError(_) => -108,
            Error::NetworkError(_) => -109,
            Error::IdentityError(_) => -110,
            Error::NodeError(_) => -111,
            Error::TomlSerError(_) => -112,
            Error::ConfigParseError { .. } => -113,
            Error::NetworkAlreadyExists { .. } => -114,
            Error::NetworkNotFound { .. } => -115,
            Error::UnsupportedTunCreationPlatform => -116,
        }
    }
}

static VERSION_CSTR: OnceLock<CString> = OnceLock::new();

#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_version() -> *const c_char {
    VERSION_CSTR
        .get_or_init(|| {
            let info = VersionInfo::new();
            CString::new(format!("{} ({})", info.version, info.full_commit()))
                .expect("no interior NULs")
        })
        .as_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_init_logging() -> c_int {
    // Set the global subscriber with TRACE level
    let subscriber = FmtSubscriber::builder()
        .with_ansi(false)
        .with_max_level(Level::TRACE) // or Level::DEBUG, etc.
        .finish();

    #[cfg(target_os = "android")]
    let subscriber = {
        use tracing_subscriber::layer::SubscriberExt;
        subscriber.with(tracing_android::layer(env!("CARGO_PKG_NAME")).unwrap())
    };

    #[cfg(any(target_os = "ios", target_os = "tvos"))]
    let subscriber = {
        use tracing_oslog::OsLogger;
        use tracing_subscriber::layer::SubscriberExt;

        tracing_subscriber::registry()
            .with(tracing_subscriber::filter::LevelFilter::TRACE)
            .with(OsLogger::new(env!("CARGO_PKG_NAME"), "default"))
    };

    match tracing::subscriber::set_global_default(subscriber) {
        Ok(_) => 0,
        Err(_) => ERR_IO,
    }
}

//
// TUN Device
//
#[repr(C)]
pub struct TunDevicePtr(*mut c_void);

impl From<Arc<TunDevice>> for TunDevicePtr {
    fn from(tun_device: Arc<TunDevice>) -> Self {
        Self(Box::into_raw(Box::new(tun_device)) as *mut c_void)
    }
}

impl From<&mut TunDevicePtr> for &Arc<TunDevice> {
    fn from(tun_device: &mut TunDevicePtr) -> Self {
        unsafe { &*(tun_device.0 as *const Arc<TunDevice>) }
    }
}

impl Drop for TunDevicePtr {
    fn drop(&mut self) {
        unsafe {
            let tun_device = Box::from_raw(self.0 as *mut Arc<TunDevice>);
            drop(tun_device);
        }
    }
}

//
// Runtime
//
#[repr(C)]
pub struct RuntimePtr(*mut c_void);

impl From<Runtime> for RuntimePtr {
    fn from(runtime: Runtime) -> Self {
        Self(Box::into_raw(Box::new(runtime)) as *mut c_void)
    }
}

impl From<&mut RuntimePtr> for &Runtime {
    fn from(runtime: &mut RuntimePtr) -> Self {
        unsafe { &*(runtime.0 as *const Runtime) }
    }
}

impl Drop for RuntimePtr {
    fn drop(&mut self) {
        unsafe {
            let runtime = Box::from_raw(self.0 as *mut Runtime);
            drop(runtime);
        }
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_runtime(runtime: *mut *mut RuntimePtr) -> c_int {
    if runtime.is_null() {
        return ERR_IO;
    }

    unsafe {
        match Runtime::new() {
            Ok(rt) => {
                let runtime_ptr = RuntimePtr::from(rt);
                *runtime = Box::into_raw(Box::new(runtime_ptr));
                0
            }
            Err(_) => ERR_IO,
        }
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_runtime_free(runtime: *mut RuntimePtr) {
    if !runtime.is_null() {
        unsafe {
            let runtime_ptr = Box::from_raw(runtime);
            drop(runtime_ptr);
        }
    }
}

//
// AgentConfig
//
#[repr(C)]
pub struct NetworkInfo {
    pub url: *const c_char, // Owned C-String pointer (freed on drop)
    pub disabled: c_int,    // Disabled status (0 = enabled, 1 = disabled)
}

impl Drop for NetworkInfo {
    fn drop(&mut self) {
        if !self.url.is_null() {
            unsafe {
                trace!("Dropping NetworkInfo and freeing CString");
                let cstring = CString::from_raw(self.url as *mut c_char);
                drop(cstring);
            }
        }
    }
}

#[repr(C)]
pub struct AgentConfigPtr(*mut c_void);

impl From<AgentConfig> for AgentConfigPtr {
    fn from(config: AgentConfig) -> Self {
        Self(Box::into_raw(Box::new(config)) as *mut c_void)
    }
}

impl From<&mut AgentConfigPtr> for &AgentConfig {
    fn from(config: &mut AgentConfigPtr) -> Self {
        unsafe { &*(config.0 as *const AgentConfig) }
    }
}

impl Drop for AgentConfigPtr {
    fn drop(&mut self) {
        unsafe {
            let config = Box::from_raw(self.0 as *mut AgentConfig);
            drop(config);
        }
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_config_load_or_generate(
    path: *const c_char,
    config: *mut *mut AgentConfigPtr,
) -> c_int {
    if path.is_null() || config.is_null() {
        return ERR_IO;
    }

    unsafe {
        let path_str = match CStr::from_ptr(path).to_str() {
            Ok(s) => s,
            Err(_) => return ERR_UTF8,
        };

        match AgentConfig::load_or_generate(path_str) {
            Ok(my_config) => {
                *config = Box::into_raw(Box::new(my_config.into()));
                0
            }
            Err(e) => {
                warn!("Error loading config: {}", e);
                e.into()
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_config_id_pk(
    config: &mut AgentConfigPtr,
    pk: *mut c_char,
) -> c_int {
    if pk.is_null() {
        return ERR_IO;
    }

    unsafe {
        // Extract the AgentConfig from the pointer
        let agent_config: &AgentConfig = config.into();

        // Convert the Public Key to 32 bytes
        let public_key_bytes: [u8; 32] = agent_config.id.pk.into();

        // Copy the 32 bytes to the provided buffer
        std::ptr::copy_nonoverlapping(public_key_bytes.as_ptr(), pk as *mut u8, 32);

        0
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_config_free(config: *mut AgentConfigPtr) {
    if !config.is_null() {
        unsafe {
            trace!("Freeing AgentConfigPtr");
            let config_ptr = Box::from_raw(config);
            drop(config_ptr);
        }
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_config_network_add(
    path: *const c_char,
    network_url: *const c_char,
) -> c_int {
    if path.is_null() || network_url.is_null() {
        return ERR_IO;
    }

    unsafe {
        let path_str = match CStr::from_ptr(path).to_str() {
            Ok(s) => s,
            Err(_) => return ERR_UTF8,
        };

        let network_url_str = match CStr::from_ptr(network_url).to_str() {
            Ok(s) => s,
            Err(_) => return ERR_UTF8,
        };

        // Load the current config
        let mut agent_config = match AgentConfig::load(path_str) {
            Ok(config) => config,
            Err(_) => return ERR_IO,
        };

        // Parse the network URL
        let url = match Url::parse(network_url_str) {
            Ok(u) => u,
            Err(_) => return ERR_INVALID_URL,
        };

        // Check if network already exists
        if agent_config.networks.contains_key(&url) {
            return ERR_NETWORK_ALREADY_EXISTS;
        }

        // Create new network
        let network = Network {
            config_url: network_url_str.to_string(),
            disabled: false,
            name: None,
            current_state: Default::default(),
            desired_state: Default::default(),
            status: Default::default(),
        };

        // Add network to config
        agent_config.networks.insert(url, network);

        // Save config to file
        if agent_config.save(path_str).is_err() {
            return ERR_IO;
        }

        0
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_config_network_remove(
    path: *const c_char,
    network_url: *const c_char,
) -> c_int {
    if path.is_null() || network_url.is_null() {
        return ERR_IO;
    }

    unsafe {
        let path_str = match CStr::from_ptr(path).to_str() {
            Ok(s) => s,
            Err(_) => return ERR_UTF8,
        };

        let network_url_str = match CStr::from_ptr(network_url).to_str() {
            Ok(s) => s,
            Err(_) => return ERR_UTF8,
        };

        // Load the current config
        let mut agent_config = match AgentConfig::load(path_str) {
            Ok(config) => config,
            Err(_) => return ERR_IO,
        };

        // Parse the network URL
        let url = match Url::parse(network_url_str) {
            Ok(u) => u,
            Err(_) => return ERR_INVALID_URL,
        };

        // Check if network exists
        if !agent_config.networks.contains_key(&url) {
            return ERR_NETWORK_NOT_FOUND;
        }

        // Remove network from config
        agent_config.networks.remove(&url);

        // Save config to file
        if agent_config.save(path_str).is_err() {
            return ERR_IO;
        }

        0
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_config_networks(
    path: *const c_char,
    networks: *mut *mut NetworkInfo,
    count: *mut c_int,
) -> c_int {
    if path.is_null() || networks.is_null() || count.is_null() {
        return ERR_IO;
    }

    unsafe {
        let path_str = match CStr::from_ptr(path).to_str() {
            Ok(s) => s,
            Err(_) => return ERR_UTF8,
        };

        let agent_config = match AgentConfig::load(path_str) {
            Ok(cfg) => cfg,
            Err(_) => return ERR_IO,
        };

        // Build vector of NetworkInfo structs
        let mut vec: Vec<NetworkInfo> = Vec::with_capacity(agent_config.networks.len());

        for (url, net) in &agent_config.networks {
            let url_str = url.as_str();

            // Create CString
            let cs = match CString::new(url_str) {
                Ok(s) => s,
                Err(_) => continue, // Skip on error
            };

            // Transfer ownership to NetworkInfo
            let url_ptr = cs.into_raw();

            let disabled_val = if net.disabled { 1 } else { 0 };
            vec.push(NetworkInfo {
                url: url_ptr,
                disabled: disabled_val,
            });
        }

        // Empty case: return NULL + 0
        if vec.is_empty() {
            *networks = std::ptr::null_mut();
            *count = 0;
            return 0;
        }

        // Convert to contiguous block and return
        let boxed: Box<[NetworkInfo]> = vec.into_boxed_slice();
        let len = boxed.len();
        let ptr = Box::into_raw(boxed) as *mut NetworkInfo;

        *networks = ptr;
        *count = len as c_int;

        0
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_network_url(
    networks: *const NetworkInfo,
    index: c_int,
) -> *const c_char {
    if networks.is_null() || index < 0 {
        return std::ptr::null();
    }

    unsafe {
        let network_info = networks.offset(index as isize);
        (*network_info).url
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_network_disabled(
    networks: *const NetworkInfo,
    index: c_int,
) -> c_int {
    if networks.is_null() || index < 0 {
        return -1; // Error indicator for null pointer or invalid index
    }

    unsafe {
        let network_info = networks.offset(index as isize);
        (*network_info).disabled
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_config_networks_free(networks: *mut NetworkInfo, count: c_int) {
    if networks.is_null() || count <= 0 {
        return;
    }

    unsafe {
        let networks_vec = Box::from_raw(std::slice::from_raw_parts_mut(networks, count as usize));
        drop(networks_vec);
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_config_network_enable(
    path: *const c_char,
    network_url: *const c_char,
) -> c_int {
    if path.is_null() || network_url.is_null() {
        return ERR_IO;
    }

    unsafe {
        let path_str = match CStr::from_ptr(path).to_str() {
            Ok(s) => s,
            Err(_) => return ERR_UTF8,
        };

        let network_url_str = match CStr::from_ptr(network_url).to_str() {
            Ok(s) => s,
            Err(_) => return ERR_UTF8,
        };

        let mut agent_config = match AgentConfig::load_or_generate(path_str) {
            Ok(config) => config,
            Err(_) => return ERR_IO,
        };

        let url = match url::Url::parse(network_url_str) {
            Ok(u) => u,
            Err(_) => return ERR_INVALID_URL,
        };

        if let Some(network) = agent_config.networks.get_mut(&url) {
            if !network.disabled {
                return ERR_NETWORK_ALREADY_ENABLED;
            }
            network.disabled = false;
        } else {
            return ERR_NETWORK_NOT_FOUND;
        }

        match agent_config.save(path_str) {
            Ok(_) => 0,
            Err(_) => ERR_IO,
        }
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_config_network_disable(
    path: *const c_char,
    network_url: *const c_char,
) -> c_int {
    if path.is_null() || network_url.is_null() {
        return ERR_IO;
    }

    unsafe {
        trace!("Extracting path string from pointer");
        let path_str = match CStr::from_ptr(path).to_str() {
            Ok(s) => s,
            Err(_) => {
                trace!("Failed to convert path to string, returning ERR_UTF8");
                return ERR_UTF8;
            }
        };

        trace!("Extracting network URL string from pointer");
        let network_url_str = match CStr::from_ptr(network_url).to_str() {
            Ok(s) => s,
            Err(_) => {
                trace!("Failed to convert network_url to string, returning ERR_UTF8");
                return ERR_UTF8;
            }
        };

        let mut agent_config = match AgentConfig::load_or_generate(path_str) {
            Ok(config) => config,
            Err(_) => return ERR_IO,
        };

        let url = match url::Url::parse(network_url_str) {
            Ok(u) => u,
            Err(_) => return ERR_INVALID_URL,
        };

        if let Some(network) = agent_config.networks.get_mut(&url) {
            if network.disabled {
                return ERR_NETWORK_ALREADY_DISABLED;
            }
            network.disabled = true;
        } else {
            return ERR_NETWORK_NOT_FOUND;
        }

        match agent_config.save(path_str) {
            Ok(_) => 0,
            Err(_) => ERR_IO,
        }
    }
}

//
// Agent
//

#[repr(C)]
pub struct AgentPtr(*mut c_void);

impl From<Agent> for AgentPtr {
    fn from(agent: Agent) -> Self {
        Self(Box::into_raw(Box::new(agent)) as *mut c_void)
    }
}

impl From<&mut AgentPtr> for &Agent {
    fn from(agent: &mut AgentPtr) -> Self {
        unsafe { &*(agent.0 as *const Agent) }
    }
}

impl Drop for AgentPtr {
    fn drop(&mut self) {
        unsafe {
            let agent = Box::from_raw(self.0 as *mut Agent);
            drop(agent);
        }
    }
}

#[repr(C)]
pub struct NetworkChange {
    pub ips: *const c_char,    // Comma-separated IPs, NULL if not available
    pub routes: *const c_char, // Comma-separated routes, NULL if not available
    #[cfg(feature = "dns")]
    pub dns_server: *const c_char, // DNS server, NULL if not available
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_network_change_ips(change: *const NetworkChange) -> *const c_char {
    if change.is_null() {
        return std::ptr::null();
    }

    unsafe { (*change).ips }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_network_change_routes(
    change: *const NetworkChange,
) -> *const c_char {
    if change.is_null() {
        return std::ptr::null();
    }

    unsafe { (*change).routes }
}

#[cfg(feature = "dns")]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_network_change_dns_server(
    change: *const NetworkChange,
) -> *const c_char {
    if change.is_null() {
        return std::ptr::null();
    }

    unsafe { (*change).dns_server }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[allow(unused_variables)]
#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_start(
    runtime: &mut RuntimePtr,
    config: &mut AgentConfigPtr,
    tun_device: *mut TunDevicePtr,
    networks_change_callback: extern "C" fn(change: *const NetworkChange),
    dns_servers: *const c_char,
    agent: *mut *mut AgentPtr,
) -> c_int {
    if agent.is_null() {
        return ERR_IO;
    }

    unsafe {
        // Extract the Runtime from the pointer
        let runtime: &Runtime = runtime.into();

        // Extract the AgentConfig from the pointer
        let agent_config: &AgentConfig = config.into();

        // Extract the TunDevice from the pointer (optional)
        #[cfg(any(target_os = "ios", target_os = "tvos", target_os = "android"))]
        let tun_device: Option<Arc<TunDevice>> = if tun_device.is_null() {
            None
        } else {
            let tun_device_ptr = &mut *tun_device;
            let tun_device_ref: &Arc<TunDevice> = tun_device_ptr.into();
            Some(tun_device_ref.clone())
        };

        match runtime.block_on(Agent::start(
            agent_config.clone(),
            "".to_string(),
            "".to_string(),
            PlatformDependent {
                #[cfg(any(target_os = "ios", target_os = "tvos", target_os = "android"))]
                tun_device: tun_device,
                #[cfg(any(target_os = "ios", target_os = "tvos", target_os = "android"))]
                network_listener: Box::new(move |change: crate::agent::NetworkChange| {
                    // Convert Rust NetworkChange to C NetworkChange
                    // Use CString to ensure proper null-termination and lifetime
                    let ips_str = change
                        .ips
                        .map(|ips| {
                            let ips_string = ips
                                .iter()
                                .map(|ip| ip.to_string())
                                .collect::<Vec<String>>()
                                .join(",");

                            CString::new(ips_string).unwrap_or_default()
                        })
                        .unwrap_or_default();

                    // Convert routes to comma-separated string
                    let routes_str = change
                        .routes
                        .map(|routes| {
                            let routes_string = routes
                                .iter()
                                .map(|route| route.to_string())
                                .collect::<Vec<String>>()
                                .join(",");

                            CString::new(routes_string).unwrap_or_default()
                        })
                        .unwrap_or_default();

                    // Convert DNS server to string
                    #[cfg(feature = "dns")]
                    let dns_server_str = if let Some(dns_server) = change.dns_server {
                        CString::new(dns_server.to_string()).unwrap_or_default()
                    } else {
                        CString::default()
                    };

                    let c_change = NetworkChange {
                        ips: ips_str.as_ptr(),
                        routes: routes_str.as_ptr(),
                        #[cfg(feature = "dns")]
                        dns_server: dns_server_str.as_ptr(),
                    };

                    trace!(
                        "Calling network_change_callback with NetworkChange: ips='{}', routes='{}'",
                        ips_str.to_string_lossy(),
                        routes_str.to_string_lossy()
                    );
                    let _ = &(networks_change_callback)(&c_change);
                }),
                #[cfg(target_os = "android")]
                dns_servers: {
                    let dns_servers = if dns_servers.is_null() {
                        ""
                    } else {
                        match CStr::from_ptr(dns_servers).to_str() {
                            Ok(s) => s,
                            Err(_) => "",
                        }
                    };
                    dns_servers
                        .split(',')
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .filter_map(|s| s.parse::<std::net::Ipv4Addr>().ok())
                        .collect()
                },
            },
        )) {
            Ok(my_agent) => {
                *agent = Box::into_raw(Box::new(my_agent.into()));
                0
            }
            Err(e) => e.into(),
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_shutdown(runtime: &mut RuntimePtr, agent: &mut AgentPtr) -> c_int {
    let runtime: &Runtime = runtime.into();
    let agent: &Agent = agent.into();

    runtime.block_on(agent.shutdown());
    0
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_free(agent: *mut AgentPtr) {
    if !agent.is_null() {
        unsafe {
            let agent_ptr = Box::from_raw(agent);
            drop(agent_ptr);
        }
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_tun_device_create(
    runtime: &mut RuntimePtr,
    fd: c_int,
    tun_device: *mut *mut TunDevicePtr,
) -> c_int {
    if tun_device.is_null() {
        return ERR_IO;
    }

    unsafe {
        let runtime: &Runtime = runtime.into();

        match runtime.block_on(async { TunDevice::from_fd(fd) }) {
            Ok(device) => {
                let tun_device_ptr = TunDevicePtr::from(Arc::new(device));
                *tun_device = Box::into_raw(Box::new(tun_device_ptr));
                0
            }
            Err(_) => {
                trace!("Failed to create TUN device from file descriptor {}", fd);
                ERR_IO
            }
        }
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_tun_device_free(tun_device: *mut TunDevicePtr) {
    if !tun_device.is_null() {
        unsafe {
            let tun_device_ptr = Box::from_raw(tun_device);
            drop(tun_device_ptr);
        }
    }
}

#[cfg(target_os = "ios")]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_cancel_udp_bindings(agent: &mut AgentPtr) -> c_int {
    trace!("FFI: Starting UDP bindings cancellation");

    let agent: &Agent = agent.into();

    // Cancel all UDP bindings
    trace!("FFI: Canceling all UDP bindings");
    let udp_bindings = agent.inner.node.inner.udp_bindings.load();
    trace!("FFI: Found {} UDP bindings", udp_bindings.len());

    for udp_binding in udp_bindings.iter() {
        trace!("FFI: Canceling UDP binding at {}", udp_binding.local_addr);
        udp_binding.cancel_binding();
    }

    trace!("FFI: All UDP bindings canceled");
    trace!("FFI: Operation successful");
    0
}

#[cfg(any(target_os = "android"))]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_update_tun_device(
    runtime: &mut RuntimePtr,
    agent: &mut AgentPtr,
    new_tun_device: &mut TunDevicePtr,
) -> c_int {
    trace!("FFI: Starting TUN device update operation");

    let runtime: &Runtime = runtime.into();
    let agent: &Agent = agent.into();
    let new_tun_device: &Arc<TunDevice> = new_tun_device.into();

    trace!("FFI: Converted runtime, agent, and tun_device pointers");

    // Get the inner agent to access the netif
    let inner = agent.inner.clone();
    trace!("FFI: Retrieved agent inner");

    // Lock networks and update TUN device
    trace!("FFI: Acquiring networks lock and updating TUN device");
    runtime.block_on(async {
        let networks_guard = inner.networks.lock().await;
        trace!("FFI: Networks lock acquired");

        trace!("FFI: Calling update_tun_device");
        inner
            .netif
            .update_tun_device(inner.clone(), new_tun_device.clone());
        trace!("FFI: update_tun_device completed");

        drop(networks_guard); // Release the lock
        trace!("FFI: Networks lock released");
    });
    trace!("FFI: Operation successful");
    0
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn netsody_agent_status(
    runtime: &mut RuntimePtr,
    agent: &mut AgentPtr,
) -> *mut c_char {
    trace!("FFI: Starting agent status request");

    let runtime: &Runtime = runtime.into();
    let agent: &Agent = agent.into();

    trace!("FFI: Converted runtime and agent pointers");

    // Generate status
    let status_result: Result<String, String> = runtime.block_on(async {
        let status = crate::rest_api::status::Status::from_agent(agent).await;
        trace!("Status generated");

        // Convert to string without secrets
        let status_string = status.to_string_with_secrets(false);
        trace!("Status converted to string without secrets");
        Ok(status_string)
    });

    match status_result {
        Ok(status_string) => {
            trace!("FFI: Status request completed successfully");
            let c_string = CString::new(status_string).unwrap_or_else(|_| {
                CString::new("Status generation failed").expect("Failed to create error string")
            });
            c_string.into_raw()
        }
        Err(error_msg) => {
            trace!("FFI: Status request failed: {}", error_msg);
            let error_string = format!("Error: {}", error_msg);
            let c_string = CString::new(error_string).unwrap_or_else(|_| {
                CString::new("Unknown error occurred").expect("Failed to create error string")
            });
            c_string.into_raw()
        }
    }
}
