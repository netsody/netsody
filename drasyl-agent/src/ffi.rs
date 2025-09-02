use crate::agent;
use crate::agent::{Agent, AgentConfig, Error, NetworkListener};
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
pub extern "C" fn drasyl_agent_version() -> *const c_char {
    VERSION_CSTR
        .get_or_init(|| {
            let info = VersionInfo::new();
            CString::new(format!("{} ({})", info.version, info.full_commit()))
                .expect("no interior NULs")
        })
        .as_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_agent_init_logging() -> c_int {
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

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_agent_runtime() -> *mut RuntimePtr {
    match Runtime::new() {
        Ok(runtime) => {
            let runtime_ptr = RuntimePtr::from(runtime);
            Box::into_raw(Box::new(runtime_ptr))
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_agent_runtime_free(runtime: *mut RuntimePtr) {
    if !runtime.is_null() {
        unsafe {
            trace!("Freeing RuntimePtr");
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
    pub url: *const c_char, // URL as C-String
    pub disabled: c_int,    // Disabled Status
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
pub extern "C" fn drasyl_agent_config_load_or_generate(
    path: *const c_char,
    run: *mut *mut AgentConfigPtr,
) -> c_int {
    if path.is_null() || run.is_null() {
        return ERR_IO;
    }

    unsafe {
        let path_str = match CStr::from_ptr(path).to_str() {
            Ok(s) => s,
            Err(_) => return ERR_UTF8,
        };

        match AgentConfig::load_or_generate(path_str) {
            Ok(my_config) => {
                *run = Box::into_raw(Box::new(my_config.into()));
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
pub extern "C" fn drasyl_agent_config_id_pk(config: &mut AgentConfigPtr, pk: *mut c_char) -> c_int {
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
pub extern "C" fn drasyl_agent_config_free(config: *mut AgentConfigPtr) {
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
pub extern "C" fn drasyl_agent_config_network_add(
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
            state: None,
            tun_state: None,
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
pub extern "C" fn drasyl_agent_config_network_remove(
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
pub extern "C" fn drasyl_agent_config_networks(
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

        // Vector füllen
        let mut vec: Vec<NetworkInfo> = Vec::with_capacity(agent_config.networks.len());
        let mut cstrings: Vec<std::ffi::CString> = Vec::new(); // Hält die Strings am Leben

        for (url, net) in &agent_config.networks {
            let url_str = url.as_str();

            // CString erstellen
            let cs = match std::ffi::CString::new(url_str) {
                Ok(s) => s,
                Err(_) => continue, // Bei Fehler überspringen
            };

            let url_ptr = cs.as_ptr();
            cstrings.push(cs); // CString am Leben halten

            let disabled_val = if net.disabled { 1 } else { 0 };
            vec.push(NetworkInfo {
                url: url_ptr,
                disabled: disabled_val,
            });
        }

        // Leerer Fall: NULL + 0 zurückgeben
        if vec.is_empty() {
            *networks = std::ptr::null_mut();
            *count = 0;
            return 0;
        }

        // In zusammenhängenden Block konvertieren und übergeben
        let boxed: Box<[NetworkInfo]> = vec.into_boxed_slice();
        let len = boxed.len();
        let ptr = Box::into_raw(boxed) as *mut NetworkInfo;

        *networks = ptr;
        *count = len as c_int;

        // CStrings am Leben halten (verhindert Memory-Leak, aber Pointer bleiben gültig)
        std::mem::forget(cstrings);

        0
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_agent_config_networks_free(networks: *mut NetworkInfo, count: c_int) {
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
pub extern "C" fn drasyl_agent_config_network_enable(
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
pub extern "C" fn drasyl_agent_config_network_disable(
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
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_agent_start(
    runtime: &mut RuntimePtr,
    config: &mut AgentConfigPtr,
    tun_device: &mut TunDevicePtr,
    networks_change_callback: Option<extern "C" fn(change: *const NetworkChange)>,
    run: *mut *mut AgentPtr,
) -> c_int {
    if run.is_null() {
        return ERR_IO;
    }

    unsafe {
        // Extract the Runtime from the pointer
        let runtime: &Runtime = runtime.into();

        // Extract the AgentConfig from the pointer
        let agent_config: &AgentConfig = config.into();

        // Extract the TunDevice from the pointer
        let tun_device: &Arc<TunDevice> = tun_device.into();

        let network_listener: Option<NetworkListener> = if let Some(cb) = networks_change_callback {
            Some(Box::new(move |change: agent::NetworkChange| {
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

                        std::ffi::CString::new(ips_string).unwrap_or_default()
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

                        std::ffi::CString::new(routes_string).unwrap_or_default()
                    })
                    .unwrap_or_default();

                let c_change = NetworkChange {
                    ips: ips_str.as_ptr(),
                    routes: routes_str.as_ptr(),
                };

                trace!(
                    "Calling network_change_callback with NetworkChange: ips='{}', routes='{}'",
                    ips_str.to_string_lossy(),
                    routes_str.to_string_lossy()
                );
                cb(&c_change);
            }))
        } else {
            None
        };

        match runtime.block_on(Agent::start(
            agent_config.clone(),
            "".to_string(),
            "".to_string(),
            Some(tun_device.clone()),
            network_listener,
        )) {
            Ok(agent) => {
                *run = Box::into_raw(Box::new(agent.into()));
                0
            }
            Err(e) => e.into(),
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_agent_shutdown(runtime: &mut RuntimePtr, agent: &mut AgentPtr) -> c_int {
    let runtime: &Runtime = runtime.into();
    let agent: &Agent = agent.into();

    runtime.block_on(agent.shutdown());
    0
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_agent_free(agent: *mut AgentPtr) {
    if !agent.is_null() {
        unsafe {
            let agent_ptr = Box::from_raw(agent);
            drop(agent_ptr);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn drasyl_agent_tun_device_create(
    runtime: &mut RuntimePtr,
    fd: c_int,
) -> *mut TunDevicePtr {
    let runtime: &Runtime = runtime.into();

    match runtime.block_on(async { unsafe { TunDevice::from_fd(fd) } }) {
        Ok(tun_device) => {
            let tun_device_ptr = TunDevicePtr::from(Arc::new(tun_device));
            Box::into_raw(Box::new(tun_device_ptr))
        }
        Err(_) => {
            trace!("Failed to create TUN device from file descriptor {}", fd);
            std::ptr::null_mut()
        }
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn drasyl_agent_tun_device_free(tun_device: *mut TunDevicePtr) {
    if !tun_device.is_null() {
        unsafe {
            let tun_device_ptr = Box::from_raw(tun_device);
            drop(tun_device_ptr);
        }
    }
}
