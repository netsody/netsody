#[cfg(target_os = "macos")]
mod macos;

use crate::agent::AgentInner;
use crate::network::Network;
use cfg_if::cfg_if;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::MutexGuard;
use tun_rs::AsyncDevice;
use url::Url;

pub trait AgentDnsInterface {
    async fn apply_desired_state(
        &self,
        _inner: Arc<AgentInner>,
        config_url: &Url,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    );

    #[allow(dead_code)]
    fn server_ip(&self) -> Option<Ipv4Addr> {
        None
    }

    #[allow(unused_variables)]
    fn is_server_ip(&self, ip: Ipv4Addr) -> bool {
        false
    }

    #[allow(unused_variables)]
    async fn on_packet(
        &self,
        message_bytes: &[u8],
        src: Ipv4Addr,
        src_port: u16,
        dst: Ipv4Addr,
        dst_port: u16,
        dev: Arc<AsyncDevice>,
    ) -> bool {
        // do nothing
        false
    }
}

cfg_if! {
    if #[cfg(any(target_os = "macos", target_os = "ios", target_os = "android"))] {
        mod embedded;
        pub use embedded::AgentDns;
    }
    else if #[cfg(target_os = "linux")] {
        mod hosts_file;
        pub use hosts_file::AgentDns;
    }
    else {
        // unsupported platform
        use crate::agent::PlatformDependent;
        use crate::network::AppliedStatus;
        use tracing::warn;


        pub struct AgentDns {}

        impl AgentDns {
            pub(crate) fn new(_platform_dependent: Arc<PlatformDependent>) -> Self {
                Self {}
            }
        }

        impl AgentDnsInterface for AgentDns {
            async fn apply_desired_state(&self, _inner: Arc<AgentInner>, _config_url: &Url, networks: &mut MutexGuard<'_, HashMap<Url, Network>>) {
                warn!("DNS is not supported on this platform. We can not update all networks.");
                for (_, network) in networks.iter_mut() {
                    network.current_state.hostnames =
                        AppliedStatus::error("DNS not supported on this platform".to_string());
                }
            }
        }
    }
}
