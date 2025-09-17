use crate::network::Network;
use cfg_if::cfg_if;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::MutexGuard;
use tun_rs::AsyncDevice;
use url::Url;

pub trait AgentDnsInterface {
    fn server_ip(&self) -> Option<Ipv4Addr> {
        None
    }

    #[allow(unused_variables)]
    fn is_server_ip(&self, ip: Ipv4Addr) -> bool {
        false
    }

    async fn shutdown(&self) {
        // do nothing
    }

    #[allow(unused_variables)]
    async fn update_network_hostnames(&self, networks: &mut MutexGuard<'_, HashMap<Url, Network>>) {
        // do nothing
    }

    #[allow(unused_variables)]
    async fn update_all_hostnames(&self, networks: &mut MutexGuard<'_, HashMap<Url, Network>>) {
        // do nothing
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

        pub struct AgentDns {}

        impl AgentDns {
            pub(crate) fn new(_platform_dependent: Arc<PlatformDependent>) -> Self {
                Self {}
            }
        }

        impl AgentDnsInterface for AgentDns {}
    }
}
