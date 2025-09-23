use crate::agent::AgentInner;
use crate::network::Network;
use cfg_if::cfg_if;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::MutexGuard;
use url::Url;

pub trait AgentRouterInterface {
    async fn apply_desired_state(
        &self,
        inner: Arc<AgentInner>,
        config_url: &Url,
        networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
    );
}

cfg_if! {
    if #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))] {
        mod desktop;
        pub use desktop::AgentRouter;
    }
    else if #[cfg(any(target_os = "ios", target_os = "tvos", target_os = "android"))] {
        mod mobile;
        pub use mobile::AgentRouter;
    }
    else {
        use tracing::warn;

        // unsupported platform
        pub struct AgentRouter {}

        impl AgentRouter {
            pub(crate) fn new() -> Self {
                Self {}
            }
        }

        impl AgentRouterInterface for AgentRouter {
            #[allow(unused_variables)]
            async fn apply_desired_state(
                &self,
                inner: Arc<AgentInner>,
                config_url: &Url,
                networks: &mut MutexGuard<'_, HashMap<Url, Network>>,
            ) {
                warn!("Routing is not supported on this platform. We can not update all networks.");
                for (_, network) in networks.iter_mut() {
                    network.current_state.routes =
                        AppliedStatus::error("Routing not supported on this platform".to_string());
                }
            }
        }
    }
}
