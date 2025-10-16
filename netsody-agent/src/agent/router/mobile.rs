use crate::agent::AgentInner;
use crate::agent::router::AgentRouterInterface;
use crate::network::{AppliedStatus, Network};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::MutexGuard;
use tracing::{trace, warn};
use url::Url;

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
        if let Some(network) = networks.get_mut(config_url) {
            // routes
            trace!(
                "We're running on a mobile platform where the network listener handles route updates. Therefore, we just assume everything is fine and hope for the best! 🤞"
            );
            network.current_state.routes = network.desired_state.routes.clone();

            // forwarding
            if let Some(desired_list) = &network.desired_state.forwardings.applied {
                if !desired_list.is_empty() {
                    warn!(
                        "We're configured as a gateway. Forwarding is not supported on this platform."
                    );
                    network.current_state.forwardings = AppliedStatus::error("We're configured as a gateway. Forwarding is not supported on this platform.".to_string());
                } else {
                    network.current_state.forwardings = network.desired_state.forwardings.clone();
                }
            } else {
                network.current_state.forwardings = network.desired_state.forwardings.clone();
            }
        }
    }
}
