use crate::agent::AgentInner;
use crate::agent::router::AgentRouterInterface;
use crate::network::Network;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::MutexGuard;
use tracing::trace;
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
        trace!(
            "We're running on a mobile platform where the network listener handles route updates. Therefore, we just assume everything is fine and hope for the best! 🤞"
        );

        if let Some(network) = networks.get_mut(config_url) {
            network.current_state.routes = network.desired_state.routes.clone();
        }
    }
}
