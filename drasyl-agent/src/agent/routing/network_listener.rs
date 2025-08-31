use crate::agent::routing::AgentRoutingInterface;
use crate::network::EffectiveRoutingList;
use std::sync::Arc;
use tracing::trace;
use tun_rs::AsyncDevice;

pub struct AgentRouting {}

impl AgentRouting {
    pub(crate) fn new() -> Self {
        Self {}
    }
}

impl AgentRoutingInterface for AgentRouting {
    #[allow(unused_variables)]
    async fn update_network(
        &self,
        current_routes: Option<EffectiveRoutingList>,
        desired_routes: Option<EffectiveRoutingList>,
        tun_device: Arc<AsyncDevice>,
    ) -> EffectiveRoutingList {
        #[allow(unused_mut)]
        let mut applied_routes = EffectiveRoutingList::default();
        trace!(
            "Routes change: current={:?}; desired={:?}",
            current_routes, desired_routes
        );

        trace!(
            "We're assuming the network listener handles route updates. Therefore, we just assume everything is fine and hope for the best! 🤞"
        );
        if let Some(desired_routes) = desired_routes.as_ref() {
            for (_, route) in desired_routes.iter() {
                applied_routes.add(route.as_applied_route());
            }
        }

        applied_routes
    }

    #[allow(unused_variables)]
    async fn remove_network(&self, routes: EffectiveRoutingList, tun_device: Arc<AsyncDevice>) {
        trace!(
            "We're assuming the network listener handles route deletions. Therefore, we just assume everything is fine and hope for the best! 🤞"
        );
    }
}
