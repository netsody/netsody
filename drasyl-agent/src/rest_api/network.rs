use super::client::RestApiClient;
use crate::agent::Agent;
use crate::rest_api::{AuthToken, RestApiServer, auth, error};
use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::trace;

#[derive(Serialize, Deserialize, Debug)]
pub struct AddNetworkRequest {
    pub config_url: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RemoveNetworkRequest {
    pub config_url: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DisableNetworkRequest {
    pub config_url: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EnableNetworkRequest {
    pub config_url: String,
}

#[derive(Serialize, Deserialize)]
pub struct NetworkResponse {
    pub success: bool,
    pub message: String,
}

impl RestApiServer {
    pub(crate) async fn add_network(
        State(agent): State<Arc<Agent>>,
        _: AuthToken,
        Json(request): Json<AddNetworkRequest>,
    ) -> Json<NetworkResponse> {
        trace!("Add network request received: {:?}", request);
        match Self::add_network_internal(agent, &request.config_url).await {
            Ok(_) => Json(NetworkResponse {
                success: true,
                message: format!("Network '{}' added successfully", request.config_url),
            }),
            Err(e) => Json(NetworkResponse {
                success: false,
                message: format!("Failed to add network '{}': {}", request.config_url, e),
            }),
        }
    }

    pub(crate) async fn remove_network(
        State(agent): State<Arc<Agent>>,
        _: auth::AuthToken,
        Json(request): Json<RemoveNetworkRequest>,
    ) -> Json<NetworkResponse> {
        trace!("Remove network request received: {:?}", request);
        match Self::remove_network_internal(agent, &request.config_url).await {
            Ok(_) => Json(NetworkResponse {
                success: true,
                message: format!("Network '{}' removed successfully", request.config_url),
            }),
            Err(e) => Json(NetworkResponse {
                success: false,
                message: format!("Failed to remove network '{}': {}", request.config_url, e),
            }),
        }
    }

    async fn add_network_internal(agent: Arc<Agent>, config_url: &str) -> Result<(), error::Error> {
        agent
            .add_network(config_url)
            .await
            .map_err(|e| error::Error::NetworkConfigFetchFailed {
                reason: e.to_string(),
            })
    }

    async fn remove_network_internal(
        agent: Arc<Agent>,
        config_url: &str,
    ) -> Result<(), error::Error> {
        agent
            .remove_network(config_url)
            .await
            .map_err(|e| error::Error::NetworkConfigFetchFailed {
                reason: e.to_string(),
            })
    }

    pub(crate) async fn disable_network(
        State(agent): State<Arc<Agent>>,
        _: AuthToken,
        Json(request): Json<DisableNetworkRequest>,
    ) -> Json<NetworkResponse> {
        trace!("Disable network request received: {:?}", request);
        match Self::disable_network_internal(agent, &request.config_url).await {
            Ok(_) => Json(NetworkResponse {
                success: true,
                message: format!("Network '{}' disabled successfully", request.config_url),
            }),
            Err(e) => Json(NetworkResponse {
                success: false,
                message: format!("Failed to disable network '{}': {}", request.config_url, e),
            }),
        }
    }

    pub(crate) async fn enable_network(
        State(agent): State<Arc<Agent>>,
        _: AuthToken,
        Json(request): Json<EnableNetworkRequest>,
    ) -> Json<NetworkResponse> {
        trace!("Enable network request received: {:?}", request);
        match Self::enable_network_internal(agent, &request.config_url).await {
            Ok(_) => Json(NetworkResponse {
                success: true,
                message: format!("Network '{}' enabled successfully", request.config_url),
            }),
            Err(e) => Json(NetworkResponse {
                success: false,
                message: format!("Failed to enable network '{}': {}", request.config_url, e),
            }),
        }
    }

    async fn disable_network_internal(
        agent: Arc<Agent>,
        config_url: &str,
    ) -> Result<(), error::Error> {
        agent.disable_network(config_url).await.map_err(|e| {
            error::Error::NetworkConfigFetchFailed {
                reason: e.to_string(),
            }
        })
    }

    async fn enable_network_internal(
        agent: Arc<Agent>,
        config_url: &str,
    ) -> Result<(), error::Error> {
        agent
            .enable_network(config_url)
            .await
            .map_err(|e| error::Error::NetworkConfigFetchFailed {
                reason: e.to_string(),
            })
    }
}

impl RestApiClient {
    pub async fn add_network(&self, config_url: &str) -> Result<NetworkResponse, error::Error> {
        let request = AddNetworkRequest {
            config_url: config_url.to_string(),
        };
        self.post("/network/add", request).await
    }

    pub async fn remove_network(&self, config_url: &str) -> Result<NetworkResponse, error::Error> {
        let request = RemoveNetworkRequest {
            config_url: config_url.to_string(),
        };
        self.post("/network/remove", request).await
    }

    pub async fn disable_network(&self, config_url: &str) -> Result<NetworkResponse, error::Error> {
        let request = DisableNetworkRequest {
            config_url: config_url.to_string(),
        };
        self.post("/network/disable", request).await
    }

    pub async fn enable_network(&self, config_url: &str) -> Result<NetworkResponse, error::Error> {
        let request = EnableNetworkRequest {
            config_url: config_url.to_string(),
        };
        self.post("/network/enable", request).await
    }
}
