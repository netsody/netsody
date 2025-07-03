use super::client::RestApiClient;
use crate::node::SdnNode;
use crate::rest_api::{AuthToken, RestApiServer, auth, error};
use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
pub struct AddNetworkRequest {
    pub config_url: String,
}

#[derive(Serialize, Deserialize)]
pub struct RemoveNetworkRequest {
    pub config_url: String,
}

#[derive(Serialize, Deserialize)]
pub struct NetworkResponse {
    pub success: bool,
    pub message: String,
}

impl RestApiServer {
    pub(crate) async fn add_network(
        State(sdn_node): State<Arc<SdnNode>>,
        _: AuthToken,
        Json(request): Json<AddNetworkRequest>,
    ) -> Json<NetworkResponse> {
        match Self::add_network_internal(sdn_node, &request.config_url).await {
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
        State(sdn_node): State<Arc<SdnNode>>,
        _: auth::AuthToken,
        Json(request): Json<RemoveNetworkRequest>,
    ) -> Json<NetworkResponse> {
        match Self::remove_network_internal(sdn_node, &request.config_url).await {
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

    async fn add_network_internal(
        sdn_node: Arc<SdnNode>,
        config_url: &str,
    ) -> Result<(), error::Error> {
        sdn_node
            .add_network(config_url)
            .await
            .map_err(|e| error::Error::NetworkConfigFetchFailed {
                reason: e.to_string(),
            })
    }

    async fn remove_network_internal(
        sdn_node: Arc<SdnNode>,
        config_url: &str,
    ) -> Result<(), error::Error> {
        sdn_node.remove_network(config_url).await.map_err(|e| {
            error::Error::NetworkConfigFetchFailed {
                reason: e.to_string(),
            }
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
}
