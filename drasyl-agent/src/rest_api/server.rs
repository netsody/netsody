use crate::agent::Agent;
use crate::rest_api;
use crate::rest_api::{API_LISTEN_DEFAULT, API_TOKEN_LEN_DEFAULT, error, load_auth_token};
use axum::Router;
use axum::routing::{get, post};
use p2p::util;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, trace};

pub struct RestApiServer {
    node: Arc<Agent>,
}

impl RestApiServer {
    pub fn new(node: Arc<Agent>) -> Self {
        Self { node }
    }

    pub async fn bind(&self) -> Result<(), error::Error> {
        let listen = util::get_env("API_LISTEN", API_LISTEN_DEFAULT.to_string());
        if listen.is_empty() {
            info!(
                "REST API server disabled: no listen address configured (DRASYL_API_LISTEN is empty)"
            );
            return Ok(());
        }

        let token_len = util::get_env("API_TOKEN_LEN", API_TOKEN_LEN_DEFAULT);

        // ensure auth token exists, create if necessary
        match load_auth_token(&self.node.inner.token_path) {
            Ok(_) => {
                trace!(
                    "Auth token {} loaded successfully",
                    self.node.inner.token_path
                );
            }
            Err(_) => {
                trace!(
                    "No auth token {} found, creating new one...",
                    self.node.inner.token_path
                );
                match rest_api::create_auth_token(&self.node.inner.token_path, token_len) {
                    Ok(_) => {
                        trace!(
                            "Auth token {} created successfully",
                            self.node.inner.token_path
                        );
                    }
                    Err(e) => {
                        error!(
                            "Failed to create auth token {}: {}",
                            self.node.inner.token_path, e
                        );
                        return Err(error::Error::TokenGenerationFailed {
                            reason: e.to_string(),
                        });
                    }
                }
            }
        }

        let api = Router::new()
            .route("/status", get(Self::status))
            .route("/network/add", post(Self::add_network))
            .route("/network/remove", post(Self::remove_network))
            .route("/network/disable", post(Self::disable_network))
            .route("/network/enable", post(Self::enable_network))
            .with_state(self.node.clone());
        let listener = TcpListener::bind(listen)
            .await
            .map_err(error::Error::Bind)?;
        axum::serve(listener, api)
            .await
            .map_err(error::Error::Serve)?;

        Ok(())
    }
}
