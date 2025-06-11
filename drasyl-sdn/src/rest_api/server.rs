use crate::node::SdnNode;
use crate::rest_api;
use crate::rest_api::{
    API_LISTEN_DEFAULT, API_TOKEN_LEN_DEFAULT, AUTH_FILE_DEFAULT, error, load_auth_token,
};
use axum::Router;
use axum::routing::get;
use drasyl::util;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, trace};

pub struct RestApiServer {
    node: Arc<SdnNode>,
}

impl RestApiServer {
    pub fn new(node: Arc<SdnNode>) -> Self {
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

        let token_file = util::get_env("AUTH_FILE", AUTH_FILE_DEFAULT.to_string());
        let token_len = util::get_env("API_TOKEN_LEN", API_TOKEN_LEN_DEFAULT);

        // ensure auth token exists, create if necessary
        match load_auth_token(&token_file) {
            Ok(_) => {
                trace!("Auth token {} loaded successfully", token_file);
            }
            Err(_) => {
                trace!("No auth token {} found, creating new one...", token_file);
                match rest_api::create_auth_token(&token_file, token_len) {
                    Ok(_) => {
                        trace!("Auth token {} created successfully", token_file);
                    }
                    Err(e) => {
                        error!("Failed to create auth token {}: {}", token_file, e);
                        return Err(error::Error::TokenGenerationFailed {
                            reason: e.to_string(),
                        });
                    }
                }
            }
        }

        let api = Router::new()
            .route("/status", get(Self::status))
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
