pub mod auth;
mod error;
mod status;

pub use auth::*;
pub use status::*;

use crate::node::SdnNode;
use axum::Router;
use axum::routing::get;
use drasyl::util;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, trace};

pub(crate) const API_LISTEN_DEFAULT: SocketAddrV4 =
    SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 22527);
pub const AUTH_FILE_DEFAULT: &str = "auth.token";
pub(crate) const API_TOKEN_LEN_DEFAULT: usize = 24;

pub struct RestApi {
    node: Arc<SdnNode>,
}

impl RestApi {
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
                match auth::create_auth_token(&token_file, token_len) {
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
        let listener = TcpListener::bind(listen).await?;
        axum::serve(listener, api).await?;

        Ok(())
    }
}
