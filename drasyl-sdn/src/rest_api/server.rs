use crate::node::SdnNode;
use crate::rest_api::{API_LISTEN_DEFAULT, error};
use axum::Router;
use axum::routing::get;
use drasyl::util;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

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
