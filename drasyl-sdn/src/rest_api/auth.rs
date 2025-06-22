use crate::node::SdnNode;
use crate::node::SdnNodeConfig;
use axum::extract::FromRequestParts;
use axum::response::{IntoResponse, Response};
use axum::{Json, RequestPartsExt};
use axum_extra::TypedHeader;
use drasyl::util;
use headers::Authorization;
use headers::authorization::Bearer;
use http::StatusCode;
use http::request::Parts;
use serde_json::json;
use std::env;
use std::fs;
use std::io::{self};
use std::sync::Arc;
use tracing::trace;

/// Load an existing REST API token from file.
///
/// # Returns
/// The API token as a string, or an error if the file doesn't exist or can't be read
pub fn load_auth_token() -> Result<String, io::Error> {
    let config_path = util::get_env("CONFIG", "config.toml".to_string());

    // First, try to load from config.toml
    let config_result = SdnNodeConfig::load(&config_path);

    match config_result {
        Ok(config) => {
            trace!("Loaded REST API token from {}", config_path);
            Ok(config.auth_token)
        }
        Err(e) => {
            // Check if it's an IO error and only fallback on NotFound or PermissionDenied
            if let crate::node::Error::IOError(io_err) = e {
                if io_err.kind() != io::ErrorKind::NotFound
                    && io_err.kind() != io::ErrorKind::PermissionDenied
                {
                    return Err(io_err);
                }
                trace!(
                    "{} not found or permission denied, trying fallback path",
                    config_path
                );

                // Fallback: try the fallback path
                if let Some(home_dir) = env::home_dir() {
                    let fallback_path = home_dir.join(".drasyl").join("auth.token");
                    trace!("Trying fallback path: {}", fallback_path.display());
                    if fallback_path.exists() {
                        let fallback_path_clone = fallback_path.clone();
                        if let Ok(token) = fs::read_to_string(fallback_path) {
                            let token = token.trim().to_string();
                            trace!(
                                "Loaded REST API token from fallback path {}",
                                fallback_path_clone.display()
                            );
                            return Ok(token);
                        }
                    } else {
                        trace!(
                            "REST API token not found at fallback path {}",
                            fallback_path.display()
                        );
                    }
                }

                // If no fallback was possible, return an error
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "No auth token found in config.toml or fallback location",
                ))
            } else {
                // For non-IO errors, convert to io::Error
                Err(io::Error::other(e))
            }
        }
    }
}

impl FromRequestParts<Arc<SdnNode>> for AuthToken {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<SdnNode>,
    ) -> Result<Self, Self::Rejection> {
        let expected_token = state.inner.auth_token.clone();

        // extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::BearerTokenMissing)?;

        let auth_token = AuthToken(bearer.token().to_string());
        if auth_token.0 != expected_token {
            return Err(AuthError::TokenWrong);
        }

        Ok(auth_token)
    }
}

#[derive(Debug)]
pub struct AuthToken(String);

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::BearerTokenMissing => (StatusCode::UNAUTHORIZED, "bearer token missing"),
            AuthError::TokenWrong => (StatusCode::UNAUTHORIZED, "token wrong"),
            AuthError::TokenFileNotFound => {
                (StatusCode::INTERNAL_SERVER_ERROR, "token file not found")
            }
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

pub enum AuthError {
    BearerTokenMissing,
    TokenWrong,
    TokenFileNotFound,
}
