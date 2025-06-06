use crate::rest_api::AUTH_FILE_DEFAULT;
use axum::extract::FromRequestParts;
use axum::response::{IntoResponse, Response};
use axum::{Json, RequestPartsExt};
use axum_extra::TypedHeader;
use drasyl::crypto::random_bytes;
use drasyl::util;
use drasyl::util::bytes_to_hex;
use headers::Authorization;
use headers::authorization::Bearer;
use http::StatusCode;
use http::request::Parts;
use serde_json::json;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use tracing::{error, info, trace};

/// Load an existing REST API token from file.
///
/// # Returns
/// The API token as a string, or an error if the file doesn't exist or can't be read
pub fn load_auth_token(token_file: &String) -> Result<String, io::Error> {
    let token_path = Path::new(token_file);

    // Try to read the main token file first
    let main_result = if token_path.exists() {
        fs::read_to_string(token_path)
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Token file {:?} does not exist", token_path),
        ))
    };

    // On NotFound or PermissionDenied, try the fallback path
    if let Err(e) = &main_result {
        if e.kind() == io::ErrorKind::NotFound || e.kind() == io::ErrorKind::PermissionDenied {
            if let Some(home_dir) = env::home_dir() {
                let fallback_path = home_dir.join(".drasyl").join("auth.token");
                println!("{}", fallback_path.display());
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
                }
            }
        }
    }

    // If main file was read successfully or no fallback was possible
    match main_result {
        Ok(token) => {
            let token = token.trim().to_string();
            trace!("Loaded REST API token from {}", token_file);
            Ok(token)
        }
        Err(e) => Err(e),
    }
}

/// Create a new cryptographically secure REST API token and save it to file.
///
/// # Returns
/// The newly generated API token as a string, or an error if file operations fail
pub(crate) fn create_auth_token(
    token_file: &String,
    token_len: usize,
) -> Result<String, io::Error> {
    let token_path = Path::new(token_file);

    // generate random bytes and convert to hex
    let mut buf = vec![0u8; token_len];
    random_bytes(&mut buf);
    let token = bytes_to_hex(&buf);

    // write token to file with restrictive permissions
    match fs::File::create(token_path) {
        Ok(mut file) => {
            // set restrictive file permissions (Unix only)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = file.metadata()?.permissions();
                perms.set_mode(0o600); // read/write for owner only
                fs::set_permissions(token_path, perms)?;
            }

            file.write_all(token.as_bytes())?;
            file.flush()?;
            info!("Created new REST API token and saved to {}", token_file);
        }
        Err(e) => {
            error!("Failed to write REST API token to {}: {}", token_file, e);
            return Err(e);
        }
    }

    Ok(token)
}

impl<S> FromRequestParts<S> for AuthToken
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // load existing API token
        let token_file = util::get_env("AUTH_FILE", AUTH_FILE_DEFAULT.to_string());
        let expected_token = load_auth_token(&token_file).map_err(|e| {
            error!("Failed to load API token: {}", e);
            AuthError::TokenFileNotFound
        })?;

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
