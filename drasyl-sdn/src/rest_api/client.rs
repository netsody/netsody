use crate::rest_api::error;
use crate::rest_api::error::Error;
use crate::rest_api::load_auth_token;
use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Empty, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::{Serialize, de::DeserializeOwned};

pub struct RestApiClient {
    token_path: String,
}

impl RestApiClient {
    pub fn new(token_path: String) -> Self {
        Self { token_path }
    }

    /// performs a GET request to the REST API
    pub(crate) async fn get<R>(&self, path: &str) -> Result<R, error::Error>
    where
        R: DeserializeOwned,
    {
        let client = Client::builder(TokioExecutor::new()).build_http();
        let auth_token = load_auth_token(&self.token_path).map_err(Error::AuthTokenReadFailed)?;

        let uri = format!("http://localhost:22527{path}")
            .parse::<hyper::Uri>()
            .map_err(|e| error::Error::StatusRequestFailed {
                reason: format!("failed to parse URI: {e}"),
            })?;

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header("Authorization", format!("Bearer {auth_token}"))
            .body(Empty::<Bytes>::new())
            .map_err(|e| error::Error::StatusRequestFailed {
                reason: format!("failed to build request: {e}"),
            })?;

        let response =
            client
                .request(req)
                .await
                .map_err(|e| error::Error::StatusRequestFailed {
                    reason: format!("HTTP request failed: {e}"),
                })?;
        let status_code = response.status();

        if status_code.is_success() {
            let body_bytes = response
                .into_body()
                .collect()
                .await
                .map_err(|e| error::Error::StatusRequestFailed {
                    reason: format!("failed to collect response body: {e}"),
                })?
                .to_bytes();
            let body_str = String::from_utf8(body_bytes.to_vec()).map_err(|e| {
                error::Error::StatusRequestFailed {
                    reason: format!("failed to parse response body as UTF-8: {e}"),
                }
            })?;
            let response_data: R =
                serde_json::from_str(&body_str).map_err(|e| error::Error::StatusRequestFailed {
                    reason: format!("failed to parse response as JSON: {e}"),
                })?;

            Ok(response_data)
        } else {
            Err(error::Error::StatusRequestFailed {
                reason: format!("server returned error status: {status_code}"),
            })
        }
    }

    /// performs a POST request to the REST API
    pub(crate) async fn post<T, R>(&self, path: &str, body: T) -> Result<R, error::Error>
    where
        T: Serialize,
        R: DeserializeOwned,
    {
        let client = Client::builder(TokioExecutor::new()).build_http();
        let auth_token = load_auth_token(&self.token_path).map_err(Error::AuthTokenReadFailed)?;

        let uri = format!("http://localhost:22527{path}")
            .parse::<hyper::Uri>()
            .map_err(|e| error::Error::StatusRequestFailed {
                reason: format!("failed to parse URI: {e}"),
            })?;

        let body_json =
            serde_json::to_string(&body).map_err(|e| error::Error::StatusRequestFailed {
                reason: format!("failed to serialize request: {e}"),
            })?;

        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("Authorization", format!("Bearer {auth_token}"))
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body_json)))
            .map_err(|e| error::Error::StatusRequestFailed {
                reason: format!("failed to build request: {e}"),
            })?;

        let response =
            client
                .request(req)
                .await
                .map_err(|e| error::Error::StatusRequestFailed {
                    reason: format!("HTTP request failed: {e}"),
                })?;
        let status_code = response.status();

        if status_code.is_success() {
            let body_bytes = response
                .into_body()
                .collect()
                .await
                .map_err(|e| error::Error::StatusRequestFailed {
                    reason: format!("failed to collect response body: {e}"),
                })?
                .to_bytes();
            let body_str = String::from_utf8(body_bytes.to_vec()).map_err(|e| {
                error::Error::StatusRequestFailed {
                    reason: format!("failed to parse response body as UTF-8: {e}"),
                }
            })?;
            let response_data: R =
                serde_json::from_str(&body_str).map_err(|e| error::Error::StatusRequestFailed {
                    reason: format!("failed to parse response as JSON: {e}"),
                })?;

            Ok(response_data)
        } else {
            Err(error::Error::StatusRequestFailed {
                reason: format!("server returned error status: {status_code}"),
            })
        }
    }
}
