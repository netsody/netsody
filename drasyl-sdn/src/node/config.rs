use crate::network::Network;
use crate::node::Error;
use crate::rest_api::API_TOKEN_LEN_DEFAULT;
use drasyl::crypto::random_bytes;
use drasyl::node::Identity;
use drasyl::util;
use drasyl::util::bytes_to_hex;
use serde::Deserialize;
use serde::Serialize;
use serde::de;
use std::collections::HashMap;
use std::fs;
use tracing::trace;
use url::Url;

#[cfg(feature = "prometheus")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PrometheusConfig {
    pub url: String,
    pub user: String,
    pub pass: String,
}

#[derive(Deserialize, Serialize)]
pub struct SdnNodeConfig {
    #[serde(rename = "identity")]
    pub id: Identity,
    pub auth_token: String,
    #[serde(
        rename = "network",
        default,
        deserialize_with = "deserialize_networks",
        serialize_with = "serialize_networks"
    )]
    pub networks: HashMap<Url, Network>,
    #[cfg(feature = "prometheus")]
    pub prometheus: Option<PrometheusConfig>,
}

impl SdnNodeConfig {
    pub fn new(id: Identity, auth_token: String) -> Self {
        Self {
            id,
            auth_token,
            networks: Default::default(),
            #[cfg(feature = "prometheus")]
            prometheus: Default::default(),
        }
    }

    pub fn load(path: &str) -> Result<Self, Error> {
        trace!("Loading SDN config from {}", path);
        let config_content = fs::read_to_string(path)?;
        trace!("Successfully read config file");
        let config: SdnNodeConfig = toml::from_str(&config_content)?;
        trace!("Successfully parsed config file");
        Ok(config)
    }

    pub fn load_or_generate(path: &str) -> Result<Self, Error> {
        trace!("Loading or generating SDN config from {}", path);

        // options
        let min_pow_difficulty = util::get_env("MIN_POW_DIFFICULTY", 24);
        trace!("Using min PoW difficulty: {}", min_pow_difficulty);
        let token_len = util::get_env("API_TOKEN_LEN", API_TOKEN_LEN_DEFAULT);

        // Read and parse config.toml from current directory
        let config = if std::path::Path::new(path).exists() {
            Self::load(path)?
        } else {
            trace!("Config file does not exist, generating new one");

            // auth_token: generate random bytes and convert to hex
            let mut buf = vec![0u8; token_len];
            random_bytes(&mut buf);
            let auth_token = bytes_to_hex(&buf);

            // Generate new identity and create default config
            let id = Identity::generate(min_pow_difficulty)?;
            trace!("Generated new identity with public key: {}", id.pk);

            let config = SdnNodeConfig::new(id, auth_token);

            // Serialize and save the config
            config.save(path)?;

            trace!("Successfully wrote config file");

            config
        };

        trace!("Config loaded successfully");
        Ok(config)
    }

    pub fn save(&self, path: &str) -> Result<(), Error> {
        trace!("Saving SDN config to {}", path);

        // Serialize the config
        let config_content = toml::to_string_pretty(self)?;
        trace!("Successfully serialized config");

        // Create empty file if it doesn't exist
        if !std::path::Path::new(path).exists() {
            fs::write(path, "")?;

            // Set restrictive file permissions (Unix only)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(path)?.permissions();
                perms.set_mode(0o600); // Read/write for owner only
                fs::set_permissions(path, perms)?;
            }
        }

        // Write content
        fs::write(path, &config_content)?;
        trace!("Successfully wrote config file");

        Ok(())
    }
}

fn deserialize_networks<'de, D>(deserializer: D) -> Result<HashMap<Url, Network>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let networks: Vec<Network> = Vec::deserialize(deserializer)?;

    let mut result = HashMap::new();
    for network in networks {
        let config_url = Url::parse(network.config_url.as_str()).map_err(de::Error::custom)?;
        if result.insert(config_url.clone(), network).is_some() {
            return Err(de::Error::custom(format!(
                "duplicate network URL: {}",
                config_url
            )));
        }
    }

    Ok(result)
}

fn serialize_networks<S>(networks: &HashMap<Url, Network>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;

    // If networks is empty, serialize as None to omit the field entirely
    if networks.is_empty() {
        return serializer.serialize_none();
    }

    // sort networks alphabetically by URL
    let mut sorted_networks: Vec<_> = networks.values().collect();
    sorted_networks.sort_by(|a, b| a.config_url.cmp(&b.config_url));

    let mut seq = serializer.serialize_seq(Some(sorted_networks.len()))?;
    for network in sorted_networks {
        seq.serialize_element(network)?;
    }
    seq.end()
}
