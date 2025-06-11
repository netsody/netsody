use crate::network::Network;
use crate::node::Error;
use drasyl::node::Identity;
use drasyl::util;
use serde::Deserialize;
use serde::Serialize;
use serde::de;
use std::collections::HashMap;
use std::fs;
use tracing::trace;
use url::Url;

#[derive(Deserialize, Serialize)]
pub struct SdnNodeConfig {
    #[serde(rename = "identity")]
    pub id: Identity,
    #[serde(
        skip_serializing,
        rename = "network",
        default,
        deserialize_with = "deserialize_networks"
    )]
    pub networks: HashMap<Url, Network>,
}

impl SdnNodeConfig {
    pub fn new(id: Identity) -> Self {
        Self {
            id,
            networks: Default::default(),
        }
    }

    pub fn load_or_generate(path: &str) -> Result<Self, Error> {
        trace!("Loading or generating SDN config from {}", path);

        // options
        let min_pow_difficulty = util::get_env("MIN_POW_DIFFICULTY", 24);
        trace!("Using min PoW difficulty: {}", min_pow_difficulty);

        // Read and parse config.toml from current directory
        let config = if std::path::Path::new(path).exists() {
            trace!("Config file exists, loading from {}", path);
            let config_content = fs::read_to_string(path)?;
            trace!("Successfully read config file");
            toml::from_str(&config_content)?
        } else {
            trace!("Config file does not exist, generating new one");
            // Generate new identity and create default config
            let id = Identity::generate(min_pow_difficulty)?;
            trace!("Generated new identity with public key: {}", id.pk);

            let config = SdnNodeConfig::new(id);

            // Serialize and save the config
            let config_content = toml::to_string_pretty(&config)?;
            trace!("Serialized config, writing to {}", path);

            // Create empty file
            fs::write(path, "")?;

            // Set restrictive file permissions (Unix only)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(path)?.permissions();
                perms.set_mode(0o600); // Read/write for owner only
                fs::set_permissions(path, perms)?;
            }

            // Write content
            fs::write(path, &config_content)?;

            trace!("Successfully wrote config file");

            config
        };

        trace!("Config loaded successfully");
        Ok(config)
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
