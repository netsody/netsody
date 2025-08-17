use crate::agent::Error;
use crate::network::Network;
use p2p::message::{ARM_HEADER_LEN, LONG_HEADER_LEN, SHORT_HEADER_LEN};
use p2p::node::{Identity, MTU_DEFAULT};
use p2p::util;
use serde::Deserialize;
use serde::Serialize;
use serde::de;
use std::collections::HashMap;
use std::fs;
use tracing::{info, trace};
use url::Url;

#[cfg(feature = "prometheus")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PrometheusConfig {
    pub url: String,
    pub user: String,
    pub pass: String,
}

#[derive(Deserialize, Serialize)]
pub struct AgentConfig {
    #[serde(rename = "identity")]
    pub id: Identity,
    #[serde(
        rename = "network",
        default,
        deserialize_with = "deserialize_networks",
        serialize_with = "serialize_networks"
    )]
    pub networks: HashMap<Url, Network>,
    pub mtu: Option<u16>,
    #[cfg(feature = "prometheus")]
    pub prometheus: Option<PrometheusConfig>,
}

impl AgentConfig {
    pub fn new(id: Identity) -> Self {
        Self {
            id,
            networks: Default::default(),
            mtu: Default::default(),
            #[cfg(feature = "prometheus")]
            prometheus: Default::default(),
        }
    }

    pub fn load(path: &str) -> Result<Self, Error> {
        trace!("Loading agent config from {}", path);
        let config_content = fs::read_to_string(path)?;
        trace!("Successfully read config file");
        let config: AgentConfig = toml::from_str(&config_content)?;
        trace!("Successfully parsed config file");
        Ok(config)
    }

    pub fn load_or_generate(path: &str) -> Result<Self, Error> {
        trace!("Loading or generating agent config from {}", path);

        // options
        let min_pow_difficulty = util::get_env("MIN_POW_DIFFICULTY", 24);
        trace!("Using min PoW difficulty: {}", min_pow_difficulty);

        // Read and parse config.toml from current directory
        let config = if std::path::Path::new(path).exists() {
            Self::load(path)?
        } else {
            info!(
                "Config file does not exist, generating new one (this might take some time due to the PoW)"
            );

            // Generate new identity and create default config
            let id = Identity::generate(min_pow_difficulty)?;
            trace!("Generated new identity with public key: {}", id.pk);

            let config = AgentConfig::new(id);

            // Serialize and save the config
            config.save(path)?;

            config
        };

        trace!("Config loaded successfully");
        Ok(config)
    }

    pub fn save(&self, path: &str) -> Result<(), Error> {
        trace!("Saving agent config to {}", path);

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

    pub(crate) fn default_mtu() -> u16 {
        let arm_messages = util::get_env("ARM_MESSAGES", true);
        (if arm_messages {
            MTU_DEFAULT - 4 - ARM_HEADER_LEN /* - 11 for COMPRESSION */ - (LONG_HEADER_LEN - SHORT_HEADER_LEN)
        } else {
            MTU_DEFAULT - 4 /* - 11 for COMPRESSION */ - (LONG_HEADER_LEN - SHORT_HEADER_LEN)
        }) as u16
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
                "duplicate network URL: {config_url}"
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
