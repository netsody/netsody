use ipnet::Ipv4Net;
use p2p::identity::PubKey;
use std::net::Ipv4Addr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("IP address {0} is not in network {1}")]
    IpNotInNetwork(Ipv4Addr, Ipv4Net),
    #[error("gateway {0} not found in nodes")]
    GatewayNotFound(PubKey),
    #[error("TOML deserialization error: {0}")]
    TomlError(#[from] toml::de::Error),
    #[error("duplicate route")]
    RouteDuplicate,
    #[error("IP address {0} is reserved")]
    IpReserved(Ipv4Addr),
    #[error("invalid hostname: {0}")]
    HostnameInvalid(String),
    #[error("invalid network address: {0} is a host address")]
    NetworkAddressInvalid(Ipv4Net),
}
