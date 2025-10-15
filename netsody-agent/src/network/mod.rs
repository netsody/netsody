pub(crate) mod config;

pub use config::*;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Default)]
pub enum AgentStateStatus {
    #[default]
    Initializing,
    Disabled,
    Ok,
    Pending,
    RetrieveConfigError(String),
    NotAMemberError,
}

#[derive(Default, PartialEq, Clone, Serialize, Deserialize, Debug)]
pub struct AppliedStatus<T> {
    pub applied: Option<T>,
    pub(crate) error: Option<String>,
}

impl<T> AppliedStatus<T> {
    pub(crate) fn applied(applied: T) -> Self {
        Self {
            applied: Some(applied),
            error: None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn unapplied() -> Self {
        Self {
            applied: None,
            error: None,
        }
    }

    pub(crate) fn error(error: String) -> Self {
        Self {
            applied: None,
            error: Some(error),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn with_error(applied: T, error: String) -> Self {
        Self {
            applied: Some(applied),
            error: Some(error),
        }
    }
}

impl<T: std::fmt::Display> fmt::Display for AppliedStatus<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.applied, &self.error) {
            (Some(applied), None) => write!(f, "{}", applied),
            (None, None) => write!(f, "None"),
            (Some(applied), Some(e)) => write!(f, "{} (Error: {e})", applied),
            (None, Some(e)) => write!(f, "None (Error: {e})"),
        }?;
        Ok(())
    }
}

#[derive(PartialEq, Clone, Deserialize, Serialize, Default)]
pub struct AgentState {
    pub ip: AppliedStatus<Ipv4Net>,
    pub(crate) access_rules: AppliedStatus<EffectiveAccessRuleList>,
    pub(crate) routes: AppliedStatus<EffectiveRoutingList>,
    pub(crate) forwardings: AppliedStatus<EffectiveForwardingList>,
    #[cfg(feature = "dns")]
    pub(crate) hostnames: AppliedStatus<HostnameList>,
}

impl AgentState {}

#[derive(Deserialize, Serialize, Clone)]
pub struct Network {
    pub(crate) config_url: String,
    #[serde(default)]
    pub(crate) disabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    #[serde(skip_deserializing, skip_serializing, default)]
    pub(crate) status: AgentStateStatus,
    #[serde(skip_deserializing, skip_serializing, default)]
    pub(crate) desired_state: AgentState,
    #[serde(skip_deserializing, skip_serializing, default)]
    pub(crate) current_state: AgentState,
}
