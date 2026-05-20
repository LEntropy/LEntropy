//! nac-policy-engine: NAC policy rule evaluation engine.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod evaluator;
pub mod rule;

/// Errors produced by the policy engine.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("unknown policy: {0}")]
    UnknownPolicy(String),
    #[error("evaluation error: {0}")]
    Evaluation(String),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// The outcome of a policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    /// Allow the device with no restrictions.
    Allow,
    /// Allow with VLAN assignment.
    AllowVlan(u16),
    /// Quarantine to a restricted VLAN.
    Quarantine { vlan: u16, reason: String },
    /// Deny network access entirely.
    Deny { reason: String },
}

/// Context provided to the policy engine for evaluation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyContext {
    pub mac_address: String,
    pub ip_address: Option<String>,
    pub hostname: Option<String>,
    pub os_family: Option<String>,
    pub device_type: Option<String>,
    pub username: Option<String>,
    pub groups: Vec<String>,
    pub is_compliant: Option<bool>,
    pub switch_port: Option<String>,
}
