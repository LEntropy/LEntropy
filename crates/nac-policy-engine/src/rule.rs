//! Policy rule definitions and condition types.

use crate::PolicyDecision;
use serde::{Deserialize, Serialize};

/// A single match condition within a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Condition {
    /// Match devices whose OS family equals the given value.
    OsFamily { value: String },
    /// Match devices belonging to any of the given user groups.
    UserGroup { groups: Vec<String> },
    /// Match by device compliance status.
    Compliant { required: bool },
    /// Match by device type (e.g. "Mobile", "IoT").
    DeviceType { value: String },
    /// Logical AND of multiple conditions.
    And { conditions: Vec<Condition> },
    /// Logical OR of multiple conditions.
    Or { conditions: Vec<Condition> },
    /// Logical NOT of a condition.
    Not { condition: Box<Condition> },
}

/// A named policy rule with priority, conditions, and a resulting decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Human-readable rule name.
    pub name: String,
    /// Lower value = higher priority (evaluated first).
    pub priority: i32,
    /// Conditions that must match for this rule to trigger.
    pub condition: Condition,
    /// Decision to apply when this rule matches.
    pub decision: PolicyDecision,
}
