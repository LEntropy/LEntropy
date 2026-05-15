use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub priority: i32,
    pub conditions: Vec<Condition>,
    pub action: PolicyAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Condition {
    MacAddress(String),
    IpRange { start: String, end: String },
    UserGroup(String),
    DeviceType(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyAction {
    Allow,
    Quarantine { vlan_id: u16 },
    Block,
}
