use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub device_mac: String,
    pub user_id: Option<String>,
    pub state: SessionState,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionState {
    Detecting,
    Authenticating,
    CheckingIntegrity,
    Active,
    Quarantined,
    Blocked,
}
