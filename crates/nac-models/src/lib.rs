//! nac-models: core domain models for the NAC platform.

pub mod device;
pub mod policy;
pub mod session;
pub mod user;

use serde::{Deserialize, Serialize};

/// MAC address represented as a 6-byte array.
pub type MacAddress = [u8; 6];

/// Network access status of a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessStatus {
    /// Device is allowed full network access.
    Allowed,
    /// Device is placed in a quarantine VLAN.
    Quarantined,
    /// Device is denied network access.
    Denied,
    /// Device is pending policy evaluation.
    Pending,
}

/// A network endpoint (device) tracked by the NAC system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    /// MAC address of the device.
    pub mac_address: String,
    /// Last known IPv4 address.
    pub ip_address: Option<String>,
    /// Hostname discovered via DNS/DHCP.
    pub hostname: Option<String>,
    /// OS family from fingerprinting (e.g. "Windows", "Linux", "iOS").
    pub os_family: Option<String>,
    /// Device category (e.g. "Workstation", "Mobile", "IoT").
    pub device_type: Option<String>,
    /// Authenticated username (from 802.1X / Captive Portal).
    pub username: Option<String>,
    /// VLAN the device is currently assigned to.
    pub vlan_id: Option<u16>,
    /// Switch port identifier (e.g. "GigabitEthernet0/1").
    pub switch_port: Option<String>,
    /// Current access status.
    pub status: AccessStatus,
    /// Unix timestamp of first seen.
    pub first_seen: i64,
    /// Unix timestamp of last seen.
    pub last_seen: i64,
}

/// A VLAN definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vlan {
    pub id: u16,
    pub name: String,
    pub description: Option<String>,
    pub is_quarantine: bool,
}

/// A switch port on a managed network device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchPort {
    pub switch_id: String,
    pub port_id: String,
    pub description: Option<String>,
    pub vlan_id: Option<u16>,
    pub mac_address: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_serialization() {
        let ep = Endpoint {
            mac_address: "AA:BB:CC:DD:EE:FF".into(),
            ip_address: Some("192.168.1.100".into()),
            hostname: Some("workstation-01".into()),
            os_family: Some("Windows".into()),
            device_type: Some("Workstation".into()),
            username: Some("alice".into()),
            vlan_id: Some(10),
            switch_port: Some("Gi0/1".into()),
            status: AccessStatus::Allowed,
            first_seen: 0,
            last_seen: 0,
        };
        let json = serde_json::to_string(&ep).unwrap();
        let decoded: Endpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.mac_address, ep.mac_address);
        assert_eq!(decoded.status, AccessStatus::Allowed);
    }
}
