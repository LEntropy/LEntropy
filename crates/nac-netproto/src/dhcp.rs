//! DHCP snooping helpers (DHCPv4 / DHCPv6).

use crate::NetProtoError;

/// A minimal DHCP binding observed from snooped OFFER/ACK messages.
#[derive(Debug, Clone)]
pub struct DhcpBinding {
    pub client_mac: [u8; 6],
    pub offered_ip: std::net::Ipv4Addr,
    pub lease_secs: u32,
}

/// Extract a DHCP binding from a raw UDP payload (BOOTP/DHCPv4).
pub fn parse_dhcp_binding(payload: &[u8]) -> Result<DhcpBinding, NetProtoError> {
    if payload.len() < 236 {
        return Err(NetProtoError::Parse("DHCPv4 payload too short".into()));
    }
    let op = payload[0];
    if op != 2 {
        return Err(NetProtoError::Parse("not a DHCP reply (op != 2)".into()));
    }

    let mut mac = [0u8; 6];
    mac.copy_from_slice(&payload[28..34]);

    let yiaddr = std::net::Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);

    // Scan options for lease time (code 51)
    let mut lease_secs = 86400u32;
    let mut i = 236 + 4; // skip magic cookie
    while i + 1 < payload.len() {
        let code = payload[i];
        if code == 255 { break; }
        if code == 0 { i += 1; continue; }
        let len = payload[i + 1] as usize;
        if code == 51 && len == 4 && i + 2 + len <= payload.len() {
            lease_secs = u32::from_be_bytes([
                payload[i+2], payload[i+3], payload[i+4], payload[i+5],
            ]);
        }
        i += 2 + len;
    }

    Ok(DhcpBinding { client_mac: mac, offered_ip: yiaddr, lease_secs })
}
