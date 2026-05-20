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

    let mut lease_secs = 86400u32;
    let mut i = 236 + 4; // skip magic cookie
    while i + 1 < payload.len() {
        let code = payload[i];
        if code == 255 {
            break;
        }
        if code == 0 {
            i += 1;
            continue;
        }
        let len = payload[i + 1] as usize;
        if code == 51 && len == 4 && i + 2 + len <= payload.len() {
            lease_secs = u32::from_be_bytes([
                payload[i + 2],
                payload[i + 3],
                payload[i + 4],
                payload[i + 5],
            ]);
        }
        i += 2 + len;
    }

    Ok(DhcpBinding {
        client_mac: mac,
        offered_ip: yiaddr,
        lease_secs,
    })
}

// ── DHCP 클라이언트 패킷 파싱 (핑거프린팅용) ─────────────────────────────

/// DHCP DISCOVER/REQUEST에서 추출한 핑거프린팅 신호.
#[derive(Debug, Clone)]
pub struct DhcpClientPacket {
    /// 클라이언트 MAC 주소 (BOOTP chaddr 필드)
    pub client_mac: [u8; 6],
    /// Option 53: DHCP 메시지 타입 (1=DISCOVER, 3=REQUEST)
    pub msg_type: u8,
    /// Option 12: 호스트명
    pub hostname: Option<String>,
    /// Option 55: Parameter Request List — OS 핑거프린팅 핵심 신호
    pub parameter_request_list: Option<Vec<u8>>,
    /// Option 60: Vendor Class Identifier
    pub vendor_class: Option<String>,
}

/// BOOTP/DHCPv4 클라이언트 요청(op=1)에서 핑거프린팅 데이터를 추출.
pub fn parse_dhcp_client(payload: &[u8]) -> Result<DhcpClientPacket, NetProtoError> {
    if payload.len() < 240 {
        return Err(NetProtoError::Parse("DHCP client payload too short".into()));
    }
    if payload[0] != 1 {
        return Err(NetProtoError::Parse("not a DHCP request (op != 1)".into()));
    }

    let mut mac = [0u8; 6];
    mac.copy_from_slice(&payload[28..34]);

    let mut msg_type = 0u8;
    let mut hostname = None;
    let mut parameter_request_list = None;
    let mut vendor_class = None;

    // Options start at byte 240 (236-byte BOOTP header + 4-byte magic cookie)
    let mut i = 240;
    while i < payload.len() {
        let code = payload[i];
        if code == 255 {
            break; // END
        }
        if code == 0 {
            i += 1; // PAD
            continue;
        }
        if i + 1 >= payload.len() {
            break;
        }
        let len = payload[i + 1] as usize;
        let data_start = i + 2;
        if data_start + len > payload.len() {
            break;
        }
        let data = &payload[data_start..data_start + len];

        match code {
            12 => hostname = String::from_utf8(data.to_vec()).ok(),
            53 if len == 1 => msg_type = data[0],
            55 => parameter_request_list = Some(data.to_vec()),
            60 => vendor_class = String::from_utf8(data.to_vec()).ok(),
            _ => {}
        }

        i = data_start + len;
    }

    Ok(DhcpClientPacket {
        client_mac: mac,
        msg_type,
        hostname,
        parameter_request_list,
        vendor_class,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dhcp_discover(mac: [u8; 6], prl: &[u8], hostname: &str) -> Vec<u8> {
        let mut pkt = vec![0u8; 240];
        pkt[0] = 1; // op=BOOTREQUEST
        pkt[1] = 1; // htype=Ethernet
        pkt[2] = 6; // hlen
        pkt[28..34].copy_from_slice(&mac);
        // magic cookie
        pkt[236] = 99;
        pkt[237] = 130;
        pkt[238] = 83;
        pkt[239] = 99;
        // Option 53: DHCP Discover
        pkt.extend_from_slice(&[53, 1, 1]);
        // Option 55: PRL
        pkt.push(55);
        pkt.push(prl.len() as u8);
        pkt.extend_from_slice(prl);
        // Option 12: hostname
        let h = hostname.as_bytes();
        pkt.push(12);
        pkt.push(h.len() as u8);
        pkt.extend_from_slice(h);
        // Option 255: END
        pkt.push(255);
        pkt
    }

    #[test]
    fn test_parse_dhcp_discover() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let prl = &[1u8, 3, 6, 15];
        let pkt = make_dhcp_discover(mac, prl, "myhost");
        let result = parse_dhcp_client(&pkt).unwrap();
        assert_eq!(result.client_mac, mac);
        assert_eq!(result.msg_type, 1); // DISCOVER
        assert_eq!(result.parameter_request_list.as_deref(), Some(prl as &[u8]));
        assert_eq!(result.hostname.as_deref(), Some("myhost"));
    }

    #[test]
    fn test_parse_dhcp_too_short() {
        let short = vec![0u8; 100];
        assert!(parse_dhcp_client(&short).is_err());
    }

    #[test]
    fn test_parse_dhcp_not_request() {
        let mut pkt = vec![0u8; 240];
        pkt[0] = 2; // op=BOOTREPLY
        assert!(parse_dhcp_client(&pkt).is_err());
    }
}
