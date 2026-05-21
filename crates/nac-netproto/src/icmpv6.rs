//! ICMPv6 Neighbor Discovery 처리 (RFC 4861).

use crate::NetProtoError;
use std::net::Ipv6Addr;

/// ICMPv6 메시지 타입
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Icmpv6Type {
    RouterSolicitation = 133,
    RouterAdvertisement = 134,
    NeighborSolicitation = 135,
    NeighborAdvertisement = 136,
    Other(u8),
}

impl From<u8> for Icmpv6Type {
    fn from(v: u8) -> Self {
        match v {
            133 => Self::RouterSolicitation,
            134 => Self::RouterAdvertisement,
            135 => Self::NeighborSolicitation,
            136 => Self::NeighborAdvertisement,
            other => Self::Other(other),
        }
    }
}

/// Neighbor Solicitation/Advertisement에서 추출한 정보
#[derive(Debug, Clone)]
pub struct NdpEntry {
    pub icmpv6_type: Icmpv6Type,
    pub target_addr: Ipv6Addr,
    /// 링크 레이어 주소 옵션 (옵션 타입 1=Source, 2=Target)
    pub link_layer_addr: Option<[u8; 6]>,
}

/// ICMPv6 페이로드에서 NDP 정보 파싱
pub fn parse_ndp(payload: &[u8]) -> Result<NdpEntry, NetProtoError> {
    if payload.len() < 24 {
        return Err(NetProtoError::Parse("ICMPv6 payload too short".into()));
    }
    let msg_type = Icmpv6Type::from(payload[0]);

    // target address: bytes 8..24
    let mut target = [0u8; 16];
    target.copy_from_slice(&payload[8..24]);
    let target_addr = Ipv6Addr::from(target);

    // options parsing: type(1) + len(1) + data(len*8 - 2)
    let mut link_layer_addr = None;
    let mut i = 24;
    while i + 2 <= payload.len() {
        let opt_type = payload[i];
        let opt_len = payload[i + 1] as usize * 8;
        if opt_len == 0 {
            break;
        }
        if i + opt_len > payload.len() {
            break;
        }
        if (opt_type == 1 || opt_type == 2) && opt_len >= 8 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&payload[i + 2..i + 8]);
            link_layer_addr = Some(mac);
        }
        i += opt_len;
    }

    Ok(NdpEntry {
        icmpv6_type: msg_type,
        target_addr,
        link_layer_addr,
    })
}

/// A Neighbor Advertisement observed on the wire (legacy alias).
#[derive(Debug, Clone)]
pub struct NeighborAdvertisement {
    pub target_addr: Ipv6Addr,
    pub link_layer_addr: Option<[u8; 6]>,
}

/// Parse an ICMPv6 Neighbor Advertisement from a raw ICMPv6 payload.
pub fn parse_neighbor_advertisement(
    payload: &[u8],
) -> Result<NeighborAdvertisement, NetProtoError> {
    // ICMPv6 NA: type=136, minimum length=24 bytes
    if payload.len() < 24 {
        return Err(NetProtoError::Parse("ICMPv6 NA payload too short".into()));
    }
    if payload[0] != 136 {
        return Err(NetProtoError::Parse(
            "not an ICMPv6 Neighbor Advertisement".into(),
        ));
    }

    let mut addr_bytes = [0u8; 16];
    addr_bytes.copy_from_slice(&payload[8..24]);
    let target_addr = Ipv6Addr::from(addr_bytes);

    // Parse NDP options starting at byte 24
    let mut link_layer_addr = None;
    let mut i = 24;
    while i + 2 <= payload.len() {
        let opt_type = payload[i];
        let opt_len = payload[i + 1] as usize * 8;
        if opt_len == 0 {
            break;
        }
        // Option type 2 = Target Link-Layer Address
        if opt_type == 2 && opt_len >= 8 && i + 8 <= payload.len() {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&payload[i + 2..i + 8]);
            link_layer_addr = Some(mac);
        }
        i += opt_len;
    }

    Ok(NeighborAdvertisement {
        target_addr,
        link_layer_addr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmpv6_type_from_u8() {
        assert_eq!(Icmpv6Type::from(133), Icmpv6Type::RouterSolicitation);
        assert_eq!(Icmpv6Type::from(134), Icmpv6Type::RouterAdvertisement);
        assert_eq!(Icmpv6Type::from(135), Icmpv6Type::NeighborSolicitation);
        assert_eq!(Icmpv6Type::from(136), Icmpv6Type::NeighborAdvertisement);
        assert_eq!(Icmpv6Type::from(0), Icmpv6Type::Other(0));
    }

    #[test]
    fn test_parse_ndp_too_short() {
        let result = parse_ndp(&[136u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ndp_neighbor_advertisement() {
        // Build a minimal NA payload: type(1) + code(1) + checksum(2) + flags(4) + target(16) = 24
        let mut payload = vec![0u8; 24];
        payload[0] = 136; // NeighborAdvertisement
                          // target: fe80::1 → bytes 8..24
        payload[8..24].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let entry = parse_ndp(&payload).unwrap();
        assert_eq!(entry.icmpv6_type, Icmpv6Type::NeighborAdvertisement);
        assert_eq!(entry.link_layer_addr, None);
    }
}
