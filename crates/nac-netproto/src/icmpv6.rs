//! ICMPv6 Neighbor Discovery (NDP) snooping helpers.

use crate::NetProtoError;
use std::net::Ipv6Addr;

/// A Neighbor Advertisement observed on the wire.
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
