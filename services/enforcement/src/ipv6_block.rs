//! IPv6 NA (Neighbor Advertisement) 스푸핑으로 IPv6 단말 격리.
//!
//! 격리 대상 단말에게 "게이트웨이 IPv6 = enforcement MAC" 라는
//! NA 패킷을 전송해 IPv6 통신을 차단한다.

use anyhow::{Context, Result};
use pnet::datalink::{self, Channel};
use std::net::Ipv6Addr;
use tracing::info;

/// IPv6 NA 스푸핑 패킷 생성 (raw Ethernet frame).
///
/// ICMPv6 Neighbor Advertisement:
/// - Ethernet dst: 33:33:00:00:00:01 (IPv6 all-nodes multicast)
/// - IPv6 src: 스푸핑할 IPv6 (e.g. gateway)
/// - Target: 같은 주소
/// - Override flag: true (캐시 덮어쓰기 강제)
#[allow(dead_code)]
pub fn craft_na_spoof(sender_mac: [u8; 6], target_ipv6: Ipv6Addr) -> Vec<u8> {
    let mut frame = Vec::with_capacity(86);

    // Ethernet header
    frame.extend_from_slice(&[0x33, 0x33, 0x00, 0x00, 0x00, 0x01]); // dst: IPv6 all-nodes
    frame.extend_from_slice(&sender_mac); // src
    frame.extend_from_slice(&[0x86, 0xDD]); // ethertype IPv6

    // IPv6 header (40 bytes)
    frame.push(0x60);
    frame.push(0);
    frame.push(0);
    frame.push(0); // version=6, TC=0, FL=0
    frame.extend_from_slice(&[0x00, 0x20]); // payload length = 32 (NA body)
    frame.push(58); // next header: ICMPv6
    frame.push(255); // hop limit
    frame.extend_from_slice(&target_ipv6.octets()); // src = target (spoofed)
                                                    // dst = all-nodes ff02::1
    frame.extend_from_slice(&[0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]);

    // ICMPv6 Neighbor Advertisement (type=136)
    frame.push(136); // type: NA
    frame.push(0); // code
    frame.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
                                            // flags: Router=0, Solicited=0, Override=1 (0x20000000 big-endian)
    frame.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&target_ipv6.octets()); // Target Address

    // Option: Target Link-Layer Address (type=2, len=1 unit=8)
    frame.push(2); // type
    frame.push(1); // len (8 bytes)
    frame.extend_from_slice(&sender_mac); // spoofed MAC

    frame
}

#[allow(dead_code)]
pub struct Ipv6Blocker {
    iface_name: String,
    enforcement_mac: [u8; 6],
}

impl Ipv6Blocker {
    #[allow(dead_code)]
    pub fn new(iface_name: String, enforcement_mac: [u8; 6]) -> Self {
        Self {
            iface_name,
            enforcement_mac,
        }
    }

    /// 대상 IPv6를 격리: NA 스푸핑 패킷 전송
    #[allow(dead_code)]
    pub fn block(&self, target_ipv6: Ipv6Addr) -> Result<()> {
        let interfaces = datalink::interfaces();
        let iface = interfaces
            .into_iter()
            .find(|i| i.name == self.iface_name)
            .with_context(|| format!("interface '{}' not found", self.iface_name))?;

        let (mut tx, _) = match datalink::channel(&iface, datalink::Config::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => anyhow::bail!("unsupported channel"),
            Err(e) => anyhow::bail!("channel error: {e}"),
        };

        let frame = craft_na_spoof(self.enforcement_mac, target_ipv6);

        match tx.send_to(&frame, None) {
            Some(Ok(())) => {
                info!(target = %target_ipv6, "IPv6 NA spoof sent");
                Ok(())
            }
            Some(Err(e)) => anyhow::bail!("send error: {e}"),
            None => anyhow::bail!("send returned None"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_craft_na_spoof_length() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let ipv6: Ipv6Addr = "fe80::1".parse().unwrap();
        let frame = craft_na_spoof(mac, ipv6);
        // 14 (Eth) + 40 (IPv6) + 32 (ICMPv6 NA + option) = 86
        assert_eq!(frame.len(), 86);
        // ethertype IPv6
        assert_eq!(&frame[12..14], &[0x86, 0xDD]);
        // ICMPv6 type = 136 (NA)
        assert_eq!(frame[54], 136);
    }

    #[test]
    fn test_craft_na_spoof_override_flag() {
        let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let ipv6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let frame = craft_na_spoof(mac, ipv6);
        // Override flag in NA flags field (byte 58)
        assert_eq!(frame[58], 0x20); // Override bit
    }
}
