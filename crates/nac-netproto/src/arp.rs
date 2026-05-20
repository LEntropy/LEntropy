//! ARP packet snooping and spoofing utilities.

use crate::NetProtoError;
use std::net::Ipv4Addr;

/// A parsed ARP entry observed on the wire.
#[derive(Debug, Clone)]
pub struct ArpEntry {
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_ip: Ipv4Addr,
    pub is_reply: bool,
}

/// Craft a gratuitous ARP reply to enforce an IP–MAC binding.
///
/// Returns the raw Ethernet frame bytes ready for injection.
pub fn craft_gratuitous_arp(
    sender_mac: [u8; 6],
    sender_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Result<Vec<u8>, NetProtoError> {
    // Ethernet header: dst=broadcast, src=sender_mac, type=0x0806
    let mut frame = Vec::with_capacity(42);
    frame.extend_from_slice(&[0xff; 6]); // dst: broadcast
    frame.extend_from_slice(&sender_mac); // src
    frame.extend_from_slice(&[0x08, 0x06]); // ethertype ARP

    // ARP payload
    frame.extend_from_slice(&[0x00, 0x01]); // HTYPE: Ethernet
    frame.extend_from_slice(&[0x08, 0x00]); // PTYPE: IPv4
    frame.push(6); // HLEN
    frame.push(4); // PLEN
    frame.extend_from_slice(&[0x00, 0x02]); // OPER: reply
    frame.extend_from_slice(&sender_mac); // SHA
    frame.extend_from_slice(&sender_ip.octets()); // SPA
    frame.extend_from_slice(&[0x00; 6]); // THA (ignored in gratuitous)
    frame.extend_from_slice(&target_ip.octets()); // TPA

    Ok(frame)
}

/// Craft a targeted ARP reply (unicast) for ARP poisoning.
///
/// - `dst_mac`: 피해자 MAC (Ethernet 목적지)
/// - `sender_mac`: 스푸핑할 MAC (enforcement node의 실제 MAC)
/// - `sender_ip`: 스푸핑할 IP (예: 게이트웨이 IP)
/// - `target_mac`: 피해자 MAC (ARP THA)
/// - `target_ip`: 피해자 IP (ARP TPA)
pub fn craft_arp_reply(
    dst_mac: [u8; 6],
    sender_mac: [u8; 6],
    sender_ip: Ipv4Addr,
    target_mac: [u8; 6],
    target_ip: Ipv4Addr,
) -> Result<Vec<u8>, NetProtoError> {
    let mut frame = Vec::with_capacity(42);
    // Ethernet header
    frame.extend_from_slice(&dst_mac); // dst: victim MAC (unicast)
    frame.extend_from_slice(&sender_mac); // src: enforcement MAC
    frame.extend_from_slice(&[0x08, 0x06]); // ethertype ARP

    // ARP payload
    frame.extend_from_slice(&[0x00, 0x01]); // HTYPE: Ethernet
    frame.extend_from_slice(&[0x08, 0x00]); // PTYPE: IPv4
    frame.push(6); // HLEN
    frame.push(4); // PLEN
    frame.extend_from_slice(&[0x00, 0x02]); // OPER: reply
    frame.extend_from_slice(&sender_mac); // SHA: spoofed sender MAC
    frame.extend_from_slice(&sender_ip.octets()); // SPA: spoofed sender IP
    frame.extend_from_slice(&target_mac); // THA: victim MAC
    frame.extend_from_slice(&target_ip.octets()); // TPA: victim IP

    Ok(frame)
}

/// Parse an ARP entry from a raw Ethernet frame slice.
pub fn parse_arp(frame: &[u8]) -> Result<ArpEntry, NetProtoError> {
    if frame.len() < 42 {
        return Err(NetProtoError::Parse("frame too short for ARP".into()));
    }
    let oper = u16::from_be_bytes([frame[20], frame[21]]);
    let mut sha = [0u8; 6];
    sha.copy_from_slice(&frame[22..28]);
    let spa = Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]);
    let tpa = Ipv4Addr::new(frame[38], frame[39], frame[40], frame[41]);

    Ok(ArpEntry {
        sender_mac: sha,
        sender_ip: spa,
        target_ip: tpa,
        is_reply: oper == 2,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_craft_gratuitous_arp_length() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let ip = "192.168.1.1".parse().unwrap();
        let frame = craft_gratuitous_arp(mac, ip, ip).unwrap();
        assert_eq!(frame.len(), 42);
        // Ethernet dst = broadcast
        assert_eq!(&frame[0..6], &[0xff; 6]);
        // ethertype ARP
        assert_eq!(&frame[12..14], &[0x08, 0x06]);
        // ARP OPER = reply (2)
        assert_eq!(&frame[20..22], &[0x00, 0x02]);
    }

    #[test]
    fn test_craft_arp_reply_unicast() {
        let dst = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let sender = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let sender_ip = "192.168.1.1".parse().unwrap();
        let target = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let target_ip = "192.168.1.100".parse().unwrap();
        let frame = craft_arp_reply(dst, sender, sender_ip, target, target_ip).unwrap();
        assert_eq!(frame.len(), 42);
        // dst = victim MAC
        assert_eq!(&frame[0..6], &dst);
        // src = sender MAC
        assert_eq!(&frame[6..12], &sender);
    }

    #[test]
    fn test_parse_arp_reply() {
        let sender_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let sender_ip = "10.0.0.1".parse().unwrap();
        let target_ip = "10.0.0.2".parse().unwrap();
        let frame = craft_gratuitous_arp(sender_mac, sender_ip, target_ip).unwrap();
        let entry = parse_arp(&frame).unwrap();
        assert_eq!(entry.sender_mac, sender_mac);
        assert_eq!(entry.sender_ip, sender_ip);
        assert!(entry.is_reply);
    }
}
