use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::Packet;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// ARP 스누핑으로 수집된 단말 정보
#[derive(Debug, Clone)]
pub struct ArpEvent {
    pub mac_address: String,
    pub ip_address: Ipv4Addr,
    pub interface: String,
    pub _is_gratuitous: bool,
}

/// 지정된 인터페이스에서 ARP 패킷을 수신해 채널로 전송
pub fn snoop(iface_name: String, tx: mpsc::Sender<ArpEvent>) -> Result<()> {
    let interfaces = datalink::interfaces();
    let iface = interfaces
        .into_iter()
        .find(|i| i.name == iface_name)
        .with_context(|| format!("interface '{iface_name}' not found"))?;

    let config = datalink::Config {
        promiscuous: true,
        ..datalink::Config::default()
    };

    let (_, mut rx) = match datalink::channel(&iface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => anyhow::bail!("unsupported channel type for {iface_name}"),
        Err(e) => anyhow::bail!("failed to open channel on {iface_name}: {e}"),
    };

    info!(interface = %iface_name, "ARP snooping started");

    loop {
        match rx.next() {
            Ok(frame) => {
                let Some(eth) = EthernetPacket::new(frame) else {
                    continue;
                };
                if eth.get_ethertype() != EtherTypes::Arp {
                    continue;
                }
                let Some(arp) = ArpPacket::new(eth.payload()) else {
                    continue;
                };

                let mac = format_mac(arp.get_sender_hw_addr().octets());
                let ip = arp.get_sender_proto_addr();

                // 0.0.0.0은 ARP probe — 탐지하되 기록만 함
                if ip == Ipv4Addr::UNSPECIFIED {
                    debug!(%mac, "ARP probe (IP=0.0.0.0) — skipping");
                    continue;
                }

                let is_gratuitous = arp.get_sender_proto_addr() == arp.get_target_proto_addr();

                let event = ArpEvent {
                    mac_address: mac.clone(),
                    ip_address: ip,
                    interface: iface_name.clone(),
                    _is_gratuitous: is_gratuitous,
                };

                debug!(mac = %mac, ip = %ip, gratuitous = is_gratuitous, "ARP event");

                if let Err(e) = tx.blocking_send(event) {
                    warn!(error = %e, "ARP event channel closed — stopping snooper");
                    break;
                }
            }
            Err(e) => {
                warn!(error = %e, "ARP rx error");
            }
        }
    }

    Ok(())
}

/// MAC 바이트 배열을 "AA:BB:CC:DD:EE:FF" 형태로 변환
fn format_mac(octets: [u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]
    )
}

/// 스캔할 인터페이스 목록 반환 (루프백/가상 인터페이스 제외)
pub fn list_physical_interfaces() -> Vec<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .filter(|i| {
            !i.is_loopback()
                && i.is_up()
                && !i.name.starts_with("docker")
                && !i.name.starts_with("br-")
                && !i.name.starts_with("veth")
                && !i.ips.is_empty()
        })
        .collect()
}
