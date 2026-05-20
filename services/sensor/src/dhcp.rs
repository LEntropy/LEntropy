use anyhow::{Context, Result};
use nac_fingerprint::{identify, FingerprintSignals};
use nac_netproto::dhcp::parse_dhcp_client;
use pnet::datalink::{self, Channel};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// DHCP 스누핑으로 수집된 단말 핑거프린트 정보
#[derive(Debug, Clone)]
pub struct DhcpEvent {
    pub mac_address: String,
    pub hostname: Option<String>,
    pub os_family: Option<String>,
    pub os_version: Option<String>,
    pub device_type: Option<String>,
    pub vendor: Option<String>,
}

/// 지정된 인터페이스에서 DHCP 클라이언트 패킷(port 67)을 수신해 채널로 전송.
/// pnet datalink 채널을 사용하므로 spawn_blocking으로 실행해야 함.
pub fn snoop(iface_name: String, tx: mpsc::Sender<DhcpEvent>) -> Result<()> {
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
        Err(e) => anyhow::bail!("failed to open DHCP channel on {iface_name}: {e}"),
    };

    info!(interface = %iface_name, "DHCP snooper started");

    loop {
        match rx.next() {
            Ok(frame) => {
                let Some(eth) = EthernetPacket::new(frame) else {
                    continue;
                };
                if eth.get_ethertype() != EtherTypes::Ipv4 {
                    continue;
                }
                let Some(ip) = Ipv4Packet::new(eth.payload()) else {
                    continue;
                };
                if ip.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
                    continue;
                }
                let Some(udp) = UdpPacket::new(ip.payload()) else {
                    continue;
                };
                // DHCP 클라이언트 → 서버: dst port 67
                if udp.get_destination() != 67 {
                    continue;
                }

                let dhcp_payload = udp.payload();
                let pkt = match parse_dhcp_client(dhcp_payload) {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                // DISCOVER(1) / REQUEST(3)만 처리
                if pkt.msg_type != 1 && pkt.msg_type != 3 {
                    continue;
                }

                let mac = format_mac(pkt.client_mac);

                // OUI (상위 3바이트)
                let oui = format!(
                    "{:02X}{:02X}{:02X}",
                    pkt.client_mac[0], pkt.client_mac[1], pkt.client_mac[2]
                );

                let signals = FingerprintSignals {
                    oui: Some(oui),
                    dhcp_prl: pkt.parameter_request_list,
                    ..Default::default()
                };

                let fp = match identify(&signals) {
                    Ok(f) => f,
                    Err(e) => {
                        warn!(mac = %mac, error = %e, "fingerprint failed");
                        continue;
                    }
                };

                debug!(
                    mac = %mac,
                    hostname = ?pkt.hostname,
                    os = ?fp.os_family,
                    "DHCP fingerprint"
                );

                let event = DhcpEvent {
                    mac_address: mac,
                    hostname: pkt.hostname,
                    os_family: fp.os_family,
                    os_version: fp.os_version,
                    device_type: fp.device_type,
                    vendor: fp.vendor,
                };

                if let Err(e) = tx.blocking_send(event) {
                    warn!(error = %e, "DHCP event channel closed — stopping snooper");
                    break;
                }
            }
            Err(e) => {
                warn!(error = %e, "DHCP rx error");
            }
        }
    }

    Ok(())
}

fn format_mac(octets: [u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]
    )
}
