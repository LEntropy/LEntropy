//! ARP spoofing / enforcement implementation using pnet datalink.

use anyhow::{bail, Context, Result};
use nac_netproto::arp::{craft_arp_reply, craft_gratuitous_arp};
use pnet::datalink::{self, Channel, DataLinkSender};
use std::net::Ipv4Addr;
use tracing::debug;

pub struct Spoofer {
    iface_name: String,
    tx: Box<dyn DataLinkSender>,
    mac: [u8; 6],
}

impl Spoofer {
    pub fn new(iface_name: &str) -> Result<Self> {
        let interfaces = datalink::interfaces();
        let iface = interfaces
            .into_iter()
            .find(|i| i.name == iface_name)
            .with_context(|| format!("interface '{iface_name}' not found"))?;

        // Get our own MAC
        let mac_addr = iface
            .mac
            .ok_or_else(|| anyhow::anyhow!("interface {iface_name} has no MAC address"))?;
        let mac: [u8; 6] = mac_addr.octets();

        let config = datalink::Config::default();
        let (tx, _rx) = match datalink::channel(&iface, config) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => bail!("unsupported channel type for {iface_name}"),
            Err(e) => bail!("failed to open channel on {iface_name}: {e}"),
        };

        Ok(Self {
            iface_name: iface_name.to_string(),
            tx,
            mac,
        })
    }

    /// ARP 격리: 피해자와 게이트웨이 모두에게 enforcement_mac으로 독살
    ///
    /// - 피해자에게 unicast: "게이트웨이 IP = enforcement_mac"
    /// - 게이트웨이에게 unicast: "피해자 IP = enforcement_mac"
    ///   (broadcast 대신 unicast를 사용해 LAN 전체 ARP 캐시 오염 방지)
    pub fn quarantine(
        &mut self,
        victim_ip: Ipv4Addr,
        victim_mac: [u8; 6],
        gateway_ip: Ipv4Addr,
    ) -> Result<()> {
        let my_mac = self.mac;

        // 피해자에게 unicast: gateway_ip가 enforcement_mac 인척
        let frame_to_victim =
            craft_arp_reply(victim_mac, my_mac, gateway_ip, victim_mac, victim_ip)?;
        self.send_frame(&frame_to_victim)?;

        debug!(
            iface = %self.iface_name,
            victim_ip = %victim_ip,
            gateway_ip = %gateway_ip,
            "sent ARP poison to victim: gateway_ip -> enforcement_mac"
        );

        // 게이트웨이에게 unicast: victim_ip가 enforcement_mac 인척
        // broadcast를 쓰면 LAN 전체 ARP 캐시가 오염되어 네트워크 불안정 발생
        let gw_mac = arp_mac_lookup(gateway_ip).unwrap_or([0xff; 6]);
        let frame_to_gw = craft_arp_reply(gw_mac, my_mac, victim_ip, gw_mac, gateway_ip)?;
        self.send_frame(&frame_to_gw)?;

        debug!(
            iface = %self.iface_name,
            victim_ip = %victim_ip,
            gateway_ip = %gateway_ip,
            gw_mac_known = gw_mac != [0xff; 6],
            "sent ARP poison to gateway: victim_ip -> enforcement_mac"
        );

        Ok(())
    }

    /// ARP 차단: 피해자와 게이트웨이 모두에게 enforcement_mac으로 독살 (quarantine과 동일)
    ///
    /// 트래픽을 Pi를 통해 우회시킨 뒤 nft blocked_macs 세트에서 전부 DROP한다.
    pub fn block(
        &mut self,
        victim_ip: Ipv4Addr,
        victim_mac: [u8; 6],
        gateway_ip: Ipv4Addr,
    ) -> Result<()> {
        let my_mac = self.mac;

        // 피해자에게 unicast: gateway_ip가 enforcement_mac 인척
        let frame_to_victim =
            craft_arp_reply(victim_mac, my_mac, gateway_ip, victim_mac, victim_ip)?;
        self.send_frame(&frame_to_victim)?;

        // 게이트웨이에게 unicast: victim_ip가 enforcement_mac 인척
        let gw_mac = arp_mac_lookup(gateway_ip).unwrap_or([0xff; 6]);
        let frame_to_gw = craft_arp_reply(gw_mac, my_mac, victim_ip, gw_mac, gateway_ip)?;
        self.send_frame(&frame_to_gw)?;

        debug!(
            iface = %self.iface_name,
            victim_ip = %victim_ip,
            gateway_ip = %gateway_ip,
            gw_mac_known = gw_mac != [0xff; 6],
            "sent ARP poison (block): victim and gateway both redirected to enforcement_mac"
        );

        Ok(())
    }

    /// ARP 복구: 피해자 + 게이트웨이 ARP 캐시 정상화
    ///
    /// 1. 피해자에게 unicast: "gateway_ip는 gateway_mac에 있다" (ARP MITM 복구)
    /// 2. 게이트웨이에게 unicast: "victim_ip는 victim_mac에 있다" (게이트웨이 ARP 복구)
    /// 3. 브로드캐스트 gratuitous ARP: 혹시 이전 broadcast 독살로 오염된 다른 기기 복구
    pub fn allow(
        &mut self,
        victim_ip: Ipv4Addr,
        victim_mac: [u8; 6],
        gateway_ip: Ipv4Addr,
        gateway_mac: [u8; 6],
    ) -> Result<()> {
        // 1. 피해자에게 올바른 게이트웨이 MAC 전송 (ARP MITM 복구)
        let frame_to_victim =
            craft_arp_reply(victim_mac, gateway_mac, gateway_ip, victim_mac, victim_ip)?;
        self.send_frame(&frame_to_victim)?;

        // 2. 게이트웨이에게 unicast: victim_ip → victim_mac 복구
        let frame_to_gw =
            craft_arp_reply(gateway_mac, victim_mac, victim_ip, gateway_mac, gateway_ip)?;
        self.send_frame(&frame_to_gw)?;

        // 3. 브로드캐스트 gratuitous ARP: 이전 broadcast 독살로 오염된 다른 기기 ARP 복구
        let corrective = craft_gratuitous_arp(victim_mac, victim_ip, victim_ip)?;
        self.send_frame(&corrective)?;

        debug!(
            iface = %self.iface_name,
            victim_ip = %victim_ip,
            victim_mac = ?victim_mac,
            gateway_ip = %gateway_ip,
            "sent ARP restore: victim unicast + gateway unicast + broadcast gratuitous"
        );

        Ok(())
    }

    pub fn send_frame(&mut self, frame: &[u8]) -> Result<()> {
        self.tx
            .send_to(frame, None)
            .with_context(|| "failed to send ARP frame")?
            .map_err(|e| anyhow::anyhow!("send_to error: {e}"))?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn my_mac(&self) -> [u8; 6] {
        self.mac
    }
}

/// /proc/net/arp에서 IP에 해당하는 MAC을 조회.
/// 게이트웨이에게 unicast ARP를 보낼 때 사용.
fn arp_mac_lookup(ip: Ipv4Addr) -> Option<[u8; 6]> {
    let content = std::fs::read_to_string("/proc/net/arp").ok()?;
    let ip_str = ip.to_string();
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 && parts[0] == ip_str && parts[3] != "00:00:00:00:00:00" {
            let bytes: Vec<u8> = parts[3]
                .split(':')
                .filter_map(|h| u8::from_str_radix(h, 16).ok())
                .collect();
            if bytes.len() == 6 {
                let mut arr = [0u8; 6];
                arr.copy_from_slice(&bytes);
                return Some(arr);
            }
        }
    }
    None
}
