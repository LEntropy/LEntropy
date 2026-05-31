//! ARP spoofing / enforcement implementation using pnet datalink.

use anyhow::{bail, Context, Result};
use nac_netproto::arp::craft_arp_reply;
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
    /// - 피해자에게: "게이트웨이 IP = enforcement_mac"
    /// - 게이트웨이에게: "피해자 IP = enforcement_mac" (broadcast)
    pub fn quarantine(
        &mut self,
        victim_ip: Ipv4Addr,
        victim_mac: [u8; 6],
        gateway_ip: Ipv4Addr,
    ) -> Result<()> {
        let my_mac = self.mac;

        // 피해자에게 보냄: gateway_ip가 enforcement_mac 인척
        let frame_to_victim =
            craft_arp_reply(victim_mac, my_mac, gateway_ip, victim_mac, victim_ip)?;
        self.send_frame(&frame_to_victim)?;

        debug!(
            iface = %self.iface_name,
            victim_ip = %victim_ip,
            gateway_ip = %gateway_ip,
            "sent ARP poison to victim: gateway_ip -> enforcement_mac"
        );

        // 게이트웨이에게 보냄: victim_ip가 enforcement_mac 인척 (broadcast dst)
        let broadcast = [0xff; 6];
        let frame_to_gw = craft_arp_reply(broadcast, my_mac, victim_ip, broadcast, gateway_ip)?;
        self.send_frame(&frame_to_gw)?;

        debug!(
            iface = %self.iface_name,
            victim_ip = %victim_ip,
            gateway_ip = %gateway_ip,
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

        // 피해자에게 보냄: gateway_ip가 enforcement_mac 인척
        let frame_to_victim =
            craft_arp_reply(victim_mac, my_mac, gateway_ip, victim_mac, victim_ip)?;
        self.send_frame(&frame_to_victim)?;

        // 게이트웨이에게 보냄: victim_ip가 enforcement_mac 인척 (broadcast dst)
        let broadcast = [0xff; 6];
        let frame_to_gw = craft_arp_reply(broadcast, my_mac, victim_ip, broadcast, gateway_ip)?;
        self.send_frame(&frame_to_gw)?;

        debug!(
            iface = %self.iface_name,
            victim_ip = %victim_ip,
            gateway_ip = %gateway_ip,
            "sent ARP poison (block): victim and gateway both redirected to enforcement_mac"
        );

        Ok(())
    }

    /// ARP 복구: 올바른 게이트웨이 MAC으로 ARP 전송
    pub fn allow(
        &mut self,
        victim_ip: Ipv4Addr,
        victim_mac: [u8; 6],
        gateway_ip: Ipv4Addr,
        gateway_mac: [u8; 6],
    ) -> Result<()> {
        // 피해자에게 올바른 게이트웨이 MAC 전송
        let frame = craft_arp_reply(victim_mac, gateway_mac, gateway_ip, victim_mac, victim_ip)?;
        self.send_frame(&frame)?;

        debug!(
            iface = %self.iface_name,
            victim_ip = %victim_ip,
            gateway_ip = %gateway_ip,
            "sent ARP restore to victim"
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
