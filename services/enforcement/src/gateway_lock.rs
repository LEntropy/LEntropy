//! Gateway Lock: 게이트웨이 MAC 주소 통제.
//!
//! 공격자가 ARP 스푸핑으로 게이트웨이 IP를 탈취하는 것을 방지하기 위해
//! enforcement 노드가 주기적으로 올바른 게이트웨이 MAC을 브로드캐스트한다.

use anyhow::{Context, Result};
use nac_netproto::arp::craft_gratuitous_arp;
use pnet::datalink::{self, Channel};
use std::net::Ipv4Addr;
use tracing::info;

#[allow(dead_code)]
pub struct GatewayLock {
    iface_name: String,
    gateway_ip: Ipv4Addr,
    gateway_mac: [u8; 6],
}

impl GatewayLock {
    #[allow(dead_code)]
    pub fn new(iface_name: String, gateway_ip: Ipv4Addr, gateway_mac: [u8; 6]) -> Self {
        Self {
            iface_name,
            gateway_ip,
            gateway_mac,
        }
    }

    /// 게이트웨이의 올바른 ARP 정보를 네트워크에 브로드캐스트.
    /// 공격자의 ARP 스푸핑 시도를 덮어쓴다.
    #[allow(dead_code)]
    pub fn announce(&self) -> Result<()> {
        let interfaces = datalink::interfaces();
        let iface = interfaces
            .into_iter()
            .find(|i| i.name == self.iface_name)
            .with_context(|| format!("interface '{}' not found", self.iface_name))?;

        let config = datalink::Config::default();
        let (mut tx, _) = match datalink::channel(&iface, config) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => anyhow::bail!("unsupported channel"),
            Err(e) => anyhow::bail!("channel error: {e}"),
        };

        let frame = craft_gratuitous_arp(self.gateway_mac, self.gateway_ip, self.gateway_ip)?;

        match tx.send_to(&frame, None) {
            Some(Ok(())) => {
                info!(
                    gw_ip = %self.gateway_ip,
                    "gateway lock ARP announced"
                );
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
    fn test_gateway_lock_creation() {
        let lock = GatewayLock::new(
            "eth0".to_string(),
            "192.168.1.1".parse().unwrap(),
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        );
        assert_eq!(lock.gateway_ip, "192.168.1.1".parse::<Ipv4Addr>().unwrap());
    }
}
