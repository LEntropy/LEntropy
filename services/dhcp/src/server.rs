//! DHCPv4 서버 — dhcproto 기반 UDP 67 리스너.

use anyhow::Result;
use dhcproto::v4::{Decodable, DhcpOption, Encodable, Message, MessageType, OptionCode};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::pool::LeasePool;

pub struct DhcpServer {
    pub pool: LeasePool,
    pub server_ip: std::net::Ipv4Addr,
    pub nats: async_nats::Client,
}

impl DhcpServer {
    pub async fn run(self, bind_addr: &str) -> Result<()> {
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
        socket.set_broadcast(true)?;
        info!(bind_addr, "DHCPv4 server listening");

        let server = Arc::new(self);
        let mut buf = vec![0u8; 4096];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, peer)) => {
                    let data = buf[..n].to_vec();
                    let srv = server.clone();
                    let sock = socket.clone();
                    tokio::spawn(async move {
                        if let Err(e) = srv.handle(&data, peer, &sock).await {
                            warn!(error = %e, peer = %peer, "DHCP handle error");
                        }
                    });
                }
                Err(e) => warn!(error = %e, "DHCP recv error"),
            }
        }
    }

    async fn handle(
        &self,
        data: &[u8],
        peer: std::net::SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        let msg = Message::from_bytes(data)?;
        let msg_type = msg
            .opts()
            .msg_type()
            .ok_or_else(|| anyhow::anyhow!("no msg type"))?;

        debug!(msg_type = ?msg_type, "DHCP message received");

        let response = match msg_type {
            MessageType::Discover => self.handle_discover(&msg)?,
            MessageType::Request => self.handle_request(&msg)?,
            _ => return Ok(()),
        };

        let encoded = response.to_vec()?;
        socket.send_to(&encoded, peer).await?;

        // NATS에 DHCP 바인딩 이벤트 발행
        let yiaddr = response.yiaddr();
        if !yiaddr.is_unspecified() {
            let ip = yiaddr;
            let mac = format_mac(msg.chaddr());
            let event = serde_json::json!({
                "event": "dhcp_binding",
                "mac": mac,
                "ip": ip.to_string(),
                "msg_type": format!("{msg_type:?}"),
            });
            let _ = self
                .nats
                .publish("nac.events.dhcp", event.to_string().into())
                .await;
        }

        Ok(())
    }

    fn handle_discover(&self, msg: &Message) -> Result<Message> {
        let mac = msg.chaddr();
        let offered_ip = self.pool.get_or_allocate(mac);

        let mut resp = Message::default();
        resp.set_opcode(dhcproto::v4::Opcode::BootReply)
            .set_htype(msg.htype())
            .set_hops(0)
            .set_xid(msg.xid())
            .set_flags(msg.flags())
            .set_yiaddr(offered_ip)
            .set_siaddr(self.server_ip)
            .set_giaddr(msg.giaddr())
            .set_chaddr(mac);

        resp.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Offer));
        resp.opts_mut()
            .insert(DhcpOption::ServerIdentifier(self.server_ip));
        resp.opts_mut().insert(DhcpOption::AddressLeaseTime(86400));
        resp.opts_mut()
            .insert(DhcpOption::SubnetMask(self.pool.subnet_mask));
        resp.opts_mut()
            .insert(DhcpOption::Router(vec![self.pool.gateway]));

        Ok(resp)
    }

    fn handle_request(&self, msg: &Message) -> Result<Message> {
        let mac = msg.chaddr();
        let requested_ip = msg
            .opts()
            .get(OptionCode::RequestedIpAddress)
            .and_then(|o| {
                if let DhcpOption::RequestedIpAddress(ip) = o {
                    Some(*ip)
                } else {
                    None
                }
            })
            .unwrap_or_else(|| self.pool.get_or_allocate(mac));

        let mut resp = Message::default();
        resp.set_opcode(dhcproto::v4::Opcode::BootReply)
            .set_htype(msg.htype())
            .set_hops(0)
            .set_xid(msg.xid())
            .set_flags(msg.flags())
            .set_yiaddr(requested_ip)
            .set_siaddr(self.server_ip)
            .set_giaddr(msg.giaddr())
            .set_chaddr(mac);

        resp.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Ack));
        resp.opts_mut()
            .insert(DhcpOption::ServerIdentifier(self.server_ip));
        resp.opts_mut().insert(DhcpOption::AddressLeaseTime(86400));
        resp.opts_mut()
            .insert(DhcpOption::SubnetMask(self.pool.subnet_mask));
        resp.opts_mut()
            .insert(DhcpOption::Router(vec![self.pool.gateway]));

        Ok(resp)
    }
}

fn format_mac(chaddr: &[u8]) -> String {
    chaddr[..6.min(chaddr.len())]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
