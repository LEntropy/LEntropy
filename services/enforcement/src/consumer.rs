//! NATS consumer for enforcement commands.

use anyhow::Result;
use async_nats::Client;
use futures_util::StreamExt;
use serde::Deserialize;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info, warn};

use crate::arp_spoof::Spoofer;

pub const SUBJECT: &str = "nac.commands.enforcement";

/// enforcement 명령 페이로드
#[derive(Debug, Clone, Deserialize)]
pub struct EnforcementCommand {
    pub mac_address: String,
    pub ip_address: String,
    pub action: String, // "quarantine" | "block" | "allow"
    pub gateway_ip: String,
    pub gateway_mac: Option<String>,
    #[allow(dead_code)]
    pub vlan_id: Option<u16>,
}

/// hex string "AABBCCDDEEFF" 또는 "AA:BB:CC:DD:EE:FF" → [u8; 6]
fn parse_mac(mac: &str) -> Option<[u8; 6]> {
    let clean: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() != 12 {
        return None;
    }
    let mut bytes = [0u8; 6];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

/// NATS 구독 루프 — enforcement 명령 처리
pub async fn run(nats: Client, spoofer: Arc<Mutex<Option<Spoofer>>>) -> Result<()> {
    let mut sub = nats.subscribe(SUBJECT).await?;
    info!(subject = SUBJECT, "enforcement NATS consumer started");

    while let Some(msg) = sub.next().await {
        let cmd = match serde_json::from_slice::<EnforcementCommand>(&msg.payload) {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "failed to parse enforcement command — skipping");
                continue;
            }
        };

        debug!(
            mac    = %cmd.mac_address,
            ip     = %cmd.ip_address,
            action = %cmd.action,
            "enforcement command received"
        );

        if let Err(e) = execute_command(&cmd, &spoofer) {
            error!(error = %e, mac = %cmd.mac_address, "enforcement command failed");
        }
    }

    info!("enforcement NATS consumer stopped");
    Ok(())
}

fn execute_command(cmd: &EnforcementCommand, spoofer: &Arc<Mutex<Option<Spoofer>>>) -> Result<()> {
    let victim_ip = Ipv4Addr::from_str(&cmd.ip_address)
        .map_err(|e| anyhow::anyhow!("invalid victim IP: {e}"))?;
    let gateway_ip = Ipv4Addr::from_str(&cmd.gateway_ip)
        .map_err(|e| anyhow::anyhow!("invalid gateway IP: {e}"))?;
    let victim_mac = parse_mac(&cmd.mac_address)
        .ok_or_else(|| anyhow::anyhow!("invalid victim MAC: {}", cmd.mac_address))?;

    let mut guard = spoofer.lock().unwrap();
    let spoofer_ref = match guard.as_mut() {
        Some(s) => s,
        None => {
            warn!("no spoofer available — enforcement action skipped");
            return Ok(());
        }
    };

    match cmd.action.as_str() {
        "quarantine" => {
            spoofer_ref.quarantine(victim_ip, victim_mac, gateway_ip)?;
            info!(mac = %cmd.mac_address, ip = %victim_ip, "quarantine ARP poison sent");
        }
        "block" => {
            spoofer_ref.block(victim_ip, victim_mac)?;
            info!(mac = %cmd.mac_address, ip = %victim_ip, "block ARP sent");
        }
        "allow" => {
            let gw_mac = cmd
                .gateway_mac
                .as_deref()
                .and_then(parse_mac)
                .unwrap_or([0xff; 6]); // fallback to broadcast if unknown
            spoofer_ref.allow(victim_ip, victim_mac, gateway_ip, gw_mac)?;
            info!(mac = %cmd.mac_address, ip = %victim_ip, "allow ARP restore sent");
        }
        unknown => {
            warn!(action = %unknown, "unknown enforcement action — ignoring");
        }
    }

    Ok(())
}
