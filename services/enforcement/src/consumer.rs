//! NATS consumer for enforcement commands.

use anyhow::Result;
use async_nats::Client;
use futures_util::StreamExt;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info, warn};

use crate::arp_spoof::Spoofer;
use crate::iptables::IptablesEnforcer;

pub const SUBJECT: &str = "nac.commands.enforcement";

/// enforcement 명령 페이로드
#[derive(Debug, Clone, Deserialize)]
pub struct EnforcementCommand {
    pub mac_address: String,
    pub ip_address: String,
    pub action: String, // "allowed"/"allow" | "denied"/"block" | "quarantined"/"quarantine"
    pub gateway_ip: String,
    pub gateway_mac: Option<String>,
    #[allow(dead_code)]
    pub vlan_id: Option<u16>,
}

/// 격리·차단 중인 단말 상태 (ARP 재독살 루프용)
#[derive(Debug, Clone)]
pub struct QuarantineEntry {
    pub victim_ip: Ipv4Addr,
    pub victim_mac: [u8; 6],
    pub gateway_ip: Ipv4Addr,
    pub action: NacAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NacAction {
    Block,
    Quarantine,
}

pub type QuarantineState = Arc<Mutex<HashMap<String, QuarantineEntry>>>;

/// NATS 구독 루프 — enforcement 명령 처리
pub async fn run(
    nats: Client,
    spoofer: Arc<Mutex<Option<Spoofer>>>,
    ipt: Arc<IptablesEnforcer>,
    state: QuarantineState,
) -> Result<()> {
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

        let result = if is_allow_action(&cmd.action) {
            execute_allow(&cmd, &spoofer, &ipt, &state)
        } else {
            execute_command(&cmd, &spoofer, &ipt, &state)
        };
        if let Err(e) = result {
            error!(error = %e, mac = %cmd.mac_address, "enforcement command failed");
        }
    }

    info!("enforcement NATS consumer stopped");
    Ok(())
}

fn execute_command(
    cmd: &EnforcementCommand,
    spoofer: &Arc<Mutex<Option<Spoofer>>>,
    ipt: &IptablesEnforcer,
    state: &QuarantineState,
) -> Result<()> {
    let action = map_action(&cmd.action);

    // ── IP 변경 시 이전 IP를 nftables set에서 제거 ───────────────────────
    if !cmd.ip_address.is_empty() && cmd.ip_address != "0.0.0.0" {
        let old_ip = state
            .lock()
            .unwrap()
            .get(&cmd.mac_address.to_lowercase())
            .map(|e| e.victim_ip);
        if let Some(old_ip) = old_ip {
            let new_ip_parsed = cmd.ip_address.parse::<std::net::Ipv4Addr>().ok();
            if let Some(new_ip) = new_ip_parsed {
                if old_ip != new_ip {
                    let old_str = old_ip.to_string();
                    ipt.remove_ip(&old_str);
                    info!(mac = %cmd.mac_address, old_ip = %old_ip, new_ip = %new_ip, "IP changed — old IP removed from sets");
                }
            }
        }
    }

    // ── iptables (primary enforcement) ──────────────────────────────────────
    let ip_opt = if cmd.ip_address.is_empty() || cmd.ip_address == "0.0.0.0" {
        None
    } else {
        Some(cmd.ip_address.as_str())
    };
    match action {
        NacAction::Block => ipt.block(&cmd.mac_address, ip_opt)?,
        NacAction::Quarantine => ipt.quarantine(&cmd.mac_address, ip_opt)?,
    };

    // ── ARP spoofer (Layer-2 secondary) ─────────────────────────────────────
    // IP가 없으면 ARP 스푸핑 불가 — 경고 후 건너뜀
    if cmd.ip_address.is_empty() || cmd.ip_address == "0.0.0.0" {
        debug!(mac = %cmd.mac_address, "no IP address — ARP enforcement skipped");
        // 상태에서 제거 (있던 경우)
        if matches!(action, NacAction::Block | NacAction::Quarantine) {
        } else {
            state
                .lock()
                .unwrap()
                .remove(&cmd.mac_address.to_lowercase());
        }
        return Ok(());
    }

    let victim_ip = match Ipv4Addr::from_str(&cmd.ip_address) {
        Ok(ip) => ip,
        Err(_) => {
            warn!(ip = %cmd.ip_address, "invalid victim IP — ARP enforcement skipped");
            return Ok(());
        }
    };

    let victim_mac = match parse_mac(&cmd.mac_address) {
        Some(m) => m,
        None => {
            warn!(mac = %cmd.mac_address, "invalid victim MAC — ARP enforcement skipped");
            return Ok(());
        }
    };

    // 게이트웨이 IP: 명령에 있으면 사용, 없으면 라우팅 테이블에서 자동 탐지
    let gateway_ip = if !cmd.gateway_ip.is_empty() && cmd.gateway_ip != "0.0.0.0" {
        Ipv4Addr::from_str(&cmd.gateway_ip).ok()
    } else {
        detect_default_gateway()
    };

    let gateway_ip = match gateway_ip {
        Some(ip) => ip,
        None => {
            warn!("cannot determine gateway IP — ARP enforcement skipped");
            return Ok(());
        }
    };

    let mut guard = spoofer.lock().unwrap();
    let spoofer_ref = match guard.as_mut() {
        Some(s) => s,
        None => {
            debug!("no spoofer — ARP enforcement skipped");
            // 상태는 여전히 업데이트 (iptables 기반 재확인용)
            update_state(state, cmd, victim_ip, victim_mac, gateway_ip, &action);
            return Ok(());
        }
    };

    match action {
        NacAction::Block => {
            spoofer_ref.block(victim_ip, victim_mac, gateway_ip)?;
            info!(mac = %cmd.mac_address, ip = %victim_ip, "ARP block sent");
        }
        NacAction::Quarantine => {
            spoofer_ref.quarantine(victim_ip, victim_mac, gateway_ip)?;
            info!(mac = %cmd.mac_address, ip = %victim_ip, "ARP quarantine poison sent");
        }
    }

    update_state(state, cmd, victim_ip, victim_mac, gateway_ip, &action);
    Ok(())
}

fn update_state(
    state: &QuarantineState,
    cmd: &EnforcementCommand,
    victim_ip: Ipv4Addr,
    victim_mac: [u8; 6],
    gateway_ip: Ipv4Addr,
    action: &NacAction,
) {
    let mut s = state.lock().unwrap();
    s.insert(
        cmd.mac_address.to_lowercase(),
        QuarantineEntry {
            victim_ip,
            victim_mac,
            gateway_ip,
            action: action.clone(),
        },
    );
}

fn is_allow_action(action: &str) -> bool {
    matches!(action, "allowed" | "allow")
}

/// policy-manager의 status 문자열 및 enforcement 액션 문자열 모두 처리
fn map_action(action: &str) -> NacAction {
    match action {
        "denied" | "block" | "blocked" => NacAction::Block,
        "quarantined" | "quarantine" => NacAction::Quarantine,
        // "allowed" / "allow" 은 호출자가 state 제거 처리
        _ => NacAction::Quarantine, // unknown → 격리 (안전한 기본값)
    }
}

/// allow 명령 처리 (별도 — state에서 제거 + ARP 복구)
///
/// QuarantineEntry가 없어도 (컨테이너 재시작 등) cmd 필드에서 복구 정보를 추출한다.
pub fn execute_allow(
    cmd: &EnforcementCommand,
    spoofer: &Arc<Mutex<Option<Spoofer>>>,
    ipt: &IptablesEnforcer,
    state: &QuarantineState,
) -> Result<()> {
    let ip_opt = if cmd.ip_address.is_empty() || cmd.ip_address == "0.0.0.0" {
        None
    } else {
        Some(cmd.ip_address.as_str())
    };
    ipt.allow(&cmd.mac_address, ip_opt)?;

    let entry = state
        .lock()
        .unwrap()
        .remove(&cmd.mac_address.to_lowercase());

    // victim_mac / victim_ip: state entry 우선, 없으면 cmd에서 파싱 (재시작 후 복구 대응)
    let victim_mac = entry
        .as_ref()
        .map(|e| e.victim_mac)
        .or_else(|| parse_mac(&cmd.mac_address));

    let victim_ip = entry
        .as_ref()
        .map(|e| e.victim_ip)
        .or_else(|| Ipv4Addr::from_str(&cmd.ip_address).ok());

    if let (Some(victim_mac), Some(victim_ip)) = (victim_mac, victim_ip) {
        let gateway_ip = entry
            .as_ref()
            .map(|e| e.gateway_ip)
            .or_else(detect_default_gateway)
            .unwrap_or(Ipv4Addr::new(0, 0, 0, 0));

        let gateway_mac = cmd
            .gateway_mac
            .as_deref()
            .and_then(parse_mac)
            .or_else(|| get_arp_mac(gateway_ip))
            .unwrap_or([0xff; 6]);

        let mut guard = spoofer.lock().unwrap();
        if let Some(s) = guard.as_mut() {
            s.allow(victim_ip, victim_mac, gateway_ip, gateway_mac)?;
            info!(
                mac = %cmd.mac_address,
                ip  = %victim_ip,
                had_state = entry.is_some(),
                "ARP restore sent (allowed)"
            );
        }
    } else {
        debug!(mac = %cmd.mac_address, "allow: no IP/MAC info — ARP restore skipped");
    }

    Ok(())
}

// ── 게이트웨이 자동 탐지 ────────────────────────────────────────────────────

/// /proc/net/route에서 기본 게이트웨이 IP 탐지
pub fn detect_default_gateway() -> Option<Ipv4Addr> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        // 파싱 실패 시 해당 줄만 건너뜀 (? 대신 continue)
        let dest = match u32::from_str_radix(parts[1], 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if dest == 0 {
            // 기본 경로 (Destination == 0.0.0.0)
            let gw_hex = match u32::from_str_radix(parts[2], 16) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let gw_bytes = gw_hex.to_le_bytes(); // little-endian
            return Some(Ipv4Addr::from(gw_bytes));
        }
    }
    None
}

/// /proc/net/arp에서 ARP 캐시 조회
pub fn get_arp_mac(ip: Ipv4Addr) -> Option<[u8; 6]> {
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

// ── hex parse ───────────────────────────────────────────────────────────────

pub fn parse_mac(mac: &str) -> Option<[u8; 6]> {
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
