//! nftables/iptables 기반 네트워크 차단·격리.
//!
//! 우선순위: nft (Debian Bookworm 기본) → iptables-legacy (구형 커널)
//!
//! nft 사용 시 set 기반으로 MAC을 관리하므로 규칙은 고정,
//! 차단/격리 변경은 set element 추가·삭제만으로 처리한다.
//!
//! nftables 구조:
//!   table inet nac_filter
//!     set blocked_macs      (ether_addr)
//!     set quarantined_macs  (ether_addr)
//!     chain nac_forward     (hook forward, priority -100)
//!       ether saddr @blocked_macs      → drop
//!       ether saddr @quarantined_macs, udp dport 53  → accept
//!       ether saddr @quarantined_macs, tcp dport 8080 → accept
//!       ether saddr @quarantined_macs  → drop
//!     chain nac_input       (hook input, priority -100)
//!       ether saddr @blocked_macs      → drop

use anyhow::Result;
use std::io::Write as _;
use std::process::{Command, Stdio};
use tracing::{debug, info, warn};

const NFT_TABLE: &str = "nac_filter";
const SET_BLOCK: &str = "blocked_macs";
const SET_QUARANTINE: &str = "quarantined_macs";
const SET_BLOCK_IP: &str = "blocked_ips";
const SET_QUARANTINE_IP: &str = "quarantined_ips";
const CAPTIVE_PORT: &str = "8080";
const CAPTIVE_DNS_PORT: &str = "5353";

// iptables-legacy 용 체인 이름
const CHAIN_BLOCK: &str = "NAC_BLOCK";
const CHAIN_QUARANTINE: &str = "NAC_QUARANTINE";

enum Backend {
    Nft,
    IptablesLegacy,
    Unavailable,
}

pub struct IptablesEnforcer {
    backend: Backend,
}

impl IptablesEnforcer {
    pub fn new() -> Self {
        let backend = if cmd_ok("nft", &["--version"]) {
            info!("firewall backend: nft (nftables)");
            Backend::Nft
        } else if cmd_ok("iptables-legacy", &["-L", "-n"]) {
            info!("firewall backend: iptables-legacy");
            Backend::IptablesLegacy
        } else {
            warn!(
                "no supported firewall tool found — network enforcement disabled. \
                Install iptables or nftables."
            );
            Backend::Unavailable
        };
        Self { backend }
    }

    /// 시작 시 NAC 체인·set 초기화
    pub fn setup_chains(&self, management_ips: &[&str]) -> Result<()> {
        match self.backend {
            Backend::Nft => setup_nft(management_ips),
            Backend::IptablesLegacy => setup_ipt_legacy(),
            Backend::Unavailable => Ok(()),
        }
    }

    /// 단말 완전 차단 (denied)
    pub fn block(&self, mac: &str, ip: Option<&str>) -> Result<()> {
        match self.backend {
            Backend::Nft => {
                let m = nft_mac(mac);
                nft_del_elem(SET_QUARANTINE, &m).ok();
                nft_add_elem(SET_BLOCK, &m)?;
                debug!(mac = %m, "nft: added to blocked_macs");
                if let Some(ip) = ip.filter(|s| !s.is_empty() && *s != "0.0.0.0") {
                    nft_del_elem(SET_QUARANTINE_IP, ip).ok();
                    if let Err(e) = nft_add_elem(SET_BLOCK_IP, ip) {
                        warn!(ip, error = %e, "nft: blocked_ips add failed — MAC-only block applied");
                    } else {
                        debug!(ip, "nft: added to blocked_ips");
                    }
                }
                Ok(())
            }
            Backend::IptablesLegacy => ipt_block(mac),
            Backend::Unavailable => Ok(()),
        }
    }

    /// 단말 격리 (quarantined): DNS + Captive Portal만 허용
    pub fn quarantine(&self, mac: &str, ip: Option<&str>) -> Result<()> {
        match self.backend {
            Backend::Nft => {
                let m = nft_mac(mac);
                nft_del_elem(SET_BLOCK, &m).ok();
                nft_add_elem(SET_QUARANTINE, &m)?;
                debug!(mac = %m, "nft: added to quarantined_macs");
                if let Some(ip) = ip.filter(|s| !s.is_empty() && *s != "0.0.0.0") {
                    nft_del_elem(SET_BLOCK_IP, ip).ok();
                    if let Err(e) = nft_add_elem(SET_QUARANTINE_IP, ip) {
                        warn!(ip, error = %e, "nft: quarantined_ips add failed — MAC-only quarantine applied");
                    } else {
                        debug!(ip, "nft: added to quarantined_ips");
                    }
                }
                Ok(())
            }
            Backend::IptablesLegacy => ipt_quarantine(mac),
            Backend::Unavailable => Ok(()),
        }
    }

    /// IP만 모든 set에서 제거 (IP 변경 시 이전 IP 정리용)
    pub fn remove_ip(&self, ip: &str) {
        if let Backend::Nft = self.backend {
            nft_del_elem(SET_BLOCK_IP, ip).ok();
            nft_del_elem(SET_QUARANTINE_IP, ip).ok();
            debug!(ip, "nft: removed stale IP from all sets");
        }
    }

    /// 단말 허용 (allowed): 모든 규칙 제거
    pub fn allow(&self, mac: &str, ip: Option<&str>) -> Result<()> {
        match self.backend {
            Backend::Nft => {
                let m = nft_mac(mac);
                nft_del_elem(SET_BLOCK, &m).ok();
                nft_del_elem(SET_QUARANTINE, &m).ok();
                debug!(mac = %m, "nft: removed from all sets (allowed)");
                if let Some(ip) = ip.filter(|s| !s.is_empty() && *s != "0.0.0.0") {
                    nft_del_elem(SET_BLOCK_IP, ip).ok();
                    nft_del_elem(SET_QUARANTINE_IP, ip).ok();
                    debug!(ip, "nft: removed from IP sets (allowed)");
                }
                Ok(())
            }
            Backend::IptablesLegacy => ipt_allow(mac),
            Backend::Unavailable => Ok(()),
        }
    }
}

// ── nftables 구현 ────────────────────────────────────────────────────────────

fn setup_nft(management_ips: &[&str]) -> Result<()> {
    // ip_forward가 꺼져 있으면 Pi가 패킷을 전달하지 않음 — 항상 강제 활성화
    let _ = Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=1"])
        .output();

    // Management IP 화이트리스트: 설정 시 SSH는 해당 IP만 허용, 미설정 시 전체 허용 (개발 모드)
    let mgmt_elems_line = if management_ips.is_empty() {
        String::new()
    } else {
        format!(
            "add element inet {NFT_TABLE} management_ips {{ {} }}\n",
            management_ips.join(", ")
        )
    };
    // 관리 포트: SSH(22) + 관리자 페이지(3000, 8000, 8001)
    // 차단된 단말이어도 관리자는 접근 가능하도록 drop 규칙보다 먼저 배치
    let mgmt_port_rules = if management_ips.is_empty() {
        // 개발 모드: 모든 IP에서 관리 포트 허용
        format!(
            "add rule inet {t} nac_input tcp dport 22 accept\n\
             add rule inet {t} nac_input tcp dport 3000 accept\n\
             add rule inet {t} nac_input tcp dport 8000 accept\n\
             add rule inet {t} nac_input tcp dport 8001 accept\n",
            t = NFT_TABLE
        )
    } else {
        // 운영 모드: management_ips 에서만 허용
        format!(
            "add rule inet {t} nac_input ip saddr @management_ips tcp dport 22 accept\n\
             add rule inet {t} nac_input ip saddr @management_ips tcp dport 3000 accept\n\
             add rule inet {t} nac_input ip saddr @management_ips tcp dport 8000 accept\n\
             add rule inet {t} nac_input ip saddr @management_ips tcp dport 8001 accept\n",
            t = NFT_TABLE
        )
    };

    // nft -f - 로 전체 ruleset을 원자적으로 적용
    // flush chain → 규칙 리셋, set 내용(기존 차단 MAC/IP)은 유지됨
    let ruleset = format!(
        r#"add table inet {t}
add set inet {t} {sb} {{ type ether_addr; }}
add set inet {t} {sq} {{ type ether_addr; }}
add set inet {t} {sbi} {{ type ipv4_addr; }}
add set inet {t} {sqi} {{ type ipv4_addr; }}
add set inet {t} management_ips {{ type ipv4_addr; }}
add chain inet {t} nac_prerouting {{ type nat hook prerouting priority dstnat; }}
flush chain inet {t} nac_prerouting
add rule inet {t} nac_prerouting ether saddr @{sb} udp dport 53 redirect to :{cdp}
add rule inet {t} nac_prerouting ether saddr @{sb} tcp dport 53 redirect to :{cdp}
add rule inet {t} nac_prerouting ether saddr @{sq} udp dport 53 redirect to :{cdp}
add rule inet {t} nac_prerouting ether saddr @{sq} tcp dport 53 redirect to :{cdp}
add rule inet {t} nac_prerouting ip saddr @{sbi} udp dport 53 redirect to :{cdp}
add rule inet {t} nac_prerouting ip saddr @{sbi} tcp dport 53 redirect to :{cdp}
add rule inet {t} nac_prerouting ip saddr @{sqi} udp dport 53 redirect to :{cdp}
add rule inet {t} nac_prerouting ip saddr @{sqi} tcp dport 53 redirect to :{cdp}
add rule inet {t} nac_prerouting ether saddr @{sb} tcp dport 80 redirect to :{cp}
add rule inet {t} nac_prerouting ether saddr @{sq} tcp dport 80 redirect to :{cp}
add rule inet {t} nac_prerouting ip saddr @{sbi} tcp dport 80 redirect to :{cp}
add rule inet {t} nac_prerouting ip saddr @{sqi} tcp dport 80 redirect to :{cp}
add chain inet {t} nac_forward {{ type filter hook forward priority -100; policy accept; }}
flush chain inet {t} nac_forward
add rule inet {t} nac_forward ether saddr @{sb} drop
add rule inet {t} nac_forward ether saddr @{sq} drop
add rule inet {t} nac_forward ip saddr @{sbi} drop
add rule inet {t} nac_forward ip saddr @{sqi} drop
add chain inet {t} nac_input {{ type filter hook input priority -100; policy accept; }}
flush chain inet {t} nac_input
add rule inet {t} nac_input ct state established,related accept
{mgmt_elems}{mgmt_port_rules}add rule inet {t} nac_input udp dport {cdp} accept
add rule inet {t} nac_input tcp dport {cdp} accept
add rule inet {t} nac_input ether saddr @{sb} tcp dport {cp} accept
add rule inet {t} nac_input ether saddr @{sq} tcp dport {cp} accept
add rule inet {t} nac_input ip saddr @{sbi} tcp dport {cp} accept
add rule inet {t} nac_input ip saddr @{sqi} tcp dport {cp} accept
add rule inet {t} nac_input ether saddr @{sb} drop
add rule inet {t} nac_input ip saddr @{sbi} drop
add table ip {t}_nat
add chain ip {t}_nat nac_postrouting {{ type nat hook postrouting priority srcnat; }}
flush chain ip {t}_nat nac_postrouting
add rule ip {t}_nat nac_postrouting masquerade
"#,
        t = NFT_TABLE,
        sb = SET_BLOCK,
        sq = SET_QUARANTINE,
        sbi = SET_BLOCK_IP,
        sqi = SET_QUARANTINE_IP,
        cp = CAPTIVE_PORT,
        cdp = CAPTIVE_DNS_PORT,
        mgmt_elems = mgmt_elems_line,
        mgmt_port_rules = mgmt_port_rules,
    );

    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()?;

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(ruleset.as_bytes())?;

    let out = child.wait_with_output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("nft setup failed: {}", stderr.trim());
    }

    info!(table = NFT_TABLE, "nftables NAC rules installed");
    Ok(())
}

fn nft_add_elem(set: &str, mac: &str) -> Result<()> {
    let out = Command::new("nft")
        .args([
            "add",
            "element",
            "inet",
            NFT_TABLE,
            set,
            &format!("{{ {} }}", mac),
        ])
        .output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        // "already exists" → 무시
        if !stderr.to_lowercase().contains("exists") {
            anyhow::bail!("nft add element {set} {mac}: {}", stderr.trim());
        }
    }
    Ok(())
}

fn nft_del_elem(set: &str, mac: &str) -> Result<()> {
    let out = Command::new("nft")
        .args([
            "delete",
            "element",
            "inet",
            NFT_TABLE,
            set,
            &format!("{{ {} }}", mac),
        ])
        .output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        // "not found" 류 오류는 무시
        if !stderr.to_lowercase().contains("could not")
            && !stderr.to_lowercase().contains("no element")
        {
            anyhow::bail!("nft delete element {set} {mac}: {}", stderr.trim());
        }
    }
    Ok(())
}

/// nftables MAC 형식: 소문자 콜론 구분 (aa:bb:cc:dd:ee:ff)
fn nft_mac(mac: &str) -> String {
    let clean: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() == 12 {
        (0..6)
            .map(|i| clean[i * 2..i * 2 + 2].to_lowercase())
            .collect::<Vec<_>>()
            .join(":")
    } else {
        mac.to_lowercase()
    }
}

// ── iptables-legacy 폴백 ─────────────────────────────────────────────────────

fn setup_ipt_legacy() -> Result<()> {
    for chain in [CHAIN_BLOCK, CHAIN_QUARANTINE] {
        if !ipt_chain_exists(chain) {
            run_ipt(&["-N", chain])?;
            info!(chain, "iptables-legacy chain created");
        }
    }
    ipt_ensure_jump("FORWARD", CHAIN_BLOCK)?;
    ipt_ensure_jump("FORWARD", CHAIN_QUARANTINE)?;
    ipt_ensure_jump("INPUT", CHAIN_BLOCK)?;
    info!("iptables-legacy NAC chains hooked");
    Ok(())
}

fn ipt_block(mac: &str) -> Result<()> {
    let mac = ipt_mac(mac);
    ipt_remove_quarantine(&mac);
    if !ipt_rule_exists(
        CHAIN_BLOCK,
        &["-m", "mac", "--mac-source", &mac, "-j", "DROP"],
    ) {
        run_ipt(&[
            "-I",
            CHAIN_BLOCK,
            "-m",
            "mac",
            "--mac-source",
            &mac,
            "-j",
            "DROP",
        ])?;
        debug!(mac = %mac, "iptables-legacy block rule added");
    }
    Ok(())
}

fn ipt_quarantine(mac: &str) -> Result<()> {
    let mac = ipt_mac(mac);
    ipt_remove_block(&mac);
    if !ipt_rule_exists(
        CHAIN_QUARANTINE,
        &["-m", "mac", "--mac-source", &mac, "-j", "DROP"],
    ) {
        run_ipt(&[
            "-I",
            CHAIN_QUARANTINE,
            "-m",
            "mac",
            "--mac-source",
            &mac,
            "-p",
            "udp",
            "--dport",
            "53",
            "-j",
            "RETURN",
        ])?;
        run_ipt(&[
            "-I",
            CHAIN_QUARANTINE,
            "-m",
            "mac",
            "--mac-source",
            &mac,
            "-p",
            "tcp",
            "--dport",
            CAPTIVE_PORT,
            "-j",
            "RETURN",
        ])?;
        run_ipt(&[
            "-A",
            CHAIN_QUARANTINE,
            "-m",
            "mac",
            "--mac-source",
            &mac,
            "-j",
            "DROP",
        ])?;
        debug!(mac = %mac, "iptables-legacy quarantine rules added");
    }
    Ok(())
}

fn ipt_allow(mac: &str) -> Result<()> {
    let mac = ipt_mac(mac);
    ipt_remove_block(&mac);
    ipt_remove_quarantine(&mac);
    debug!(mac = %mac, "iptables-legacy rules removed (allowed)");
    Ok(())
}

fn ipt_remove_block(mac: &str) {
    while run_ipt(&[
        "-D",
        CHAIN_BLOCK,
        "-m",
        "mac",
        "--mac-source",
        mac,
        "-j",
        "DROP",
    ])
    .is_ok()
    {}
}

fn ipt_remove_quarantine(mac: &str) {
    for args in [
        vec![
            "-D",
            CHAIN_QUARANTINE,
            "-m",
            "mac",
            "--mac-source",
            mac,
            "-p",
            "udp",
            "--dport",
            "53",
            "-j",
            "RETURN",
        ],
        vec![
            "-D",
            CHAIN_QUARANTINE,
            "-m",
            "mac",
            "--mac-source",
            mac,
            "-p",
            "tcp",
            "--dport",
            CAPTIVE_PORT,
            "-j",
            "RETURN",
        ],
        vec![
            "-D",
            CHAIN_QUARANTINE,
            "-m",
            "mac",
            "--mac-source",
            mac,
            "-j",
            "DROP",
        ],
    ] {
        while run_ipt(&args).is_ok() {}
    }
}

fn ipt_chain_exists(chain: &str) -> bool {
    Command::new("iptables-legacy")
        .args(["-L", chain, "-n"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn ipt_rule_exists(chain: &str, rule: &[&str]) -> bool {
    let mut args = vec!["-C", chain];
    args.extend_from_slice(rule);
    Command::new("iptables-legacy")
        .args(&args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn ipt_ensure_jump(parent: &str, chain: &str) -> Result<()> {
    if !ipt_rule_exists(parent, &["-j", chain]) {
        run_ipt(&["-I", parent, "1", "-j", chain])?;
    }
    Ok(())
}

fn run_ipt(args: &[&str]) -> Result<()> {
    let out = Command::new("iptables-legacy").args(args).output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("iptables-legacy {}: {}", args.join(" "), stderr.trim());
    }
    Ok(())
}

/// iptables-legacy MAC 형식: 대문자 콜론 구분 (AA:BB:CC:DD:EE:FF)
fn ipt_mac(mac: &str) -> String {
    let clean: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() == 12 {
        (0..6)
            .map(|i| clean[i * 2..i * 2 + 2].to_uppercase())
            .collect::<Vec<_>>()
            .join(":")
    } else {
        mac.to_uppercase()
    }
}

// ── 공통 유틸 ────────────────────────────────────────────────────────────────

fn cmd_ok(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
