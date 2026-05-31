//! iptables 기반 네트워크 차단 / 격리 (primary enforcement).
//!
//! 두 개의 커스텀 체인을 관리한다:
//! - NAC_BLOCK:       차단(denied) 단말 → DROP
//! - NAC_QUARANTINE:  격리(quarantined) 단말 → DNS·Captive Portal만 허용, 나머지 DROP

use anyhow::Result;
use std::process::Command;
use tracing::{debug, info, warn};

const CHAIN_BLOCK: &str = "NAC_BLOCK";
const CHAIN_QUARANTINE: &str = "NAC_QUARANTINE";
const CAPTIVE_PORTAL_PORT: &str = "8080";

pub struct IptablesEnforcer {
    available: bool,
}

impl IptablesEnforcer {
    /// iptables 사용 가능 여부 탐지 후 초기화
    pub fn new() -> Self {
        let available = Command::new("iptables")
            .args(["-L", "-n", "--line-numbers"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !available {
            warn!("iptables not available or insufficient permissions — iptables enforcement disabled");
        }
        Self { available }
    }

    /// 시작 시 NAC 전용 체인 생성 및 훅 연결
    pub fn setup_chains(&self) -> Result<()> {
        if !self.available {
            return Ok(());
        }
        // 체인 생성 (이미 있으면 무시)
        for chain in [CHAIN_BLOCK, CHAIN_QUARANTINE] {
            if !chain_exists(chain) {
                run_ipt(&["-N", chain])?;
                info!(chain = chain, "created iptables chain");
            }
        }
        // FORWARD와 INPUT 훅에 삽입 (순서: BLOCK → QUARANTINE)
        ensure_jump("FORWARD", CHAIN_BLOCK)?;
        ensure_jump("FORWARD", CHAIN_QUARANTINE)?;
        ensure_jump("INPUT", CHAIN_BLOCK)?;
        info!("iptables NAC chains hooked into FORWARD/INPUT");
        Ok(())
    }

    /// 단말 완전 차단 (denied)
    pub fn block(&self, mac: &str) -> Result<()> {
        if !self.available {
            return Ok(());
        }
        let mac = normalize_mac(mac);
        // quarantine 규칙 먼저 제거
        self.remove_quarantine_rules(&mac);
        // 이미 block 규칙이 있으면 중복 추가 안 함
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
            debug!(mac = %mac, "iptables block rule added");
        }
        Ok(())
    }

    /// 단말 격리 (quarantined): DNS + Captive Portal만 허용
    pub fn quarantine(&self, mac: &str) -> Result<()> {
        if !self.available {
            return Ok(());
        }
        let mac = normalize_mac(mac);
        // block 규칙 먼저 제거
        self.remove_block_rule(&mac);
        // 격리 규칙이 이미 있으면 건너뜀
        if ipt_rule_exists(
            CHAIN_QUARANTINE,
            &["-m", "mac", "--mac-source", &mac, "-j", "DROP"],
        ) {
            return Ok(());
        }
        // DNS (UDP 53) 허용
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
        // Captive Portal (TCP 8080) 허용
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
            CAPTIVE_PORTAL_PORT,
            "-j",
            "RETURN",
        ])?;
        // 나머지 차단 (APPEND — RETURN 규칙 뒤에)
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
        debug!(mac = %mac, "iptables quarantine rules added");
        Ok(())
    }

    /// 단말 허용 (allowed): 모든 규칙 제거
    pub fn allow(&self, mac: &str) -> Result<()> {
        if !self.available {
            return Ok(());
        }
        let mac = normalize_mac(mac);
        self.remove_block_rule(&mac);
        self.remove_quarantine_rules(&mac);
        debug!(mac = %mac, "iptables rules removed (allowed)");
        Ok(())
    }

    fn remove_block_rule(&self, mac: &str) {
        // 존재할 수 있는 만큼 반복 삭제
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

    fn remove_quarantine_rules(&self, mac: &str) {
        // DNS RETURN 규칙
        while run_ipt(&[
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
        ])
        .is_ok()
        {}
        // Captive Portal RETURN 규칙
        while run_ipt(&[
            "-D",
            CHAIN_QUARANTINE,
            "-m",
            "mac",
            "--mac-source",
            mac,
            "-p",
            "tcp",
            "--dport",
            CAPTIVE_PORTAL_PORT,
            "-j",
            "RETURN",
        ])
        .is_ok()
        {}
        // DROP 규칙
        while run_ipt(&[
            "-D",
            CHAIN_QUARANTINE,
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
}

// ── helpers ─────────────────────────────────────────────────────────────────

fn normalize_mac(mac: &str) -> String {
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

fn chain_exists(chain: &str) -> bool {
    Command::new("iptables")
        .args(["-L", chain, "-n"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn ipt_rule_exists(chain: &str, rule_args: &[&str]) -> bool {
    let mut args = vec!["-C", chain];
    args.extend_from_slice(rule_args);
    Command::new("iptables")
        .args(&args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn ensure_jump(parent: &str, chain: &str) -> Result<()> {
    if !ipt_rule_exists(parent, &["-j", chain]) {
        run_ipt(&["-I", parent, "1", "-j", chain])?;
    }
    Ok(())
}

fn run_ipt(args: &[&str]) -> Result<()> {
    let out = Command::new("iptables").args(args).output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("iptables {}: {}", args.join(" "), stderr.trim());
    }
    Ok(())
}
