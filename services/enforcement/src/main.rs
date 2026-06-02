//! enforcement: Policy Enforcement Agent
//!
//! 두 가지 메커니즘으로 차단·격리를 실행한다:
//! 1. iptables (primary)  — NAC_BLOCK / NAC_QUARANTINE 체인으로 커널 레벨 차단
//! 2. ARP spoofing (secondary) — L2 레벨 ARP 독살로 트래픽 차단

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing_subscriber::{fmt, EnvFilter};

mod arp_spoof;
mod consumer;
mod gateway_lock;
mod iptables;
mod ipv6_block;
mod snmp_port;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!(service = "enforcement", "starting up");

    let config = nac_config::AppConfig::load()?;

    // NATS 연결
    let nats = async_nats::connect(&config.nats_url).await?;
    tracing::info!(nats_url = %config.nats_url, "NATS connected");

    // ── iptables 초기화 ─────────────────────────────────────────────────────
    let management_ips_raw = config.management_ips.clone().unwrap_or_default();
    let management_ips: Vec<&str> = management_ips_raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if management_ips.is_empty() {
        tracing::warn!("MANAGEMENT_IPS not set — SSH open to all (dev mode)");
    } else {
        tracing::info!(ips = ?management_ips, "SSH restricted to management IPs");
    }

    let ipt = Arc::new(iptables::IptablesEnforcer::new());
    if let Err(e) = ipt.setup_chains(&management_ips) {
        tracing::warn!(error = %e, "iptables chain setup failed — enforcement may be limited");
    }

    // ── ARP Spoofer 초기화 (물리 인터페이스 자동 탐지) ─────────────────────
    let spoofer: Arc<Mutex<Option<arp_spoof::Spoofer>>> = {
        use pnet::datalink;
        let interfaces: Vec<_> = datalink::interfaces()
            .into_iter()
            .filter(|i| {
                !i.is_loopback()
                    && i.is_up()
                    && !i.name.starts_with("docker")
                    && !i.name.starts_with("br-")
                    && !i.name.starts_with("veth")
                    && !i.ips.is_empty()
                    && i.mac.is_some()
            })
            .collect();

        if interfaces.is_empty() {
            tracing::warn!("no suitable interfaces found — ARP enforcement disabled");
            Arc::new(Mutex::new(None))
        } else {
            let iface = &interfaces[0];
            tracing::info!(interface = %iface.name, "initializing ARP spoofer");
            match arp_spoof::Spoofer::new(&iface.name) {
                Ok(s) => {
                    tracing::info!(interface = %iface.name, "ARP spoofer initialized");
                    Arc::new(Mutex::new(Some(s)))
                }
                Err(e) => {
                    tracing::warn!(error = %e, "ARP spoofer init failed — ARP enforcement disabled");
                    Arc::new(Mutex::new(None))
                }
            }
        }
    };

    // ── 격리 상태 공유 (재독살 루프 + consumer 공유) ─────────────────────
    let quarantine_state: consumer::QuarantineState = Arc::new(Mutex::new(HashMap::new()));

    // ── NATS consumer 태스크 ────────────────────────────────────────────────
    {
        let consumer_nats = nats.clone();
        let consumer_spoofer = spoofer.clone();
        let consumer_ipt = ipt.clone();
        let consumer_state = quarantine_state.clone();
        tokio::spawn(async move {
            if let Err(e) = consumer::run(
                consumer_nats,
                consumer_spoofer,
                consumer_ipt,
                consumer_state,
            )
            .await
            {
                tracing::error!(error = %e, "enforcement consumer error");
            }
        });
    }

    // ── ARP 재독살 루프 (30초 주기) ─────────────────────────────────────────
    // ARP 캐시는 보통 60~120초 후 만료되므로 30초마다 재독살해 격리를 유지한다.
    {
        let repoison_spoofer = spoofer.clone();
        let repoison_state = quarantine_state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;

                let entries: Vec<consumer::QuarantineEntry> = {
                    let s = repoison_state.lock().unwrap();
                    s.values().cloned().collect()
                };

                if entries.is_empty() {
                    continue;
                }

                let mut guard = repoison_spoofer.lock().unwrap();
                let Some(spoofer_ref) = guard.as_mut() else {
                    continue;
                };

                // 게이트웨이를 동적으로 감지: DHCP 설정이 바뀌어도 (39↔1) 30초 내에 자동 적응
                let current_gw = consumer::detect_default_gateway();

                let mut ok = 0usize;
                let mut fail = 0usize;

                for entry in &entries {
                    let gw = current_gw.unwrap_or(entry.gateway_ip);
                    let result = match entry.action {
                        consumer::NacAction::Quarantine => {
                            spoofer_ref.quarantine(entry.victim_ip, entry.victim_mac, gw)
                        }
                        consumer::NacAction::Block => {
                            spoofer_ref.block(entry.victim_ip, entry.victim_mac, gw)
                        }
                    };
                    match result {
                        Ok(_) => ok += 1,
                        Err(e) => {
                            fail += 1;
                            tracing::warn!(
                                error = %e,
                                ip = %entry.victim_ip,
                                "re-poison failed"
                            );
                        }
                    }
                }

                if ok > 0 || fail > 0 {
                    tracing::debug!(ok, fail, "ARP re-poison tick");
                }
            }
        });
    }

    // ── iptables 재확인 루프 (60초 주기) ────────────────────────────────────
    // 외부 요인(iptables -F 등)으로 규칙이 삭제될 경우 재적용한다.
    {
        let reinforce_ipt = ipt.clone();
        let reinforce_state = quarantine_state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;

                let entries: Vec<(String, std::net::Ipv4Addr, consumer::NacAction)> = {
                    let s = reinforce_state.lock().unwrap();
                    s.iter()
                        .map(|(mac, e)| (mac.clone(), e.victim_ip, e.action.clone()))
                        .collect()
                };

                for (mac, victim_ip, action) in &entries {
                    let ip_str = victim_ip.to_string();
                    let ip_opt = Some(ip_str.as_str());
                    let result = match action {
                        consumer::NacAction::Block => reinforce_ipt.block(mac, ip_opt),
                        consumer::NacAction::Quarantine => reinforce_ipt.quarantine(mac, ip_opt),
                    };
                    if let Err(e) = result {
                        tracing::warn!(error = %e, mac = %mac, "iptables reinforce failed");
                    }
                }

                if !entries.is_empty() {
                    tracing::debug!(count = entries.len(), "iptables rules reinforced");
                }
            }
        });
    }

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}
