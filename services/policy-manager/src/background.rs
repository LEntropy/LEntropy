/// 백그라운드 태스크: 시작 시 enforcement 재조정 + 주기적 ARP 동기화
use async_nats::Client;
use serde_json::json;
use sqlx::PgPool;
use std::collections::HashMap;
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};

const ARP_SYNC_INTERVAL_SECS: u64 = 20;
const RECONCILE_DELAY_SECS: u64 = 6;
const ARP_PATH_HOST: &str = "/host/proc/net/arp";
const ARP_PATH_FALLBACK: &str = "/proc/net/arp";
const ENDPOINT_DETECTED_SUBJECT: &str = "nac.events.endpoint.detected";
const ENFORCEMENT_SUBJECT: &str = "nac.commands.enforcement";

/// 시작 시 한 번 실행: 현재 denied/quarantined 단말 및 ip_rules 재적용
pub async fn run_reconciliation(nats: Client, pool: PgPool) {
    tokio::time::sleep(Duration::from_secs(RECONCILE_DELAY_SECS)).await;
    if let Err(e) = reconcile(&nats, &pool).await {
        warn!(error = %e, "reconciliation failed");
    }
}

async fn reconcile(nats: &Client, pool: &PgPool) -> anyhow::Result<()> {
    // 1. 차단/격리 단말 재차단
    let rows: Vec<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT mac_address, ip_address, status FROM endpoints \
         WHERE status IN ('denied', 'quarantined')",
    )
    .fetch_all(pool)
    .await?;

    info!(
        count = rows.len(),
        "reconciliation: re-applying enforcement for blocked/quarantined endpoints"
    );

    for (mac, ip_opt, status) in &rows {
        let ip = ip_opt
            .as_deref()
            .map(|s| s.split('/').next().unwrap_or(s))
            .unwrap_or("");
        let action = if status == "denied" {
            "block"
        } else {
            "quarantine"
        };
        publish_enforcement(nats, mac, ip, action).await;
        debug!(mac = %mac, action, "reconciliation: sent");
    }

    // 2. IP 규칙 재적용
    let ip_rules: Vec<(String, String)> =
        sqlx::query_as("SELECT ip_cidr, action FROM ip_rules WHERE enabled = true")
            .fetch_all(pool)
            .await?;

    for (ip_cidr, action) in &ip_rules {
        let ip = ip_cidr.split('/').next().unwrap_or(ip_cidr);
        let action_str = match action.as_str() {
            "block" => "block",
            "quarantine" => "quarantine",
            _ => continue,
        };
        publish_enforcement(nats, "00:00:00:00:00:00", ip, action_str).await;
    }

    info!(
        endpoints = rows.len(),
        ip_rules = ip_rules.len(),
        "reconciliation complete"
    );
    Ok(())
}

/// 주기적으로 ARP 테이블 스캔 → NATS 이벤트 발행 (기존 consumer가 처리)
pub async fn run_arp_sync(nats: Client, pool: PgPool) {
    let mut ticker = interval(Duration::from_secs(ARP_SYNC_INTERVAL_SECS));
    loop {
        ticker.tick().await;
        if let Err(e) = arp_sync(&nats, &pool).await {
            warn!(error = %e, "ARP sync error");
        }
    }
}

async fn arp_sync(nats: &Client, pool: &PgPool) -> anyhow::Result<()> {
    let arp_path = if std::path::Path::new(ARP_PATH_HOST).exists() {
        ARP_PATH_HOST
    } else {
        ARP_PATH_FALLBACK
    };

    let content = match std::fs::read_to_string(arp_path) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, path = arp_path, "ARP sync: cannot read ARP table");
            return Ok(());
        }
    };

    // 호스트 ARP 테이블 파싱: IP → MAC (도커 내부/로컬 IP 제외)
    let mut arp_map: HashMap<String, String> = HashMap::new();
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let ip = parts[0];
        let mac = parts[3].to_lowercase();
        if mac == "00:00:00:00:00:00" {
            continue;
        }
        // 도커 브리지/루프백 제외
        if ip.starts_with("172.") || ip.starts_with("127.") || ip.starts_with("169.254.") {
            continue;
        }
        arp_map.insert(ip.to_string(), mac);
    }

    debug!(entries = arp_map.len(), "ARP sync: table read");

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // DB에서 기존 단말 MAC 조회
    let existing: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT mac_address, ip_address FROM endpoints")
            .fetch_all(pool)
            .await?;

    let existing_map: HashMap<String, Option<String>> = existing
        .into_iter()
        .map(|(mac, ip)| (mac.to_lowercase(), ip))
        .collect();

    for (ip, mac) in &arp_map {
        let current_ip = existing_map.get(mac).and_then(|opt_ip| {
            opt_ip
                .as_deref()
                .map(|s| s.split('/').next().unwrap_or(s).to_string())
        });

        let is_new = !existing_map.contains_key(mac);
        let ip_changed = !is_new && current_ip.as_deref() != Some(ip.as_str());

        if is_new || ip_changed {
            // consumer.rs의 process_event 로직 재사용 — NATS 이벤트로 발행
            let event = json!({
                "mac_address": mac,
                "ip_address": ip,
                "interface": "",
                "source": "arp-sync",
                "timestamp": now_ts,
            });
            if let Ok(payload) = serde_json::to_vec(&event) {
                nats.publish(ENDPOINT_DETECTED_SUBJECT, payload.into())
                    .await
                    .ok();
                if is_new {
                    info!(mac = %mac, ip = %ip, "ARP sync: new endpoint discovered");
                } else {
                    info!(mac = %mac, old_ip = ?current_ip, new_ip = %ip, "ARP sync: IP changed");
                }
            }
        }
    }

    Ok(())
}

async fn publish_enforcement(nats: &Client, mac: &str, ip: &str, action: &str) {
    let cmd = json!({
        "mac_address": mac,
        "ip_address": ip,
        "action": action,
        "gateway_ip": "",
        "gateway_mac": null,
        "vlan_id": null,
    });
    if let Ok(payload) = serde_json::to_vec(&cmd) {
        if let Err(e) = nats.publish(ENFORCEMENT_SUBJECT, payload.into()).await {
            warn!(error = %e, mac = %mac, "reconciliation: failed to publish");
        }
    }
}
