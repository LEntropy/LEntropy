/// 백그라운드 태스크: 시작 시 enforcement 재조정 + 주기적 ARP 동기화
use async_nats::Client;
use nac_store::endpoint::EndpointRepo;
use serde_json::json;
use sqlx::PgPool;
use std::collections::HashMap;
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};

const ARP_SYNC_INTERVAL_SECS: u64 = 20;
const RECONCILE_DELAY_SECS: u64 = 6;
const ARP_PATH_HOST: &str = "/host/proc/net/arp";
const ARP_PATH_FALLBACK: &str = "/proc/net/arp";
const ROUTE_PATH: &str = "/proc/net/route";
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
    // 0. 세션 기반 인증: 열린 세션 전체 종료 → 재시작 시 모든 단말 재인증 요구
    let terminated: i64 = sqlx::query_scalar(
        "WITH t AS (
            UPDATE sessions SET state = 'terminated', ended_at = NOW(), updated_at = NOW()
            WHERE ended_at IS NULL
            RETURNING 1
        ) SELECT COUNT(*) FROM t",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    if terminated > 0 {
        info!(
            count = terminated,
            "reconciliation: open sessions terminated"
        );
    }

    // 재시작 시 항상 allowed 단말 재평가: 세션 유무와 무관하게 실행
    // (enforcement 인메모리 상태가 사라지고, 세션이 없는 상태에서 allowed인 단말도 처리)
    let allowed: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT mac_address::TEXT, ip_address::TEXT FROM endpoints WHERE status = 'allowed'",
    )
    .fetch_all(pool)
    .await?;

    if !allowed.is_empty() {
        // username 초기화: 정책 엔진이 세션을 모르므로, username이 있으면 여전히 allow로 평가됨.
        // 재시작 시 username을 지워야 "미인증 상태"로 재평가 → quarantine → 재로그인 요구.
        // (username 없이 MAC/IP 기반으로 allow하는 정책의 단말은 영향 없음)
        if let Err(e) = sqlx::query(
            "UPDATE endpoints SET username = NULL \
             WHERE status = 'allowed' AND username IS NOT NULL",
        )
        .execute(pool)
        .await
        {
            warn!(error = %e, "reconciliation: failed to clear usernames — re-auth may not work");
        } else {
            info!("reconciliation: usernames cleared for allowed endpoints");
        }

        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        for (mac, ip_opt) in &allowed {
            let ip = ip_opt
                .as_deref()
                .map(|s| s.split('/').next().unwrap_or(s))
                .unwrap_or("");
            let event = serde_json::json!({
                "mac_address": mac,
                "ip_address":  ip,
                "interface":   "",
                "source":      "session-cleanup",
                "timestamp":   now_ts,
            });
            if let Ok(payload) = serde_json::to_vec(&event) {
                nats.publish(ENDPOINT_DETECTED_SUBJECT, payload.into())
                    .await
                    .ok();
            }
        }

        info!(
            count = allowed.len(),
            "reconciliation: re-evaluation triggered for allowed endpoints (session-based auth reset)"
        );
    }

    // 1. 차단/격리 단말 재차단
    let rows: Vec<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT mac_address::TEXT, ip_address::TEXT, status FROM endpoints \
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

/// /proc/net/route에서 기본 게이트웨이 IP 목록을 수집.
/// ARP 동기화에서 게이트웨이가 "신규 단말"로 오인식되지 않도록 제외 목록 생성.
fn detect_default_gateways() -> std::collections::HashSet<String> {
    let mut gateways = std::collections::HashSet::new();
    let Ok(content) = std::fs::read_to_string(ROUTE_PATH) else {
        return gateways;
    };
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let dest = match u32::from_str_radix(parts[1], 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let gw = match u32::from_str_radix(parts[2], 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if dest == 0 && gw != 0 {
            let bytes = gw.to_le_bytes();
            let ip = format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]);
            gateways.insert(ip);
        }
    }
    gateways
}

/// 주기적으로 ARP 테이블 스캔.
/// - 신규 단말: NATS 이벤트 발행 (정책 평가 트리거)
/// - IP 변경 단말: DB 직접 업데이트 (NATS 이벤트 금지 → 피드백 루프 방지)
///   단, 2회 연속 같은 IP가 확인되어야 확정 (oscillation debounce)
pub async fn run_arp_sync(nats: Client, pool: PgPool) {
    let mut ticker = interval(Duration::from_secs(ARP_SYNC_INTERVAL_SECS));
    // MAC → 후보 IP (다음 사이클에도 동일하면 확정)
    let mut pending_ip: HashMap<String, String> = HashMap::new();
    loop {
        ticker.tick().await;
        if let Err(e) = arp_sync(&nats, &pool, &mut pending_ip).await {
            warn!(error = %e, "ARP sync error");
        }
    }
}

async fn arp_sync(
    nats: &Client,
    pool: &PgPool,
    pending_ip: &mut HashMap<String, String>,
) -> anyhow::Result<()> {
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

    // 호스트 ARP 테이블 파싱: MAC → IP (도커 내부/로컬 IP 제외)
    // incomplete(flags==0x0) 항목 무시, 같은 MAC에 여러 IP면 complete(0x2) 플래그 우선
    let mut arp_raw: HashMap<String, (String, u8)> = HashMap::new();
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let ip = parts[0];
        let flags = parts
            .get(2)
            .and_then(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        let mac = parts[3].to_lowercase();
        if mac == "00:00:00:00:00:00" || flags == 0 {
            continue;
        }
        if ip.starts_with("172.") || ip.starts_with("127.") || ip.starts_with("169.254.") {
            continue;
        }
        // 같은 MAC에 여러 IP: complete(0x2) 플래그 항목 우선, 동일하면 먼저 나온 것 유지
        let entry = arp_raw.entry(mac).or_insert((ip.to_string(), flags));
        if flags > entry.1 {
            *entry = (ip.to_string(), flags);
        }
    }
    // MAC → IP 매핑으로 변환 (루프에서 MAC당 1회만 처리)
    let arp_map: HashMap<String, String> = arp_raw
        .into_iter()
        .map(|(mac, (ip, _))| (mac, ip))
        .collect();

    debug!(entries = arp_map.len(), "ARP sync: table read");

    // 기본 게이트웨이 IP는 NAC 관리 대상에서 제외 — 게이트웨이가 차단되면 Pi 자체의
    // 인터넷 연결이 끊기기 때문에 절대 endpoint로 등록하지 않는다.
    let gateway_ips = detect_default_gateways();

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let existing: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT mac_address::TEXT, ip_address::TEXT FROM endpoints")
            .fetch_all(pool)
            .await?;

    let existing_map: HashMap<String, Option<String>> = existing
        .into_iter()
        .map(|(mac, ip)| (mac.to_lowercase(), ip))
        .collect();

    // 현재 ARP 테이블에 없는 MAC의 pending 항목 제거
    pending_ip.retain(|mac, _| arp_map.contains_key(mac));

    for (mac, ip) in &arp_map {
        // 게이트웨이 IP는 절대 endpoint로 등록하지 않음
        if gateway_ips.contains(ip) {
            debug!(ip = %ip, "ARP sync: skipping default gateway");
            pending_ip.remove(mac);
            continue;
        }

        let current_ip = existing_map.get(mac).and_then(|opt_ip| {
            opt_ip
                .as_deref()
                .map(|s| s.split('/').next().unwrap_or(s).to_string())
        });

        let is_new = !existing_map.contains_key(mac);
        let ip_changed = !is_new && current_ip.as_deref() != Some(ip.as_str());

        if is_new {
            // 신규 단말만 NATS 이벤트 발행 (정책 평가 트리거)
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
                info!(mac = %mac, ip = %ip, "ARP sync: new endpoint discovered");
            }
            pending_ip.remove(mac);
        } else if ip_changed {
            // IP 변경: NATS 이벤트 발행하지 않음 (피드백 루프 방지)
            // 2회 연속 같은 IP 확인 후 DB 직접 업데이트 (oscillation debounce)
            let prev_candidate = pending_ip.get(mac).map(|s| s.as_str());
            if prev_candidate == Some(ip.as_str()) {
                // 2회 연속 확인 → 확정
                info!(
                    mac = %mac,
                    old_ip = ?current_ip,
                    new_ip = %ip,
                    "ARP sync: IP change confirmed — updating DB directly"
                );

                if let Err(e) = sqlx::query(
                    "UPDATE endpoints SET ip_address = $1::inet, last_seen = NOW() \
                     WHERE mac_address = $2::macaddr",
                )
                .bind(ip)
                .bind(mac)
                .execute(pool)
                .await
                {
                    warn!(error = %e, mac = %mac, "ARP sync: DB IP update failed");
                }

                // 차단/격리 단말: 새 IP로 enforcement 직접 재발행
                let repo = EndpointRepo::new(pool);
                if let Ok(Some(ep)) = repo.find_by_mac(mac).await {
                    let action = match ep.status.as_str() {
                        "denied" => Some("block"),
                        "quarantined" => Some("quarantine"),
                        _ => None,
                    };
                    if let Some(action) = action {
                        publish_enforcement(nats, mac, ip, action).await;
                        debug!(mac = %mac, action, new_ip = %ip, "ARP sync: enforcement re-sent for IP change");
                    }
                }

                pending_ip.remove(mac);
            } else {
                // 처음 본 IP 변경 → 후보 등록, 다음 사이클에 재확인
                debug!(
                    mac = %mac,
                    candidate_ip = %ip,
                    "ARP sync: IP change pending confirmation"
                );
                pending_ip.insert(mac.clone(), ip.clone());
            }
        } else {
            // IP 안정 → 후보 초기화
            pending_ip.remove(mac);
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
            warn!(error = %e, mac = %mac, "failed to publish enforcement command");
        }
    }
}
