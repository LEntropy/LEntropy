use anyhow::Result;
use async_nats::Client;
use futures_util::StreamExt;
use nac_policy_engine::evaluator;
use nac_policy_engine::PolicyDecision;
use nac_store::audit::AuditRepo;
use nac_store::endpoint::{EndpointRepo, UpsertEndpoint};
use nac_store::policy::{decision_to_status, PolicyRepo};
use nac_store::session::{CreateSession, SessionRepo};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use tracing::{debug, error, info, warn};

const SUBJECT: &str = "nac.events.endpoint.detected";
const ENFORCEMENT_SUBJECT: &str = "nac.commands.enforcement";

/// sensor 서비스가 발행하는 이벤트 페이로드
#[derive(Debug, Deserialize)]
struct EndpointDetectedEvent {
    mac_address: String,
    ip_address: String,
    interface: String,
    source: String,
    #[allow(dead_code)]
    timestamp: i64,
    // 핑거프린팅 필드 (DHCP 경로에서 채워짐)
    hostname: Option<String>,
    os_family: Option<String>,
    os_version: Option<String>,
    device_type: Option<String>,
    vendor: Option<String>,
}

/// NATS 구독 루프 — 단말 탐지 이벤트 수신 → DB 업서트 → 정책 평가 → Audit
pub async fn run(nats: Client, pool: PgPool) -> Result<()> {
    let mut sub = nats.subscribe(SUBJECT).await?;
    info!(subject = SUBJECT, "NATS consumer started");

    while let Some(msg) = sub.next().await {
        let payload = match serde_json::from_slice::<EndpointDetectedEvent>(&msg.payload) {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "failed to parse endpoint event — skipping");
                continue;
            }
        };

        debug!(
            mac = %payload.mac_address,
            ip  = %payload.ip_address,
            src = %payload.source,
            "endpoint event received"
        );

        if let Err(e) = process_event(&nats, &pool, payload).await {
            error!(error = %e, "error processing endpoint event");
        }
    }

    info!("NATS consumer stopped");
    Ok(())
}

async fn process_event(nats: &Client, pool: &PgPool, event: EndpointDetectedEvent) -> Result<()> {
    let endpoint_repo = EndpointRepo::new(pool);
    let policy_repo = PolicyRepo::new(pool);
    let audit_repo = AuditRepo::new(pool);
    let session_repo = SessionRepo::new(pool);

    // ── 1. 단말 업서트 (업서트 전 기존 IP 저장) ──────────────────────────
    let old_ip = endpoint_repo
        .find_by_mac(&event.mac_address)
        .await
        .ok()
        .flatten()
        .and_then(|e| e.ip_address)
        .map(strip_cidr);

    let ip = if event.ip_address.is_empty() {
        None
    } else {
        Some(event.ip_address.clone())
    };

    let ep = UpsertEndpoint {
        mac_address: event.mac_address.clone(),
        ip_address: ip,
        hostname: event.hostname.clone(),
        os_family: event.os_family.clone(),
        os_version: event.os_version.clone(),
        device_type: event.device_type.clone(),
        vendor: event.vendor.clone(),
        interface: if event.interface.is_empty() {
            None
        } else {
            Some(event.interface.clone())
        },
    };

    let row = endpoint_repo.upsert(&ep).await?;
    let new_ip = row.ip_address.clone().map(strip_cidr);

    // IP 변경 여부 체크
    let ip_changed = new_ip.is_some() && old_ip != new_ip;

    debug!(
        id     = %row.id,
        mac    = %row.mac_address,
        status = %row.status,
        ip_changed,
        "endpoint upserted"
    );

    // ── 2. 감사 로그: 단말 탐지 ──────────────────────────────────────────
    audit_repo
        .log(
            "endpoint_detected",
            Some(row.id),
            &format!("sensor/{}", event.source),
            json!({
                "mac": row.mac_address,
                "ip":  new_ip,
                "source": event.source,
                "os_family": row.os_family,
                "device_type": row.device_type,
            }),
        )
        .await?;

    // IP 변경 감사 로그
    if ip_changed {
        audit_repo
            .log(
                "endpoint_ip_changed",
                Some(row.id),
                "sensor",
                json!({
                    "mac":    row.mac_address,
                    "old_ip": old_ip,
                    "new_ip": new_ip,
                }),
            )
            .await?;
        info!(
            mac    = %row.mac_address,
            old_ip = ?old_ip,
            new_ip = ?new_ip,
            "endpoint IP changed"
        );
    }

    // ── 3. 정책 평가 ─────────────────────────────────────────────────────
    let mut rules = policy_repo.load_rules().await?;

    if rules.is_empty() {
        debug!(mac = %row.mac_address, "no policies loaded — skipping evaluation");
        return Ok(());
    }

    let ctx = nac_policy_engine::PolicyContext {
        mac_address: row.mac_address.clone(),
        ip_address: row.ip_address.clone(),
        hostname: row.hostname.clone(),
        os_family: row.os_family.clone(),
        device_type: row.device_type.clone(),
        username: row.username.clone(),
        groups: vec![],
        is_compliant: None,
        switch_port: row.switch_port.clone(),
    };

    let decision = evaluator::evaluate(&mut rules, &ctx)?;
    let new_status = decision_to_status(&decision);

    debug!(
        mac      = %row.mac_address,
        decision = ?decision,
        status   = new_status,
        "policy evaluated"
    );

    // ── 4. 상태 변경 or IP 변경 시 enforcement 재발행 ────────────────────
    let status_changed = row.status != new_status;
    // IP가 바뀌었고 이미 차단/격리 상태면 enforcement 재발행 필요
    let needs_enforcement_update = ip_changed
        && matches!(row.status, _ if ["denied", "quarantined"].contains(&row.status.as_str()));

    if status_changed {
        endpoint_repo.set_status(row.id, new_status).await?;

        info!(
            mac        = %row.mac_address,
            old_status = %row.status,
            new_status = new_status,
            "endpoint status changed"
        );

        audit_repo
            .log(
                "policy_decision",
                Some(row.id),
                "policy-manager",
                json!({
                    "mac":        row.mac_address,
                    "old_status": row.status,
                    "new_status": new_status,
                    "decision":   format!("{:?}", decision),
                }),
            )
            .await?;

        if new_status == "quarantined" {
            let vlan_id = match &decision {
                PolicyDecision::Quarantine { vlan, .. } => Some(*vlan as i16),
                _ => None,
            };
            match session_repo
                .create(&CreateSession {
                    endpoint_id: row.id,
                    auth_method: "captive_portal".to_string(),
                    vlan_id,
                })
                .await
            {
                Ok(sess) => {
                    info!(
                        session_id  = %sess.id,
                        endpoint_id = %row.id,
                        mac         = %row.mac_address,
                        "session created for quarantined endpoint"
                    );
                }
                Err(e) => {
                    warn!(error = %e, mac = %row.mac_address, "failed to create session");
                }
            }
        }

        publish_enforcement_command(nats, &row.mac_address, &new_ip, new_status, &decision).await;
    } else if needs_enforcement_update {
        // 상태 변경 없이 IP만 바뀐 경우: enforcement에 새 IP로 재발행
        info!(
            mac    = %row.mac_address,
            status = %row.status,
            new_ip = ?new_ip,
            "re-publishing enforcement for IP change"
        );
        publish_enforcement_command(nats, &row.mac_address, &new_ip, &row.status, &decision).await;
    }

    Ok(())
}

/// CIDR 접미사 제거: "192.168.0.2/32" → "192.168.0.2"
fn strip_cidr(ip: String) -> String {
    ip.split('/').next().unwrap_or(&ip).to_string()
}

/// enforcement 서비스에 ARP 명령 발행
async fn publish_enforcement_command(
    nats: &Client,
    mac: &str,
    ip: &Option<String>,
    status: &str,
    decision: &PolicyDecision,
) {
    let action = match status {
        "quarantined" => "quarantine",
        "denied" => "block",
        "allowed" => "allow",
        _ => return,
    };

    let vlan_id = match decision {
        PolicyDecision::Quarantine { vlan, .. } => Some(*vlan),
        PolicyDecision::AllowVlan(v) => Some(*v),
        _ => None,
    };

    // CIDR 제거: DB의 INET 타입이 "192.168.0.2/32" 형태일 수 있음
    let ip_str = ip
        .as_deref()
        .map(|s| s.split('/').next().unwrap_or(s))
        .unwrap_or("");

    let cmd = json!({
        "mac_address": mac,
        "ip_address": ip_str,
        "action": action,
        "gateway_ip": "",
        "gateway_mac": null,
        "vlan_id": vlan_id,
    });

    match serde_json::to_vec(&cmd) {
        Ok(payload) => {
            if let Err(e) = nats.publish(ENFORCEMENT_SUBJECT, payload.into()).await {
                warn!(error = %e, mac = %mac, "failed to publish enforcement command");
            } else {
                debug!(mac = %mac, action = %action, "enforcement command published");
            }
        }
        Err(e) => {
            warn!(error = %e, "failed to serialize enforcement command");
        }
    }
}
