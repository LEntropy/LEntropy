use anyhow::Result;
use async_nats::Client;
use futures_util::StreamExt;
use nac_policy_engine::evaluator;
use nac_store::audit::AuditRepo;
use nac_store::endpoint::{EndpointRepo, UpsertEndpoint};
use nac_store::policy::{decision_to_status, PolicyRepo};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use tracing::{debug, error, info, warn};

const SUBJECT: &str = "nac.events.endpoint.detected";

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

        if let Err(e) = process_event(&pool, payload).await {
            error!(error = %e, "error processing endpoint event");
        }
    }

    info!("NATS consumer stopped");
    Ok(())
}

async fn process_event(pool: &PgPool, event: EndpointDetectedEvent) -> Result<()> {
    let endpoint_repo = EndpointRepo::new(pool);
    let policy_repo = PolicyRepo::new(pool);
    let audit_repo = AuditRepo::new(pool);

    // ── 1. 단말 업서트 ────────────────────────────────────────────────────
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

    debug!(
        id     = %row.id,
        mac    = %row.mac_address,
        status = %row.status,
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
                "ip":  row.ip_address,
                "source": event.source,
                "os_family": row.os_family,
                "device_type": row.device_type,
            }),
        )
        .await?;

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

    // ── 4. 상태 변경 (이전과 다를 때만) ──────────────────────────────────
    if row.status != new_status {
        endpoint_repo.set_status(row.id, new_status).await?;

        info!(
            mac        = %row.mac_address,
            old_status = %row.status,
            new_status = new_status,
            "endpoint status changed"
        );

        // 감사 로그: 정책 결정
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
    }

    Ok(())
}
