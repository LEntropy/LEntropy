use anyhow::Result;
use async_nats::Client;
use futures_util::StreamExt;
use nac_policy_engine::evaluator;
use nac_store::audit::AuditRepo;
use nac_store::endpoint::EndpointRepo;
use nac_store::policy::{decision_to_status, PolicyRepo};
use nac_store::posture::{CompliancePolicy, PostureRepo, PostureReport};
use serde_json::json;
use sqlx::PgPool;
use tracing::{debug, error, info, warn};

const SUBJECT: &str = "nac.events.posture.report";

pub async fn run(nats: Client, pool: PgPool) -> Result<()> {
    let mut sub = nats.subscribe(SUBJECT).await?;
    info!(subject = SUBJECT, "posture handler started");

    while let Some(msg) = sub.next().await {
        let report: PostureReport = match serde_json::from_slice(&msg.payload) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "failed to parse posture report");
                continue;
            }
        };

        if let Err(e) = process_posture(&nats, &pool, report).await {
            error!(error = %e, "posture processing error");
        }
    }
    Ok(())
}

async fn process_posture(nats: &Client, pool: &PgPool, report: PostureReport) -> Result<()> {
    let endpoint_repo = EndpointRepo::new(pool);
    let posture_repo = PostureRepo::new(pool);
    let policy_repo = PolicyRepo::new(pool);
    let audit_repo = AuditRepo::new(pool);

    // 1. MAC으로 endpoint 조회
    let endpoint = match endpoint_repo.find_by_mac(&report.device_id).await? {
        Some(ep) => ep,
        None => {
            warn!(mac = %report.device_id, "posture report for unknown endpoint");
            return Ok(());
        }
    };

    // 2. Compliance 평가
    let policy = CompliancePolicy::default_policy();
    let is_compliant = policy.evaluate(&report);

    debug!(mac = %report.device_id, is_compliant, "compliance evaluated");

    // 3. posture_reports 저장
    posture_repo
        .save(endpoint.id, &report, is_compliant)
        .await?;

    // 4. endpoint is_compliant 업데이트
    endpoint_repo
        .set_compliance(endpoint.id, is_compliant)
        .await?;

    // 5. audit log
    audit_repo
        .log(
            "posture_report",
            Some(endpoint.id),
            "agent-gateway",
            json!({
                "mac": report.device_id,
                "is_compliant": is_compliant,
                "missing_patches": report.missing_patches.len(),
                "usb_enabled": report.usb_enabled,
            }),
        )
        .await?;

    // 6. 정책 재평가
    let mut rules = policy_repo.load_rules().await?;
    if rules.is_empty() {
        return Ok(());
    }

    let ctx = nac_policy_engine::PolicyContext {
        mac_address: endpoint.mac_address.clone(),
        ip_address: endpoint.ip_address.clone(),
        hostname: endpoint.hostname.clone(),
        os_family: endpoint
            .os_family
            .clone()
            .or_else(|| Some(report.os.clone())),
        device_type: endpoint.device_type.clone(),
        username: endpoint.username.clone(),
        groups: vec![],
        is_compliant: Some(is_compliant),
        switch_port: endpoint.switch_port.clone(),
    };

    let decision = evaluator::evaluate(&mut rules, &ctx)?;
    let new_status = decision_to_status(&decision);

    // 7. 상태 변경 시 업데이트 + enforcement 명령
    if endpoint.status != new_status {
        endpoint_repo.set_status(endpoint.id, new_status).await?;
        info!(
            mac = %report.device_id,
            old = %endpoint.status,
            new = new_status,
            "status changed by posture"
        );

        audit_repo
            .log(
                "posture_status_change",
                Some(endpoint.id),
                "policy-manager",
                json!({
                    "mac": report.device_id,
                    "old_status": endpoint.status,
                    "new_status": new_status,
                    "is_compliant": is_compliant,
                }),
            )
            .await?;

        // enforcement 명령 발행
        let cmd = json!({
            "mac_address": endpoint.mac_address,
            "ip_address": endpoint.ip_address.as_deref().unwrap_or(""),
            "action": new_status,
            "gateway_ip": "",
            "gateway_mac": null,
            "vlan_id": null,
        });
        if let Ok(payload) = serde_json::to_vec(&cmd) {
            nats.publish("nac.commands.enforcement", payload.into())
                .await
                .ok();
        }
    }

    Ok(())
}
