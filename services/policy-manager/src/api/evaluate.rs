use axum::{extract::State, Json};
use nac_policy_engine::rule::Condition;
use nac_store::endpoint::EndpointRow;
use nac_store::{
    endpoint::EndpointRepo,
    policy::{decision_to_status, PolicyRepo},
};
use serde::Serialize;
use sqlx::PgPool;

use super::endpoints::AppError;

#[derive(Serialize)]
pub struct EvaluateResult {
    pub evaluated: u32,
    pub changed: u32,
}

/// POST /api/v1/policies/evaluate
/// 활성 정책을 우선순위 순으로 모든 단말에 적용하고 상태를 갱신한다.
pub async fn evaluate_policies(
    State(pool): State<PgPool>,
) -> Result<Json<EvaluateResult>, AppError> {
    let policy_repo = PolicyRepo::new(&pool);
    let endpoint_repo = EndpointRepo::new(&pool);

    let rules = policy_repo.load_rules().await?;
    let endpoints = endpoint_repo.list(10_000, 0).await?;

    let mut changed = 0u32;
    for ep in &endpoints {
        let new_status = rules.iter().find_map(|rule| {
            if condition_matches(&rule.condition, ep) {
                Some(decision_to_status(&rule.decision))
            } else {
                None
            }
        });

        if let Some(status) = new_status {
            if ep.status != status {
                endpoint_repo.set_status(ep.id, status).await?;
                changed += 1;
            }
        }
    }

    Ok(Json(EvaluateResult {
        evaluated: endpoints.len() as u32,
        changed,
    }))
}

fn condition_matches(condition: &Condition, ep: &EndpointRow) -> bool {
    match condition {
        Condition::And { conditions } => {
            if conditions.is_empty() {
                return true; // 조건 없음 = 전체 단말 매칭 (default-allow 패턴)
            }
            conditions.iter().all(|c| condition_matches(c, ep))
        }
        Condition::Or { conditions } => conditions.iter().any(|c| condition_matches(c, ep)),
        Condition::Not { condition } => !condition_matches(condition, ep),
        Condition::OsFamily { value } => ep
            .os_family
            .as_deref()
            .map(|o| o.eq_ignore_ascii_case(value))
            .unwrap_or(false),
        Condition::DeviceType { value } => ep
            .device_type
            .as_deref()
            .map(|d| d.eq_ignore_ascii_case(value))
            .unwrap_or(false),
        Condition::Compliant { required } => ep.is_compliant.unwrap_or(false) == *required,
        Condition::MacList { macs } => macs.iter().any(|m| m.eq_ignore_ascii_case(&ep.mac_address)),
        Condition::UserGroup { .. } => false, // Phase 3 (LDAP)
    }
}
