use axum::{extract::State, Json};
use nac_policy_engine::rule::Condition;
use nac_store::endpoint::EndpointRow;
use nac_store::{
    endpoint::EndpointRepo,
    policy::{decision_to_status, PolicyRepo},
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

use super::endpoints::AppError;

/// POST /api/v1/policies/evaluate 요청 바디
#[derive(Deserialize, Default)]
pub struct EvaluateRequest {
    /// 어떤 정책에도 매칭되지 않는 단말에 적용할 기본 동작
    /// "allowed" | "denied" | "quarantined" | null (변경 없음)
    pub default_action: Option<String>,
}

/// 평가 결과
#[derive(Serialize)]
pub struct EvaluateResult {
    pub evaluated: u32,
    pub changed: u32,
    pub skipped: u32,
}

/// POST /api/v1/policies/evaluate
/// 활성 정책을 우선순위 순으로 모든 단말에 적용하고 상태를 갱신한다.
/// - policy_exempt=true 단말은 건너뜀
/// - assigned_policy_id가 있는 단말은 해당 정책만 적용
/// - 매칭 정책이 없으면 default_action(지정된 경우)을 적용
pub async fn evaluate_policies(
    State(pool): State<PgPool>,
    Json(req): Json<EvaluateRequest>,
) -> Result<Json<EvaluateResult>, AppError> {
    let policy_repo = PolicyRepo::new(&pool);
    let endpoint_repo = EndpointRepo::new(&pool);

    let rules_with_id = policy_repo.load_rules_with_id().await?;
    let id_to_idx: HashMap<Uuid, usize> = rules_with_id
        .iter()
        .enumerate()
        .map(|(i, (id, _))| (*id, i))
        .collect();

    let endpoints = endpoint_repo.list(10_000, 0).await?;

    let mut changed = 0u32;
    let mut skipped = 0u32;

    for ep in &endpoints {
        if ep.policy_exempt {
            skipped += 1;
            continue;
        }

        let new_status: Option<&str> = if let Some(pid) = ep.assigned_policy_id {
            // 수동 할당된 정책 적용
            if let Some(&idx) = id_to_idx.get(&pid) {
                rules_with_id
                    .get(idx)
                    .map(|(_, rule)| decision_to_status(&rule.decision))
            } else {
                // 비활성 정책이더라도 할당된 경우 직접 조회
                match policy_repo.find_rule_by_id(pid).await {
                    Ok(Some(rule)) => Some(decision_to_status(&rule.decision)),
                    _ => None,
                }
            }
        } else {
            // 우선순위 기반 자동 매칭
            rules_with_id.iter().find_map(|(_, rule)| {
                if condition_matches(&rule.condition, ep) {
                    Some(decision_to_status(&rule.decision))
                } else {
                    None
                }
            })
        };

        let effective = new_status.or(req.default_action.as_deref());

        if let Some(status) = effective {
            if ep.status != status {
                endpoint_repo.set_status(ep.id, status).await?;
                changed += 1;
            }
        }
    }

    Ok(Json(EvaluateResult {
        evaluated: endpoints.len() as u32,
        changed,
        skipped,
    }))
}

fn condition_matches(condition: &Condition, ep: &EndpointRow) -> bool {
    match condition {
        Condition::And { conditions } => {
            if conditions.is_empty() {
                return true;
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
        Condition::UserGroup { .. } => false,
    }
}
