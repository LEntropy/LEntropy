use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::endpoints::AppError;
use super::AppState;

#[derive(Debug, Serialize)]
pub struct IpRule {
    pub id: Uuid,
    pub ip_cidr: String,
    pub action: String,
    pub note: Option<String>,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateIpRuleRequest {
    pub ip_cidr: String,
    #[serde(default = "default_action")]
    pub action: String,
    pub note: Option<String>,
}

fn default_action() -> String {
    "block".to_string()
}

/// GET /api/v1/network/ip-rules
pub async fn list_ip_rules(State(state): State<AppState>) -> Result<Json<Vec<IpRule>>, AppError> {
    let rows = sqlx::query_as::<_, (Uuid, String, String, Option<String>, bool, String)>(
        "SELECT id, ip_cidr, action, note, enabled, \
         to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
         FROM ip_rules ORDER BY created_at DESC",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(anyhow::Error::from)?;

    let rules = rows
        .into_iter()
        .map(|(id, ip_cidr, action, note, enabled, created_at)| IpRule {
            id,
            ip_cidr,
            action,
            note,
            enabled,
            created_at,
        })
        .collect();

    Ok(Json(rules))
}

/// POST /api/v1/network/ip-rules
pub async fn create_ip_rule(
    State(state): State<AppState>,
    Json(req): Json<CreateIpRuleRequest>,
) -> Result<impl IntoResponse, AppError> {
    if req.ip_cidr.trim().is_empty() {
        return Err(AppError::NotFound("ip_cidr is required".to_string()));
    }
    if !matches!(req.action.as_str(), "block" | "quarantine") {
        return Err(AppError::NotFound(
            "action must be 'block' or 'quarantine'".to_string(),
        ));
    }

    let row = sqlx::query_as::<_, (Uuid, String, String, Option<String>, bool, String)>(
        "INSERT INTO ip_rules (ip_cidr, action, note) VALUES ($1, $2, $3) \
         RETURNING id, ip_cidr, action, note, enabled, \
         to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')",
    )
    .bind(req.ip_cidr.trim())
    .bind(&req.action)
    .bind(&req.note)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| {
        if e.to_string().contains("unique") {
            AppError::NotFound(format!("IP rule for '{}' already exists", req.ip_cidr))
        } else {
            AppError::Db(anyhow::Error::from(e))
        }
    })?;

    let rule = IpRule {
        id: row.0,
        ip_cidr: row.1,
        action: row.2,
        note: row.3,
        enabled: row.4,
        created_at: row.5,
    };

    // enforcement에 즉시 반영
    publish_ip_enforcement(&state, &rule.ip_cidr, &rule.action).await;

    tracing::info!(ip = %rule.ip_cidr, action = %rule.action, "IP rule created");
    Ok((StatusCode::CREATED, Json(rule)))
}

/// DELETE /api/v1/network/ip-rules/{id}
pub async fn delete_ip_rule(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    // 삭제 전 IP 조회
    let row = sqlx::query_as::<_, (String, String)>(
        "DELETE FROM ip_rules WHERE id = $1 RETURNING ip_cidr, action",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(anyhow::Error::from)?;

    match row {
        None => Err(AppError::NotFound(format!("IP rule {id} not found"))),
        Some((ip_cidr, _action)) => {
            // enforcement에 허용 명령 발행 (IP 차단 해제)
            publish_ip_enforcement(&state, &ip_cidr, "allow").await;
            tracing::info!(ip = %ip_cidr, "IP rule deleted");
            Ok(StatusCode::NO_CONTENT)
        }
    }
}

/// PATCH /api/v1/network/ip-rules/{id}/enable  or  /disable
pub async fn set_ip_rule_enabled(
    State(state): State<AppState>,
    Path((id, action)): Path<(Uuid, String)>,
) -> Result<StatusCode, AppError> {
    let enabled = match action.as_str() {
        "enable" => true,
        "disable" => false,
        _ => {
            return Err(AppError::NotFound(
                "action must be 'enable' or 'disable'".to_string(),
            ))
        }
    };

    let row = sqlx::query_as::<_, (String, String)>(
        "UPDATE ip_rules SET enabled = $1 WHERE id = $2 RETURNING ip_cidr, action",
    )
    .bind(enabled)
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(anyhow::Error::from)?;

    match row {
        None => Err(AppError::NotFound(format!("IP rule {id} not found"))),
        Some((ip_cidr, rule_action)) => {
            let enforcement_action = if enabled { &rule_action } else { "allow" };
            publish_ip_enforcement(&state, &ip_cidr, enforcement_action).await;
            Ok(StatusCode::NO_CONTENT)
        }
    }
}

async fn publish_ip_enforcement(state: &AppState, ip: &str, action: &str) {
    let enforcement_action = match action {
        "block" => "block",
        "quarantine" => "quarantine",
        "allow" => "allow",
        _ => return,
    };
    let cmd = serde_json::json!({
        "mac_address": "00:00:00:00:00:00",
        "ip_address": ip.split('/').next().unwrap_or(ip),
        "action": enforcement_action,
        "gateway_ip": "",
        "gateway_mac": null,
        "vlan_id": null,
    });
    if let Ok(payload) = serde_json::to_vec(&cmd) {
        state
            .nats
            .publish("nac.commands.enforcement", payload.into())
            .await
            .ok();
    }
}
