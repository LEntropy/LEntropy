use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use nac_store::audit::AuditRepo;
use nac_store::endpoint::EndpointRepo;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use super::AppState;

/// GET /api/v1/endpoints 쿼리 파라미터
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

/// 단말 목록 응답
#[derive(Debug, Serialize)]
pub struct ListResponse {
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
    pub items: Vec<serde_json::Value>,
}

/// GET /api/v1/endpoints
pub async fn list_endpoints(
    State(pool): State<PgPool>,
    Query(q): Query<ListQuery>,
) -> Result<Json<ListResponse>, AppError> {
    let repo = EndpointRepo::new(&pool);
    let limit = q.limit.clamp(1, 200);
    let offset = q.offset.max(0);

    let (total, items) = tokio::try_join!(repo.count(), repo.list(limit, offset))?;

    let items = items
        .into_iter()
        .map(|r| serde_json::to_value(r).unwrap_or_default())
        .collect();

    Ok(Json(ListResponse {
        total,
        limit,
        offset,
        items,
    }))
}

/// GET /api/v1/endpoints/:id
pub async fn get_endpoint(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let repo = EndpointRepo::new(&pool);

    match repo.find_by_id(id).await? {
        Some(ep) => Ok(Json(serde_json::to_value(ep)?)),
        None => Err(AppError::NotFound(format!("endpoint {id} not found"))),
    }
}

/// GET /api/v1/endpoints/mac/:mac
pub async fn get_endpoint_by_mac(
    State(pool): State<PgPool>,
    Path(mac): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let repo = EndpointRepo::new(&pool);

    match repo.find_by_mac(&mac).await? {
        Some(ep) => Ok(Json(serde_json::to_value(ep)?)),
        None => Err(AppError::NotFound(format!(
            "endpoint with MAC {mac} not found"
        ))),
    }
}

// ── 상태 변경 헬퍼 ────────────────────────────────────────────────────────

async fn update_endpoint_status(
    state: &AppState,
    id: Uuid,
    status: &str,
    event_type: &str,
) -> Result<Json<serde_json::Value>, AppError> {
    let repo = EndpointRepo::new(&state.pool);
    match repo.find_by_id(id).await? {
        None => Err(AppError::NotFound(format!("endpoint {id} not found"))),
        Some(ep) => {
            repo.set_status(id, status).await?;
            let audit = AuditRepo::new(&state.pool);
            audit
                .log(
                    event_type,
                    Some(id),
                    "api",
                    serde_json::json!({ "status": status }),
                )
                .await?;

            // enforcement NATS 명령 발행
            let ip = ep
                .ip_address
                .as_deref()
                .unwrap_or("")
                .split('/')
                .next()
                .unwrap_or("")
                .to_string();
            let cmd = serde_json::json!({
                "mac_address": ep.mac_address,
                "ip_address": ip,
                "action": status,
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

            match repo.find_by_id(id).await? {
                Some(updated) => Ok(Json(serde_json::to_value(updated)?)),
                None => Err(AppError::NotFound(format!("endpoint {id} not found"))),
            }
        }
    }
}

/// POST /api/v1/endpoints/:id/allow
pub async fn allow_endpoint(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    update_endpoint_status(&state, id, "allowed", "endpoint_allowed").await
}

/// POST /api/v1/endpoints/:id/block
pub async fn block_endpoint(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    update_endpoint_status(&state, id, "denied", "endpoint_blocked").await
}

/// POST /api/v1/endpoints/:id/quarantine
pub async fn quarantine_endpoint(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    update_endpoint_status(&state, id, "quarantined", "endpoint_quarantined").await
}

/// POST /api/v1/endpoints/:id/policy — 수동 정책 할당 (policy_id: null 이면 해제)
#[derive(Deserialize)]
pub struct AssignPolicyRequest {
    pub policy_id: Option<Uuid>,
}

pub async fn assign_policy(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
    Json(req): Json<AssignPolicyRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let repo = EndpointRepo::new(&pool);
    match repo.find_by_id(id).await? {
        None => Err(AppError::NotFound(format!("endpoint {id} not found"))),
        Some(_) => {
            repo.set_policy(id, req.policy_id).await?;
            let audit = AuditRepo::new(&pool);
            audit
                .log(
                    "endpoint_policy_assigned",
                    Some(id),
                    "api",
                    serde_json::json!({ "policy_id": req.policy_id }),
                )
                .await?;
            match repo.find_by_id(id).await? {
                Some(ep) => Ok(Json(serde_json::to_value(ep)?)),
                None => Err(AppError::NotFound(format!("endpoint {id} not found"))),
            }
        }
    }
}

/// POST /api/v1/endpoints/:id/exempt — 정책 예외 설정
#[derive(Deserialize)]
pub struct SetExemptRequest {
    pub exempt: bool,
}

pub async fn set_exempt(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
    Json(req): Json<SetExemptRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let repo = EndpointRepo::new(&pool);
    match repo.find_by_id(id).await? {
        None => Err(AppError::NotFound(format!("endpoint {id} not found"))),
        Some(_) => {
            repo.set_exempt(id, req.exempt).await?;
            let audit = AuditRepo::new(&pool);
            let event = if req.exempt {
                "endpoint_policy_exempted"
            } else {
                "endpoint_policy_unexempted"
            };
            audit
                .log(
                    event,
                    Some(id),
                    "api",
                    serde_json::json!({ "exempt": req.exempt }),
                )
                .await?;
            match repo.find_by_id(id).await? {
                Some(ep) => Ok(Json(serde_json::to_value(ep)?)),
                None => Err(AppError::NotFound(format!("endpoint {id} not found"))),
            }
        }
    }
}

// ── 에러 타입 ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum AppError {
    Db(anyhow::Error),
    NotFound(String),
    Serialization(serde_json::Error),
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        Self::Db(e)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match &self {
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            Self::Db(e) => {
                tracing::error!(error = %e, "database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                )
            }
            Self::Serialization(e) => {
                tracing::error!(error = %e, "serialization error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "serialization error".to_string(),
                )
            }
        };

        let body = Json(serde_json::json!({ "error": message }));
        (status, body).into_response()
    }
}
