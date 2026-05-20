use axum::{
    extract::{Query, State},
    Json,
};
use nac_store::audit::AuditRepo;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use super::endpoints::AppError;

/// GET /api/v1/audit 쿼리 파라미터
#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    pub endpoint_id: Option<Uuid>,
}

fn default_limit() -> i64 {
    50
}

/// 감사 로그 목록 응답
#[derive(Debug, Serialize)]
pub struct AuditListResponse {
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
    pub items: Vec<serde_json::Value>,
}

/// GET /api/v1/audit
pub async fn list_audit(
    State(pool): State<PgPool>,
    Query(q): Query<AuditQuery>,
) -> Result<Json<AuditListResponse>, AppError> {
    let repo = AuditRepo::new(&pool);
    let limit = q.limit.clamp(1, 200);
    let offset = q.offset.max(0);

    let (total, items) = tokio::try_join!(
        repo.count(q.endpoint_id),
        repo.list(limit, offset, q.endpoint_id),
    )?;

    let items = items
        .into_iter()
        .map(|r| serde_json::to_value(r).unwrap_or_default())
        .collect();

    Ok(Json(AuditListResponse {
        total,
        limit,
        offset,
        items,
    }))
}
