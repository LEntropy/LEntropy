use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use nac_store::endpoint::EndpointRepo;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

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
