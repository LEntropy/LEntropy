use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use nac_store::policy::{CreatePolicy, PolicyRepo, UpdatePolicy};
use sqlx::PgPool;
use uuid::Uuid;

use super::endpoints::AppError;

/// GET /api/v1/policies
pub async fn list_policies(
    State(pool): State<PgPool>,
) -> Result<Json<Vec<serde_json::Value>>, AppError> {
    let repo = PolicyRepo::new(&pool);
    let rows = repo.list_all().await?;
    let items = rows
        .into_iter()
        .map(|r| serde_json::to_value(r).unwrap_or_default())
        .collect();
    Ok(Json(items))
}

/// GET /api/v1/policies/:id
pub async fn get_policy(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let repo = PolicyRepo::new(&pool);
    match repo.find_by_id(id).await? {
        Some(row) => Ok(Json(serde_json::to_value(row)?)),
        None => Err(AppError::NotFound(format!("policy {id} not found"))),
    }
}

/// POST /api/v1/policies
pub async fn create_policy(
    State(pool): State<PgPool>,
    Json(body): Json<CreatePolicy>,
) -> Result<impl IntoResponse, AppError> {
    let repo = PolicyRepo::new(&pool);
    let row = repo.create(&body).await?;
    let value = serde_json::to_value(row)?;
    Ok((StatusCode::CREATED, Json(value)))
}

/// PUT /api/v1/policies/:id
pub async fn update_policy(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdatePolicy>,
) -> Result<Json<serde_json::Value>, AppError> {
    let repo = PolicyRepo::new(&pool);
    match repo.update(id, &body).await? {
        Some(row) => Ok(Json(serde_json::to_value(row)?)),
        None => Err(AppError::NotFound(format!("policy {id} not found"))),
    }
}

/// DELETE /api/v1/policies/:id
pub async fn delete_policy(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let repo = PolicyRepo::new(&pool);
    if repo.delete(id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound(format!("policy {id} not found")))
    }
}
