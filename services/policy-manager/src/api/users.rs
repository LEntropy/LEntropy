use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use nac_auth::local_auth::hash_password;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use super::endpoints::AppError;

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    #[serde(default = "default_role")]
    pub role: String,
}

fn default_role() -> String {
    "user".to_string()
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub role: String,
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub password: String,
}

/// GET /api/v1/users
pub async fn list_users(State(pool): State<PgPool>) -> Result<Json<Vec<UserResponse>>, AppError> {
    let rows = sqlx::query_as::<_, (Uuid, String, String, bool)>(
        "SELECT id, username, role, enabled FROM nac_users ORDER BY created_at",
    )
    .fetch_all(&pool)
    .await
    .map_err(anyhow::Error::from)?;

    let users = rows
        .into_iter()
        .map(|(id, username, role, enabled)| UserResponse {
            id,
            username,
            role,
            enabled,
        })
        .collect();

    Ok(Json(users))
}

/// POST /api/v1/users
pub async fn create_user(
    State(pool): State<PgPool>,
    Json(req): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, AppError> {
    if req.username.trim().is_empty() || req.password.len() < 8 {
        return Err(AppError::NotFound(
            "username required and password must be at least 8 characters".to_string(),
        ));
    }
    if !matches!(req.role.as_str(), "admin" | "user") {
        return Err(AppError::NotFound(
            "role must be 'admin' or 'user'".to_string(),
        ));
    }

    let hash = hash_password(&req.password)
        .map_err(|e| AppError::Db(anyhow::anyhow!("password hashing failed: {e}")))?;

    let row = sqlx::query_as::<_, (Uuid, String, String, bool)>(
        "INSERT INTO nac_users (username, password_hash, role) VALUES ($1, $2, $3) \
         RETURNING id, username, role, enabled",
    )
    .bind(req.username.trim())
    .bind(hash)
    .bind(&req.role)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        if e.to_string().contains("unique") {
            AppError::NotFound(format!("username '{}' already exists", req.username))
        } else {
            AppError::Db(anyhow::Error::from(e))
        }
    })?;

    let user = UserResponse {
        id: row.0,
        username: row.1,
        role: row.2,
        enabled: row.3,
    };

    tracing::info!(username = %user.username, role = %user.role, "user created");
    Ok((StatusCode::CREATED, Json(user)))
}

/// DELETE /api/v1/users/{id}
pub async fn delete_user(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let rows = sqlx::query("DELETE FROM nac_users WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .map_err(anyhow::Error::from)?;

    if rows.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("user {id} not found")));
    }

    tracing::info!(user_id = %id, "user deleted");
    Ok(StatusCode::NO_CONTENT)
}

/// PUT /api/v1/users/{id}/password
pub async fn change_password(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<StatusCode, AppError> {
    if req.password.len() < 8 {
        return Err(AppError::NotFound(
            "password must be at least 8 characters".to_string(),
        ));
    }

    let hash = hash_password(&req.password)
        .map_err(|e| AppError::Db(anyhow::anyhow!("password hashing failed: {e}")))?;

    let rows = sqlx::query("UPDATE nac_users SET password_hash = $1 WHERE id = $2")
        .bind(hash)
        .bind(id)
        .execute(&pool)
        .await
        .map_err(anyhow::Error::from)?;

    if rows.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("user {id} not found")));
    }

    tracing::info!(user_id = %id, "password changed");
    Ok(StatusCode::NO_CONTENT)
}

/// PATCH /api/v1/users/{id}/enable  or  /disable
pub async fn set_enabled(
    State(pool): State<PgPool>,
    Path((id, action)): Path<(Uuid, String)>,
) -> Result<StatusCode, AppError> {
    let enabled = match action.as_str() {
        "enable" => true,
        "disable" => false,
        _ => {
            return Err(AppError::NotFound(
                "action must be enable or disable".to_string(),
            ))
        }
    };

    let rows = sqlx::query("UPDATE nac_users SET enabled = $1 WHERE id = $2")
        .bind(enabled)
        .bind(id)
        .execute(&pool)
        .await
        .map_err(anyhow::Error::from)?;

    if rows.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("user {id} not found")));
    }

    tracing::info!(user_id = %id, enabled, "user enabled state changed");
    Ok(StatusCode::NO_CONTENT)
}
