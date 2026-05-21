//! GET /api/v1/stats — 대시보드 통계

use axum::{extract::State, Json};
use serde::Serialize;
use sqlx::PgPool;

use super::endpoints::AppError;

/// 대시보드 통계 응답
#[derive(Debug, Serialize)]
pub struct Stats {
    pub total_endpoints: i64,
    pub allowed: i64,
    pub blocked: i64,
    pub quarantine: i64,
    pub pending: i64,
    pub recent_events: i64,
}

/// GET /api/v1/stats
pub async fn get_stats(State(pool): State<PgPool>) -> Result<Json<Stats>, AppError> {
    let row: (i64, i64, i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*)::bigint                                          AS total,
            COUNT(*) FILTER (WHERE status = 'allowed')::bigint       AS allowed,
            COUNT(*) FILTER (WHERE status = 'denied')::bigint        AS blocked,
            COUNT(*) FILTER (WHERE status = 'quarantined')::bigint   AS quarantine,
            COUNT(*) FILTER (WHERE status = 'pending')::bigint       AS pending
        FROM endpoints
        "#,
    )
    .fetch_one(&pool)
    .await
    .map_err(anyhow::Error::from)?;

    let (recent_events,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM audit_log WHERE created_at > NOW() - INTERVAL '24 hours'",
    )
    .fetch_one(&pool)
    .await
    .map_err(anyhow::Error::from)?;

    Ok(Json(Stats {
        total_endpoints: row.0,
        allowed: row.1,
        blocked: row.2,
        quarantine: row.3,
        pending: row.4,
        recent_events,
    }))
}
