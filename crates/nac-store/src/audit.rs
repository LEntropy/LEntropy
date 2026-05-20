use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// 감사 로그 레코드
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditRow {
    pub id: i64,
    pub event_type: String,
    pub endpoint_id: Option<Uuid>,
    pub actor: Option<String>,
    pub detail: Option<serde_json::Value>,
    pub created_at: OffsetDateTime,
}

/// 감사 로그 레포지토리
pub struct AuditRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> AuditRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    /// 이벤트를 audit_log 테이블에 기록
    pub async fn log(
        &self,
        event_type: &str,
        endpoint_id: Option<Uuid>,
        actor: &str,
        detail: serde_json::Value,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO audit_log (event_type, endpoint_id, actor, detail) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(event_type)
        .bind(endpoint_id)
        .bind(actor)
        .bind(detail)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// 감사 로그 목록 조회 (페이지네이션, 단말 ID 필터 지원)
    pub async fn list(
        &self,
        limit: i64,
        offset: i64,
        endpoint_id: Option<Uuid>,
    ) -> Result<Vec<AuditRow>> {
        let rows = if let Some(eid) = endpoint_id {
            sqlx::query_as::<_, AuditRow>(
                "SELECT id, event_type, endpoint_id, actor, detail, created_at \
                 FROM audit_log \
                 WHERE endpoint_id = $1 \
                 ORDER BY created_at DESC \
                 LIMIT $2 OFFSET $3",
            )
            .bind(eid)
            .bind(limit)
            .bind(offset)
            .fetch_all(self.pool)
            .await?
        } else {
            sqlx::query_as::<_, AuditRow>(
                "SELECT id, event_type, endpoint_id, actor, detail, created_at \
                 FROM audit_log \
                 ORDER BY created_at DESC \
                 LIMIT $1 OFFSET $2",
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(self.pool)
            .await?
        };
        Ok(rows)
    }

    /// 감사 로그 전체 수 (단말 ID 필터 지원)
    pub async fn count(&self, endpoint_id: Option<Uuid>) -> Result<i64> {
        let (count,): (i64,) = if let Some(eid) = endpoint_id {
            sqlx::query_as("SELECT COUNT(*)::bigint FROM audit_log WHERE endpoint_id = $1")
                .bind(eid)
                .fetch_one(self.pool)
                .await?
        } else {
            sqlx::query_as("SELECT COUNT(*)::bigint FROM audit_log")
                .fetch_one(self.pool)
                .await?
        };
        Ok(count)
    }
}
