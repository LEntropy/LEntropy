use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

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
}
