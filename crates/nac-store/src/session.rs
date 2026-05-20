use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// DB에서 읽어온 세션 레코드
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SessionRow {
    pub id: Uuid,
    pub endpoint_id: Uuid,
    pub username: Option<String>,
    pub auth_method: Option<String>,
    pub state: String,
    pub vlan_id: Option<i16>,
    pub started_at: OffsetDateTime,
    pub ended_at: Option<OffsetDateTime>,
    pub updated_at: OffsetDateTime,
}

/// 세션 생성 파라미터
pub struct CreateSession {
    pub endpoint_id: Uuid,
    pub auth_method: String, // "captive_portal", "mac_bypass"
    pub vlan_id: Option<i16>,
}

/// 세션 레코드 조회/저장 레포지토리
pub struct SessionRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> SessionRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    /// 새 세션 생성 (state = "detecting")
    pub async fn create(&self, s: &CreateSession) -> Result<SessionRow> {
        let row = sqlx::query_as::<_, SessionRow>(
            r#"
            INSERT INTO sessions (endpoint_id, auth_method, vlan_id)
            VALUES ($1, $2, $3)
            RETURNING id, endpoint_id, username, auth_method, state, vlan_id,
                      started_at, ended_at, updated_at
            "#,
        )
        .bind(s.endpoint_id)
        .bind(&s.auth_method)
        .bind(s.vlan_id)
        .fetch_one(self.pool)
        .await?;

        Ok(row)
    }

    /// 단말 ID로 활성 세션 조회 (ended_at IS NULL)
    pub async fn find_active_by_endpoint(&self, endpoint_id: Uuid) -> Result<Option<SessionRow>> {
        let row = sqlx::query_as::<_, SessionRow>(
            r#"
            SELECT id, endpoint_id, username, auth_method, state, vlan_id,
                   started_at, ended_at, updated_at
            FROM sessions
            WHERE endpoint_id = $1 AND ended_at IS NULL
            ORDER BY started_at DESC
            LIMIT 1
            "#,
        )
        .bind(endpoint_id)
        .fetch_optional(self.pool)
        .await?;

        Ok(row)
    }

    /// 세션 ID로 조회
    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<SessionRow>> {
        let row = sqlx::query_as::<_, SessionRow>(
            r#"
            SELECT id, endpoint_id, username, auth_method, state, vlan_id,
                   started_at, ended_at, updated_at
            FROM sessions
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(self.pool)
        .await?;

        Ok(row)
    }

    /// 상태 전이 + username 업데이트
    pub async fn transition(
        &self,
        id: Uuid,
        new_state: &str,
        username: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE sessions SET state = $1, username = COALESCE($2, username), \
             updated_at = NOW() WHERE id = $3",
        )
        .bind(new_state)
        .bind(username)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// 세션 종료 (ended_at = NOW(), state = "terminated")
    pub async fn terminate(&self, id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE sessions SET state = 'terminated', ended_at = NOW(), \
             updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }
}
