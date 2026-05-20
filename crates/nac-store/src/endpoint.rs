use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// DB에서 읽어온 단말 레코드
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EndpointRow {
    pub id: Uuid,
    pub mac_address: String,
    pub ip_address: Option<String>,
    pub hostname: Option<String>,
    pub os_family: Option<String>,
    pub os_version: Option<String>,
    pub device_type: Option<String>,
    pub vendor: Option<String>,
    pub vlan_id: Option<i16>,
    pub switch_port: Option<String>,
    pub interface: Option<String>,
    pub username: Option<String>,
    pub status: String,
    pub first_seen: OffsetDateTime,
    pub last_seen: OffsetDateTime,
    pub is_compliant: Option<bool>,
    pub last_posture_check: Option<OffsetDateTime>,
}

/// 단말 신규 등록 / 업서트용 파라미터
#[derive(Debug, Clone)]
pub struct UpsertEndpoint {
    pub mac_address: String,
    pub ip_address: Option<String>,
    pub hostname: Option<String>,
    pub os_family: Option<String>,
    pub os_version: Option<String>,
    pub device_type: Option<String>,
    pub vendor: Option<String>,
    pub interface: Option<String>,
}

/// 단말 레코드 조회/저장 레포지토리
pub struct EndpointRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> EndpointRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    /// MAC 기준 업서트 — 없으면 INSERT, 있으면 ip/hostname/last_seen 갱신
    pub async fn upsert(&self, ep: &UpsertEndpoint) -> Result<EndpointRow> {
        let row = sqlx::query_as::<_, EndpointRow>(
            r#"
            INSERT INTO endpoints (mac_address, ip_address, hostname,
                                   os_family, os_version, device_type,
                                   vendor, interface)
            VALUES ($1, $2::inet, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (mac_address) DO UPDATE SET
                ip_address  = COALESCE(EXCLUDED.ip_address,  endpoints.ip_address),
                hostname    = COALESCE(EXCLUDED.hostname,    endpoints.hostname),
                os_family   = COALESCE(EXCLUDED.os_family,   endpoints.os_family),
                os_version  = COALESCE(EXCLUDED.os_version,  endpoints.os_version),
                device_type = COALESCE(EXCLUDED.device_type, endpoints.device_type),
                vendor      = COALESCE(EXCLUDED.vendor,      endpoints.vendor),
                interface   = COALESCE(EXCLUDED.interface,   endpoints.interface),
                last_seen   = NOW()
            RETURNING
                id, mac_address::text, ip_address::text,
                hostname, os_family, os_version, device_type, vendor,
                vlan_id, switch_port, interface, username, status,
                first_seen, last_seen, is_compliant, last_posture_check
            "#,
        )
        .bind(&ep.mac_address)
        .bind(&ep.ip_address)
        .bind(&ep.hostname)
        .bind(&ep.os_family)
        .bind(&ep.os_version)
        .bind(&ep.device_type)
        .bind(&ep.vendor)
        .bind(&ep.interface)
        .fetch_one(self.pool)
        .await?;

        Ok(row)
    }

    /// 전체 단말 목록 (최근 탐지 순)
    pub async fn list(&self, limit: i64, offset: i64) -> Result<Vec<EndpointRow>> {
        let rows = sqlx::query_as::<_, EndpointRow>(
            r#"
            SELECT id, mac_address::text, ip_address::text,
                   hostname, os_family, os_version, device_type, vendor,
                   vlan_id, switch_port, interface, username, status,
                   first_seen, last_seen, is_compliant, last_posture_check
            FROM endpoints
            ORDER BY last_seen DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(self.pool)
        .await?;

        Ok(rows)
    }

    /// MAC 주소로 단말 조회
    pub async fn find_by_mac(&self, mac: &str) -> Result<Option<EndpointRow>> {
        let row = sqlx::query_as::<_, EndpointRow>(
            r#"
            SELECT id, mac_address::text, ip_address::text,
                   hostname, os_family, os_version, device_type, vendor,
                   vlan_id, switch_port, interface, username, status,
                   first_seen, last_seen, is_compliant, last_posture_check
            FROM endpoints
            WHERE mac_address = $1::macaddr
            "#,
        )
        .bind(mac)
        .fetch_optional(self.pool)
        .await?;

        Ok(row)
    }

    /// ID로 단말 조회
    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<EndpointRow>> {
        let row = sqlx::query_as::<_, EndpointRow>(
            r#"
            SELECT id, mac_address::text, ip_address::text,
                   hostname, os_family, os_version, device_type, vendor,
                   vlan_id, switch_port, interface, username, status,
                   first_seen, last_seen, is_compliant, last_posture_check
            FROM endpoints
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(self.pool)
        .await?;

        Ok(row)
    }

    /// 상태 변경
    pub async fn set_status(&self, id: Uuid, status: &str) -> Result<()> {
        sqlx::query("UPDATE endpoints SET status = $1 WHERE id = $2")
            .bind(status)
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// username 업데이트
    pub async fn set_username(&self, id: Uuid, username: &str) -> Result<()> {
        sqlx::query("UPDATE endpoints SET username = $1 WHERE id = $2")
            .bind(username)
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// compliance 업데이트
    pub async fn set_compliance(&self, id: Uuid, is_compliant: bool) -> Result<()> {
        sqlx::query(
            "UPDATE endpoints SET is_compliant = $1, last_posture_check = NOW() WHERE id = $2",
        )
        .bind(is_compliant)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// 전체 단말 수
    pub async fn count(&self) -> Result<i64> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM endpoints")
            .fetch_one(self.pool)
            .await?;
        Ok(count)
    }
}
