use anyhow::Result;
use nac_policy_engine::rule::{Condition, PolicyRule};
use nac_policy_engine::PolicyDecision;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// DB에서 읽어온 정책 레코드
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PolicyRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub priority: i32,
    pub conditions: serde_json::Value,
    pub action: String,
    pub vlan_id: Option<i16>,
    pub enabled: bool,
    pub created_at: OffsetDateTime,
}

/// 정책 생성 파라미터
#[derive(Debug, Clone, Deserialize)]
pub struct CreatePolicy {
    pub name: String,
    pub description: Option<String>,
    pub priority: i32,
    pub conditions: Option<serde_json::Value>,
    pub action: String,
    pub vlan_id: Option<i16>,
}

/// 정책 부분 업데이트 파라미터
#[derive(Debug, Clone, Deserialize)]
pub struct UpdatePolicy {
    pub name: Option<String>,
    pub description: Option<String>,
    pub priority: Option<i32>,
    pub conditions: Option<serde_json::Value>,
    pub action: Option<String>,
    pub vlan_id: Option<i16>,
    pub enabled: Option<bool>,
}

/// 정책 레포지토리
pub struct PolicyRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> PolicyRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    /// 활성화된 정책을 우선순위 순으로 모두 로드해 PolicyRule 목록으로 반환
    pub async fn load_rules(&self) -> Result<Vec<PolicyRule>> {
        let rows = sqlx::query_as::<_, PolicyRow>(
            "SELECT id, name, description, priority, conditions, action, vlan_id, enabled, created_at \
             FROM policies WHERE enabled = true ORDER BY priority ASC",
        )
        .fetch_all(self.pool)
        .await?;

        rows.iter().map(to_policy_rule).collect()
    }

    /// 모든 정책 목록 반환 (우선순위 순)
    pub async fn list_all(&self) -> Result<Vec<PolicyRow>> {
        let rows = sqlx::query_as::<_, PolicyRow>(
            "SELECT id, name, description, priority, conditions, action, vlan_id, enabled, created_at \
             FROM policies ORDER BY priority ASC",
        )
        .fetch_all(self.pool)
        .await?;
        Ok(rows)
    }

    /// ID로 정책 조회
    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<PolicyRow>> {
        let row = sqlx::query_as::<_, PolicyRow>(
            "SELECT id, name, description, priority, conditions, action, vlan_id, enabled, created_at \
             FROM policies WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(self.pool)
        .await?;
        Ok(row)
    }

    /// 정책 생성
    pub async fn create(&self, p: &CreatePolicy) -> Result<PolicyRow> {
        let row = sqlx::query_as::<_, PolicyRow>(
            r#"
            INSERT INTO policies (name, description, priority, conditions, action, vlan_id, enabled)
            VALUES ($1, $2, $3, $4, $5, $6, true)
            RETURNING id, name, description, priority, conditions, action, vlan_id, enabled, created_at
            "#,
        )
        .bind(&p.name)
        .bind(&p.description)
        .bind(p.priority)
        .bind(p.conditions.as_ref().unwrap_or(&serde_json::json!([])))
        .bind(&p.action)
        .bind(p.vlan_id)
        .fetch_one(self.pool)
        .await?;
        Ok(row)
    }

    /// 정책 부분 업데이트
    pub async fn update(&self, id: Uuid, p: &UpdatePolicy) -> Result<Option<PolicyRow>> {
        // 먼저 기존 레코드 조회
        let existing = match self.find_by_id(id).await? {
            Some(r) => r,
            None => return Ok(None),
        };

        let name = p.name.as_deref().unwrap_or(&existing.name);
        let description = p.description.as_deref().or(existing.description.as_deref());
        let priority = p.priority.unwrap_or(existing.priority);
        let conditions = p.conditions.as_ref().unwrap_or(&existing.conditions);
        let action = p.action.as_deref().unwrap_or(&existing.action);
        let vlan_id = if p.vlan_id.is_some() {
            p.vlan_id
        } else {
            existing.vlan_id
        };
        let enabled = p.enabled.unwrap_or(existing.enabled);

        let row = sqlx::query_as::<_, PolicyRow>(
            r#"
            UPDATE policies
            SET name = $1, description = $2, priority = $3, conditions = $4,
                action = $5, vlan_id = $6, enabled = $7
            WHERE id = $8
            RETURNING id, name, description, priority, conditions, action, vlan_id, enabled, created_at
            "#,
        )
        .bind(name)
        .bind(description)
        .bind(priority)
        .bind(conditions)
        .bind(action)
        .bind(vlan_id)
        .bind(enabled)
        .bind(id)
        .fetch_optional(self.pool)
        .await?;
        Ok(row)
    }

    /// 정책 삭제 — 삭제되면 true 반환
    pub async fn delete(&self, id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM policies WHERE id = $1")
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// 활성화된 정책을 (UUID, PolicyRule) 쌍으로 반환 — evaluate에서 수동 할당 정책 조회용
    pub async fn load_rules_with_id(&self) -> Result<Vec<(Uuid, PolicyRule)>> {
        let rows = sqlx::query_as::<_, PolicyRow>(
            "SELECT id, name, description, priority, conditions, action, vlan_id, enabled, created_at \
             FROM policies WHERE enabled = true ORDER BY priority ASC",
        )
        .fetch_all(self.pool)
        .await?;

        rows.iter()
            .map(|r| Ok((r.id, to_policy_rule(r)?)))
            .collect()
    }

    /// 비활성 정책 포함 — 수동 할당된 정책이 비활성이어도 적용하기 위해 사용
    pub async fn find_rule_by_id(&self, id: Uuid) -> Result<Option<PolicyRule>> {
        match self.find_by_id(id).await? {
            Some(r) => Ok(Some(to_policy_rule(&r)?)),
            None => Ok(None),
        }
    }
}

/// DB PolicyRow → nac-policy-engine PolicyRule 변환
pub fn to_policy_rule(row: &PolicyRow) -> Result<PolicyRule> {
    // conditions 컬럼이 빈 배열이면 항상 매칭되는 And{} 조건 사용
    let conditions: Vec<Condition> =
        if row.conditions.is_null() || row.conditions == serde_json::Value::Array(vec![]) {
            vec![]
        } else {
            serde_json::from_value::<Vec<Condition>>(row.conditions.clone())?
        };

    let condition = match conditions.len() {
        0 => Condition::And { conditions: vec![] }, // always-match (e.g. default-allow)
        1 => conditions.into_iter().next().unwrap(),
        _ => Condition::And { conditions },
    };

    let decision = match row.action.as_str() {
        "allow" => PolicyDecision::Allow,
        "quarantine" => PolicyDecision::Quarantine {
            vlan: row.vlan_id.unwrap_or(99) as u16,
            reason: format!("policy: {}", row.name),
        },
        _ => PolicyDecision::Deny {
            reason: format!("policy: {}", row.name),
        },
    };

    Ok(PolicyRule {
        name: row.name.clone(),
        priority: row.priority,
        condition,
        decision,
    })
}

/// PolicyDecision을 DB status 컬럼 값으로 변환
pub fn decision_to_status(decision: &PolicyDecision) -> &'static str {
    match decision {
        PolicyDecision::Allow | PolicyDecision::AllowVlan(_) => "allowed",
        PolicyDecision::Quarantine { .. } => "quarantined",
        PolicyDecision::Deny { .. } => "denied",
    }
}

/// PolicyDecision 역직렬화용 헬퍼 (Deserialize가 없어 별도 구현)
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConditionDef {
    OsFamily { value: String },
    UserGroup { groups: Vec<String> },
    Compliant { required: bool },
    DeviceType { value: String },
    And { conditions: Vec<ConditionDef> },
    Or { conditions: Vec<ConditionDef> },
    Not { condition: Box<ConditionDef> },
}
