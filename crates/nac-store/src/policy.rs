use anyhow::Result;
use nac_policy_engine::rule::{Condition, PolicyRule};
use nac_policy_engine::PolicyDecision;
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

/// DB에서 읽어온 정책 레코드
#[derive(Debug, sqlx::FromRow)]
pub struct PolicyRow {
    pub id: Uuid,
    pub name: String,
    pub priority: i32,
    pub conditions: serde_json::Value,
    pub action: String,
    pub vlan_id: Option<i16>,
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
            "SELECT id, name, priority, conditions, action, vlan_id \
             FROM policies WHERE enabled = true ORDER BY priority ASC",
        )
        .fetch_all(self.pool)
        .await?;

        rows.iter().map(to_policy_rule).collect()
    }
}

/// DB PolicyRow → nac-policy-engine PolicyRule 변환
fn to_policy_rule(row: &PolicyRow) -> Result<PolicyRule> {
    // conditions 컬럼이 빈 배열이면 항상 매칭되는 And{} 조건 사용
    let conditions: Vec<Condition> = if row.conditions.is_null()
        || row.conditions == serde_json::Value::Array(vec![])
    {
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
