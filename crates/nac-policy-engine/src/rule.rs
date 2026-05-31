//! Policy rule definitions and condition types.

use crate::PolicyDecision;
use serde::{Deserialize, Serialize};

/// A single match condition within a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Condition {
    /// Match devices whose OS family equals the given value.
    OsFamily { value: String },
    /// Match devices belonging to any of the given user groups.
    UserGroup { groups: Vec<String> },
    /// Match by device compliance status.
    Compliant { required: bool },
    /// Match by device type (e.g. "Mobile", "IoT").
    DeviceType { value: String },
    /// Logical AND of multiple conditions.
    And { conditions: Vec<Condition> },
    /// Logical OR of multiple conditions.
    Or { conditions: Vec<Condition> },
    /// Logical NOT of a condition.
    Not { condition: Box<Condition> },
    /// MAC 주소 allowlist — 등록 단말 자동 허용(MAC bypass)에 사용
    MacList { macs: Vec<String> },
    /// OS 버전이 지정 버전보다 낮으면 매칭 (Windows: 빌드 번호 기준)
    OsVersionBelow { version: String },
    /// OS 버전이 지정 버전 이상이면 매칭
    OsVersionAtLeast { version: String },
    /// 특정 소프트웨어가 설치되어 있으면 매칭
    SoftwareInstalled { name: String },
    /// 특정 소프트웨어가 설치되어 있지 않으면 매칭
    SoftwareNotInstalled { name: String },
    /// 누락된 패치가 하나라도 있으면 매칭
    HasMissingPatches,
    /// USB 저장소가 활성화된 경우 매칭
    UsbEnabled,
    /// 블루투스가 활성화된 경우 매칭
    BluetoothEnabled,
    /// 폴더 공유가 활성화된 경우 매칭
    FolderSharingEnabled,
    /// MAC 주소 목록 — 블랙리스트 차단에 사용
    MacBlacklist { macs: Vec<String> },
}

/// A named policy rule with priority, conditions, and a resulting decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Human-readable rule name.
    pub name: String,
    /// Lower value = higher priority (evaluated first).
    pub priority: i32,
    /// Conditions that must match for this rule to trigger.
    pub condition: Condition,
    /// Decision to apply when this rule matches.
    pub decision: PolicyDecision,
}
