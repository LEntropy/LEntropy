//! Policy rule evaluator: matches a context against an ordered list of rules.

use crate::rule::{Condition, PolicyRule};
use crate::{PolicyContext, PolicyDecision, PolicyError};

/// Evaluate an ordered list of rules against a context.
///
/// Rules are evaluated in ascending priority order (lower value = higher priority).
/// Returns the decision of the first matching rule, or `Deny` if none match.
pub fn evaluate(
    rules: &mut [PolicyRule],
    ctx: &PolicyContext,
) -> Result<PolicyDecision, PolicyError> {
    rules.sort_by_key(|r| r.priority);

    for rule in rules.iter() {
        if matches_condition(&rule.condition, ctx) {
            return Ok(rule.decision.clone());
        }
    }

    Ok(PolicyDecision::Deny {
        reason: "no matching policy rule".into(),
    })
}

/// Recursively evaluate a condition against a context.
pub fn matches_condition(condition: &Condition, ctx: &PolicyContext) -> bool {
    match condition {
        Condition::OsFamily { value } => ctx.os_family.as_deref() == Some(value.as_str()),
        Condition::UserGroup { groups } => groups.iter().any(|g| ctx.groups.contains(g)),
        Condition::Compliant { required } => ctx.is_compliant == Some(*required),
        Condition::DeviceType { value } => ctx.device_type.as_deref() == Some(value.as_str()),
        Condition::And { conditions } => conditions.iter().all(|c| matches_condition(c, ctx)),
        Condition::Or { conditions } => conditions.iter().any(|c| matches_condition(c, ctx)),
        Condition::Not { condition } => !matches_condition(condition, ctx),
        Condition::MacList { macs } => macs
            .iter()
            .any(|m| m.to_uppercase() == ctx.mac_address.to_uppercase()),
        Condition::MacBlacklist { macs } => macs
            .iter()
            .any(|m| m.to_uppercase() == ctx.mac_address.to_uppercase()),
        // 아래 조건들은 posture 데이터가 필요하며 evaluate.rs의 condition_matches에서 처리됨
        // PolicyContext에는 posture 데이터가 없으므로 여기서는 false 반환
        Condition::OsVersionBelow { .. }
        | Condition::OsVersionAtLeast { .. }
        | Condition::SoftwareInstalled { .. }
        | Condition::SoftwareNotInstalled { .. }
        | Condition::HasMissingPatches
        | Condition::UsbEnabled
        | Condition::BluetoothEnabled
        | Condition::FolderSharingEnabled => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx(os: &str, groups: &[&str]) -> PolicyContext {
        PolicyContext {
            mac_address: "AA:BB:CC:DD:EE:FF".into(),
            os_family: Some(os.into()),
            groups: groups.iter().map(|s| s.to_string()).collect(),
            is_compliant: Some(true),
            ..Default::default()
        }
    }

    #[test]
    fn test_os_family_match() {
        let mut rules = vec![PolicyRule {
            name: "allow-windows".into(),
            priority: 10,
            condition: Condition::OsFamily {
                value: "Windows".into(),
            },
            decision: PolicyDecision::Allow,
        }];
        let ctx = make_ctx("Windows", &[]);
        let decision = evaluate(&mut rules, &ctx).unwrap();
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_no_match_returns_deny() {
        let mut rules = vec![PolicyRule {
            name: "allow-windows".into(),
            priority: 10,
            condition: Condition::OsFamily {
                value: "Windows".into(),
            },
            decision: PolicyDecision::Allow,
        }];
        let ctx = make_ctx("Linux", &[]);
        let decision = evaluate(&mut rules, &ctx).unwrap();
        matches!(decision, PolicyDecision::Deny { .. });
    }

    #[test]
    fn test_group_match() {
        let mut rules = vec![PolicyRule {
            name: "quarantine-guests".into(),
            priority: 5,
            condition: Condition::UserGroup {
                groups: vec!["guests".into()],
            },
            decision: PolicyDecision::Quarantine {
                vlan: 99,
                reason: "guest".into(),
            },
        }];
        let ctx = make_ctx("Windows", &["guests"]);
        let decision = evaluate(&mut rules, &ctx).unwrap();
        matches!(decision, PolicyDecision::Quarantine { .. });
    }

    #[test]
    fn test_mac_list_match() {
        use crate::rule::Condition;
        let mut rules = vec![PolicyRule {
            name: "mac-bypass".into(),
            priority: 1,
            condition: Condition::MacList {
                macs: vec!["AA:BB:CC:DD:EE:FF".into()],
            },
            decision: PolicyDecision::Allow,
        }];
        let ctx = PolicyContext {
            mac_address: "AA:BB:CC:DD:EE:FF".into(),
            ..Default::default()
        };
        let decision = evaluate(&mut rules, &ctx).unwrap();
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_mac_list_no_match() {
        use crate::rule::Condition;
        let mut rules = vec![PolicyRule {
            name: "mac-bypass".into(),
            priority: 1,
            condition: Condition::MacList {
                macs: vec!["AA:BB:CC:DD:EE:FF".into()],
            },
            decision: PolicyDecision::Allow,
        }];
        let ctx = PolicyContext {
            mac_address: "11:22:33:44:55:66".into(),
            ..Default::default()
        };
        let decision = evaluate(&mut rules, &ctx).unwrap();
        matches!(decision, PolicyDecision::Deny { .. });
    }

    #[test]
    fn test_compliant_condition() {
        use crate::rule::Condition;
        let mut rules = vec![PolicyRule {
            name: "require-compliance".into(),
            priority: 10,
            condition: Condition::Compliant { required: true },
            decision: PolicyDecision::Allow,
        }];
        // Compliant device → allowed
        let ctx = PolicyContext {
            mac_address: "AA:BB:CC:DD:EE:FF".into(),
            is_compliant: Some(true),
            ..Default::default()
        };
        let decision = evaluate(&mut rules, &ctx).unwrap();
        assert_eq!(decision, PolicyDecision::Allow);

        // Non-compliant → deny (no matching rule)
        let ctx2 = PolicyContext {
            mac_address: "AA:BB:CC:DD:EE:FF".into(),
            is_compliant: Some(false),
            ..Default::default()
        };
        let decision2 = evaluate(&mut rules, &ctx2).unwrap();
        matches!(decision2, PolicyDecision::Deny { .. });
    }

    #[test]
    fn test_priority_ordering() {
        use crate::rule::Condition;
        // Lower priority number wins
        let mut rules = vec![
            PolicyRule {
                name: "low-priority-deny".into(),
                priority: 100,
                condition: Condition::And { conditions: vec![] }, // always match
                decision: PolicyDecision::Deny {
                    reason: "low".into(),
                },
            },
            PolicyRule {
                name: "high-priority-allow".into(),
                priority: 1,
                condition: Condition::And { conditions: vec![] }, // always match
                decision: PolicyDecision::Allow,
            },
        ];
        let ctx = PolicyContext {
            mac_address: "AA:BB:CC:DD:EE:FF".into(),
            ..Default::default()
        };
        let decision = evaluate(&mut rules, &ctx).unwrap();
        assert_eq!(decision, PolicyDecision::Allow); // priority 1 wins
    }
}
