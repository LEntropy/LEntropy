//! Policy rule evaluator: matches a context against an ordered list of rules.

use crate::{PolicyContext, PolicyDecision, PolicyError};
use crate::rule::{Condition, PolicyRule};

/// Evaluate an ordered list of rules against a context.
///
/// Rules are evaluated in ascending priority order (lower value = higher priority).
/// Returns the decision of the first matching rule, or `Deny` if none match.
pub fn evaluate(
    rules: &mut Vec<PolicyRule>,
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
        Condition::OsFamily { value } => {
            ctx.os_family.as_deref() == Some(value.as_str())
        }
        Condition::UserGroup { groups } => {
            groups.iter().any(|g| ctx.groups.contains(g))
        }
        Condition::Compliant { required } => {
            ctx.is_compliant == Some(*required)
        }
        Condition::DeviceType { value } => {
            ctx.device_type.as_deref() == Some(value.as_str())
        }
        Condition::And { conditions } => {
            conditions.iter().all(|c| matches_condition(c, ctx))
        }
        Condition::Or { conditions } => {
            conditions.iter().any(|c| matches_condition(c, ctx))
        }
        Condition::Not { condition } => {
            !matches_condition(condition, ctx)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx(os: &str, groups: &[&str]) -> PolicyContext {
        PolicyContext {
            mac_address:  "AA:BB:CC:DD:EE:FF".into(),
            os_family:    Some(os.into()),
            groups:       groups.iter().map(|s| s.to_string()).collect(),
            is_compliant: Some(true),
            ..Default::default()
        }
    }

    #[test]
    fn test_os_family_match() {
        let mut rules = vec![PolicyRule {
            name:      "allow-windows".into(),
            priority:  10,
            condition: Condition::OsFamily { value: "Windows".into() },
            decision:  PolicyDecision::Allow,
        }];
        let ctx = make_ctx("Windows", &[]);
        let decision = evaluate(&mut rules, &ctx).unwrap();
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_no_match_returns_deny() {
        let mut rules = vec![PolicyRule {
            name:      "allow-windows".into(),
            priority:  10,
            condition: Condition::OsFamily { value: "Windows".into() },
            decision:  PolicyDecision::Allow,
        }];
        let ctx = make_ctx("Linux", &[]);
        let decision = evaluate(&mut rules, &ctx).unwrap();
        matches!(decision, PolicyDecision::Deny { .. });
    }

    #[test]
    fn test_group_match() {
        let mut rules = vec![PolicyRule {
            name:      "quarantine-guests".into(),
            priority:  5,
            condition: Condition::UserGroup { groups: vec!["guests".into()] },
            decision:  PolicyDecision::Quarantine { vlan: 99, reason: "guest".into() },
        }];
        let ctx = make_ctx("Windows", &["guests"]);
        let decision = evaluate(&mut rules, &ctx).unwrap();
        matches!(decision, PolicyDecision::Quarantine { .. });
    }
}
