//! 엔드포인트 컴플라이언스 체크 (소프트웨어, OS 패치).

use anyhow::Result;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ComplianceReport {
    pub is_compliant: bool,
    pub checks: Vec<ComplianceCheck>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ComplianceCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// 기본 컴플라이언스 체크 수행
pub fn run_checks() -> Result<ComplianceReport> {
    let mut checks = Vec::new();

    // 체크 1: OS 타입 확인
    let os = std::env::consts::OS;
    checks.push(ComplianceCheck {
        name: "os_supported".to_string(),
        passed: matches!(os, "linux" | "windows" | "macos"),
        detail: format!("OS: {os}"),
    });

    // 체크 2: 환경변수로 root 여부 판단 (libc 의존성 없이)
    let is_root = std::env::var("USER").map(|u| u == "root").unwrap_or(false)
        || std::env::var("LOGNAME")
            .map(|u| u == "root")
            .unwrap_or(false);
    checks.push(ComplianceCheck {
        name: "not_running_as_root".to_string(),
        passed: !is_root,
        detail: if is_root {
            "running as root".to_string()
        } else {
            "non-root".to_string()
        },
    });

    // 체크 3: 환경변수 기반 보안 정책 (확장 포인트)
    let disk_encrypt_ok = std::env::var("NAC_DISK_ENCRYPT_OK")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);
    checks.push(ComplianceCheck {
        name: "disk_encryption".to_string(),
        passed: disk_encrypt_ok,
        detail: if disk_encrypt_ok {
            "enabled".to_string()
        } else {
            "not confirmed".to_string()
        },
    });

    let is_compliant = checks.iter().all(|c| c.passed);
    Ok(ComplianceReport {
        is_compliant,
        checks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_checks_returns_report() {
        let report = run_checks().unwrap();
        // OS 체크는 항상 통과해야 함
        let os_check = report.checks.iter().find(|c| c.name == "os_supported");
        assert!(os_check.is_some());
        assert!(os_check.unwrap().passed);
    }
}
