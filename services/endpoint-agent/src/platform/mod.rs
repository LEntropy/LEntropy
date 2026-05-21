//! 플랫폼별 시스템 정보 수집.

use anyhow::Result;

#[derive(Debug, Clone, serde::Serialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub cpu_cores: u32,
    pub mem_total_mb: u64,
    pub agent_version: String,
}

pub fn collect() -> Result<SystemInfo> {
    let hostname = sys_info::hostname().unwrap_or_else(|_| "unknown".to_string());
    let os_type = sys_info::os_type().unwrap_or_else(|_| std::env::consts::OS.to_string());
    let os_release = sys_info::os_release().unwrap_or_else(|_| "unknown".to_string());
    let cpu_num = sys_info::cpu_num().unwrap_or(1);
    let mem = sys_info::mem_info().map(|m| m.total / 1024).unwrap_or(0);

    Ok(SystemInfo {
        hostname,
        os_name: os_type,
        os_version: os_release,
        cpu_cores: cpu_num,
        mem_total_mb: mem,
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_system_info() {
        let info = collect().unwrap();
        assert!(!info.hostname.is_empty());
        assert!(!info.os_name.is_empty());
        assert!(info.cpu_cores >= 1);
    }
}
