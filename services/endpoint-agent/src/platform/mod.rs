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
    /// 기본 네트워크 인터페이스의 하드웨어 MAC (없으면 빈 문자열)
    pub primary_mac: String,
}

pub fn collect() -> Result<SystemInfo> {
    let hostname = sys_info::hostname().unwrap_or_else(|_| "unknown".to_string());
    let cpu_num = sys_info::cpu_num().unwrap_or(1);
    let mem = sys_info::mem_info().map(|m| m.total / 1024).unwrap_or(0);
    let primary_mac = collect_primary_mac();

    // Windows: sys-info가 GetVersionEx(deprecated)를 써서 항상 "6.2"를 반환.
    // CIM Win32_OperatingSystem으로 정확한 정보 수집.
    #[cfg(target_os = "windows")]
    let (os_name, os_version) = windows_os_info();
    #[cfg(not(target_os = "windows"))]
    let os_name = sys_info::os_type().unwrap_or_else(|_| std::env::consts::OS.to_string());
    #[cfg(not(target_os = "windows"))]
    let os_version = sys_info::os_release().unwrap_or_else(|_| "unknown".to_string());

    Ok(SystemInfo {
        hostname,
        os_name,
        os_version,
        cpu_cores: cpu_num,
        mem_total_mb: mem,
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        primary_mac,
    })
}

/// Windows 10/11의 정확한 OS 이름과 버전을 CIM으로 조회.
/// sys-info::os_release()는 GetVersionEx를 써서 Windows 10에서도 "6.2.9200"을 반환하는 버그가 있음.
#[cfg(target_os = "windows")]
fn windows_os_info() -> (String, String) {
    use std::process::Command;
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "$o = Get-CimInstance Win32_OperatingSystem; \"$($o.Caption)|$($o.Version)\"",
        ])
        .output();

    if let Ok(out) = out {
        let s = String::from_utf8_lossy(&out.stdout);
        let s = s.trim();
        if let Some((caption, version)) = s.split_once('|') {
            let caption = caption.trim().trim_start_matches("Microsoft ").to_string();
            return (caption, version.trim().to_string());
        }
    }
    ("Windows".to_string(), String::new())
}

/// 기본 네트워크 인터페이스의 MAC 주소 수집 (플랫폼별 구현)
fn collect_primary_mac() -> String {
    #[cfg(target_os = "linux")]
    {
        linux_primary_mac()
    }
    #[cfg(target_os = "windows")]
    {
        windows_primary_mac()
    }
    #[cfg(target_os = "macos")]
    {
        macos_primary_mac()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        String::new()
    }
}

#[cfg(target_os = "linux")]
fn linux_primary_mac() -> String {
    // 우선순위: eth0 → enp* → wlan0 → wlp* → 첫 번째 실제 인터페이스
    let candidates = ["eth0", "eth1", "enp0s3", "enp0s8"];
    for iface in &candidates {
        if let Ok(mac) = read_linux_mac(iface) {
            return mac;
        }
    }
    // 후보 없으면 /sys/class/net 순회
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        let mut names: Vec<String> = entries
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n != "lo")
            .collect();
        names.sort();
        for name in &names {
            if let Ok(mac) = read_linux_mac(name) {
                return mac;
            }
        }
    }
    String::new()
}

#[cfg(target_os = "linux")]
fn read_linux_mac(iface: &str) -> Result<String> {
    let path = format!("/sys/class/net/{}/address", iface);
    let raw = std::fs::read_to_string(&path)?;
    let mac = raw.trim().to_string();
    // 올바른 MAC이고 all-zero가 아닌지 확인
    if mac.len() == 17 && mac != "00:00:00:00:00:00" {
        Ok(mac)
    } else {
        Err(anyhow::anyhow!("invalid mac"))
    }
}

#[cfg(target_os = "windows")]
fn windows_primary_mac() -> String {
    use std::process::Command;
    // getmac /fo csv /nh → 첫 번째 행에서 MAC 추출
    let out = Command::new("getmac")
        .args(["/fo", "csv", "/nh"])
        .output()
        .ok();
    if let Some(out) = out {
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            let parts: Vec<&str> = line.splitn(3, ',').collect();
            if let Some(mac_raw) = parts.first() {
                let mac = mac_raw.trim().trim_matches('"');
                // Windows: "AA-BB-CC-DD-EE-FF" 형식 → 소문자 콜론
                let normalized = mac.replace('-', ":").to_lowercase();
                if normalized.len() == 17 && normalized != "00:00:00:00:00:00" {
                    return normalized;
                }
            }
        }
    }
    String::new()
}

#[cfg(target_os = "macos")]
fn macos_primary_mac() -> String {
    use std::process::Command;
    // networksetup -listallhardwareports → Hardware Port/Device/Ethernet Address 순으로 출력
    let out = Command::new("networksetup")
        .args(["-listallhardwareports"])
        .output()
        .ok();
    if let Some(out) = out {
        let s = String::from_utf8_lossy(&out.stdout);
        let mut lines = s.lines().peekable();
        while let Some(line) = lines.next() {
            if line.contains("Ethernet Address:") {
                let mac = line
                    .split(':')
                    .skip(1)
                    .collect::<Vec<_>>()
                    .join(":")
                    .trim()
                    .to_lowercase();
                if mac.len() == 17 && mac != "00:00:00:00:00:00" {
                    return mac;
                }
            }
        }
    }
    String::new()
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
