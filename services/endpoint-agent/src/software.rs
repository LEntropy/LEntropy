//! 플랫폼별 소프트웨어 목록 및 장치 상태 수집.

pub struct InstalledSoftware {
    pub name: String,
    pub version: String,
}

/// 설치된 소프트웨어 목록 수집
pub fn collect_installed_software() -> Vec<InstalledSoftware> {
    collect_impl()
}

/// USB 저장소 장치가 연결/활성화 여부
pub fn usb_storage_enabled() -> bool {
    usb_impl()
}

/// 블루투스 컨트롤러 존재 여부
pub fn bluetooth_enabled() -> bool {
    bt_impl()
}

/// SMB/NFS 공유 폴더 서비스 실행 여부
pub fn folder_sharing_enabled() -> bool {
    sharing_impl()
}

// ── Linux 구현 ──────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn collect_impl() -> Vec<InstalledSoftware> {
    // 1순위: /var/lib/dpkg/status (Debian/Ubuntu)
    if let Ok(status) = std::fs::read_to_string("/var/lib/dpkg/status") {
        return parse_dpkg_status(&status);
    }

    // 2순위: rpm -qa (RHEL/CentOS/Fedora)
    if let Ok(out) = std::process::Command::new("rpm")
        .args(["-qa", "--queryformat", "%{NAME}\t%{VERSION}\n"])
        .output()
    {
        if out.status.success() {
            return String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|l| !l.is_empty())
                .filter_map(|l| {
                    let mut parts = l.splitn(2, '\t');
                    let name = parts.next()?.trim().to_string();
                    let version = parts.next().unwrap_or("").trim().to_string();
                    Some(InstalledSoftware { name, version })
                })
                .collect();
        }
    }

    vec![]
}

#[cfg(target_os = "linux")]
fn parse_dpkg_status(content: &str) -> Vec<InstalledSoftware> {
    let mut result = Vec::new();
    let mut name = String::new();
    let mut version = String::new();
    let mut installed = false;

    for line in content.lines() {
        if let Some(v) = line.strip_prefix("Package: ") {
            name = v.trim().to_string();
            version = String::new();
            installed = false;
        } else if let Some(v) = line.strip_prefix("Version: ") {
            version = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("Status: ") {
            installed = v.contains("install ok installed");
        } else if line.is_empty() && installed && !name.is_empty() {
            result.push(InstalledSoftware {
                name: name.clone(),
                version: version.clone(),
            });
        }
    }

    result
}

#[cfg(target_os = "linux")]
fn usb_impl() -> bool {
    // usb-storage 드라이버에 바인딩된 장치가 있으면 USB 저장소 연결됨
    std::fs::read_dir("/sys/bus/usb/drivers/usb-storage/")
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .any(|e| !e.file_name().to_string_lossy().starts_with('.'))
        })
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn bt_impl() -> bool {
    // /sys/class/bluetooth/ 에 HCI 어댑터가 등록된 경우 BT 활성
    std::fs::read_dir("/sys/class/bluetooth/")
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .any(|e| !e.file_name().to_string_lossy().starts_with('.'))
        })
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn sharing_impl() -> bool {
    // /proc/<pid>/comm 파일로 smbd / nfsd 프로세스 존재 확인
    let Ok(proc) = std::fs::read_dir("/proc") else {
        return false;
    };
    proc.filter_map(|e| e.ok()).any(|entry| {
        let comm_path = entry.path().join("comm");
        std::fs::read_to_string(comm_path)
            .map(|s| {
                let s = s.trim();
                s == "smbd" || s == "nfsd" || s == "nfs-server"
            })
            .unwrap_or(false)
    })
}

// ── Windows 구현 ────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn collect_impl() -> Vec<InstalledSoftware> {
    // PowerShell로 설치 목록 조회
    let ps_cmd = r#"
        Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
            HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
            Where-Object DisplayName |
            Select-Object DisplayName,DisplayVersion |
            ConvertTo-Json -Compress
    "#;

    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", ps_cmd])
        .output();

    let Ok(out) = out else {
        return vec![];
    };

    if !out.status.success() {
        return vec![];
    }

    #[derive(serde::Deserialize)]
    struct WinPkg {
        #[serde(rename = "DisplayName")]
        display_name: Option<String>,
        #[serde(rename = "DisplayVersion")]
        display_version: Option<String>,
    }

    let json = String::from_utf8_lossy(&out.stdout);
    // PowerShell returns object or array depending on count
    let pkgs: Vec<WinPkg> = if json.trim_start().starts_with('[') {
        serde_json::from_str(&json).unwrap_or_default()
    } else {
        serde_json::from_str::<WinPkg>(&json)
            .map(|p| vec![p])
            .unwrap_or_default()
    };

    pkgs.into_iter()
        .filter_map(|p| {
            Some(InstalledSoftware {
                name: p.display_name?,
                version: p.display_version.unwrap_or_default(),
            })
        })
        .collect()
}

#[cfg(target_os = "windows")]
fn usb_impl() -> bool {
    // USB 대용량 저장소 장치 쿼리
    std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "(Get-PnpDevice -Class USB | Where-Object Status -eq OK | Where-Object FriendlyName -like '*Mass Storage*').Count -gt 0",
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "True")
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn bt_impl() -> bool {
    std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "(Get-PnpDevice -Class Bluetooth | Where-Object Status -eq OK).Count -gt 0",
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "True")
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn sharing_impl() -> bool {
    std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "(Get-SmbShare | Where-Object Name -ne 'IPC$').Count -gt 0",
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "True")
        .unwrap_or(false)
}

// ── macOS 구현 ──────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn collect_impl() -> Vec<InstalledSoftware> {
    let out = std::process::Command::new("system_profiler")
        .args(["SPApplicationsDataType", "-json"])
        .output();

    let Ok(out) = out else {
        return vec![];
    };

    #[derive(serde::Deserialize)]
    struct MacApp {
        #[serde(rename = "_name")]
        name: Option<String>,
        version: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct Root {
        #[serde(rename = "SPApplicationsDataType")]
        apps: Vec<MacApp>,
    }

    serde_json::from_slice::<Root>(&out.stdout)
        .map(|r| {
            r.apps
                .into_iter()
                .filter_map(|a| {
                    Some(InstalledSoftware {
                        name: a.name?,
                        version: a.version.unwrap_or_default(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn usb_impl() -> bool {
    // system_profiler SPUSBDataType - 간단히 Mass Storage 존재 여부
    std::process::Command::new("system_profiler")
        .args(["SPUSBDataType"])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .to_lowercase()
                .contains("mass storage")
        })
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn bt_impl() -> bool {
    std::process::Command::new("system_profiler")
        .args(["SPBluetoothDataType"])
        .output()
        .map(|o| {
            let s = String::from_utf8_lossy(&o.stdout).to_lowercase();
            s.contains("state: on") || s.contains("bluetooth power: on")
        })
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn sharing_impl() -> bool {
    std::process::Command::new("defaults")
        .args([
            "read",
            "/var/db/launchd.db/com.apple.launchd/overrides.plist",
            "com.apple.smbd",
        ])
        .output()
        .map(|o| {
            !String::from_utf8_lossy(&o.stdout)
                .to_lowercase()
                .contains("disabled = 1")
        })
        .unwrap_or(false)
}

// ── 기타 플랫폼 폴백 ────────────────────────────────────────────────────────

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn collect_impl() -> Vec<InstalledSoftware> {
    vec![]
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn usb_impl() -> bool {
    false
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn bt_impl() -> bool {
    false
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn sharing_impl() -> bool {
    false
}
