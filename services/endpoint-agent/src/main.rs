//! endpoint-agent: NAC endpoint agent daemon.
//! Windows/macOS/Linux 크로스 컴파일 바이너리.

use std::time::Duration;

use anyhow::Result;
use tracing::{error, info};
use tracing_subscriber::{fmt, EnvFilter};

mod compliance;
mod platform;
mod software;
mod transport;

#[tokio::main]
async fn main() -> Result<()> {
    fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!(
        service = "endpoint-agent",
        version = env!("CARGO_PKG_VERSION"),
        "starting up"
    );

    let gateway_addr = std::env::var("AGENT_GATEWAY_ADDR")
        .unwrap_or_else(|_| "http://localhost:50051".to_string());
    let checkin_interval_secs: u64 = std::env::var("CHECKIN_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);

    // 디바이스 ID: 파일 기반 영속 또는 새 UUID
    let device_id = load_or_create_device_id()?;
    info!(device_id, "device identity loaded");

    // 시스템 정보 수집
    let sys = platform::collect()?;
    info!(
        hostname = sys.hostname,
        os = sys.os_name,
        version = sys.os_version,
        "system info collected"
    );

    // gateway 연결
    let mut transport =
        match transport::AgentTransport::connect(&gateway_addr, device_id.clone()).await {
            Ok(t) => {
                info!("connected to agent-gateway");
                t
            }
            Err(e) => {
                error!(error = %e, "failed to connect to agent-gateway — running in offline mode");
                let report = compliance::run_checks()?;
                info!(
                    is_compliant = report.is_compliant,
                    "offline compliance check done"
                );
                return Ok(());
            }
        };

    // 초기 등록
    let os_str = format!("{} {}", sys.os_name, sys.os_version);
    if let Err(e) = transport.register(&os_str, &sys.agent_version).await {
        error!(error = %e, "initial registration failed");
    }

    // 주기적 상태 보고 루프
    let mut interval = tokio::time::interval(Duration::from_secs(checkin_interval_secs));
    loop {
        interval.tick().await;

        // 소프트웨어 목록 수집
        let sw_list = software::collect_installed_software();
        let usb = software::usb_storage_enabled();
        let bluetooth = software::bluetooth_enabled();
        let sharing = software::folder_sharing_enabled();

        info!(
            sw_count = sw_list.len(),
            usb_enabled = usb,
            bluetooth_enabled = bluetooth,
            folder_sharing = sharing,
            "posture data collected"
        );

        // 컴플라이언스 체크 (기본 OS/루트 체크)
        let report = match compliance::run_checks() {
            Ok(r) => r,
            Err(e) => {
                error!(error = %e, "compliance check failed");
                continue;
            }
        };

        // 상태 보고
        match transport
            .report_status(&sw_list, usb, bluetooth, sharing)
            .await
        {
            Ok(action) => {
                info!(
                    action,
                    is_compliant = report.is_compliant,
                    "status report sent"
                );
            }
            Err(e) => {
                error!(error = %e, "status report failed");
            }
        }
    }
}

fn load_or_create_device_id() -> Result<String> {
    let id_path = std::env::var("DEVICE_ID_FILE")
        .unwrap_or_else(|_| "/var/lib/nac-agent/device-id".to_string());

    if let Ok(id) = std::fs::read_to_string(&id_path) {
        let id = id.trim().to_string();
        if !id.is_empty() {
            return Ok(id);
        }
    }
    let id = uuid::Uuid::new_v4().to_string();
    if let Some(parent) = std::path::Path::new(&id_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&id_path, &id);
    Ok(id)
}
