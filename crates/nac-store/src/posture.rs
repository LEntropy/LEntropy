use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareItem {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchItem {
    pub kb_id: String,
    pub description: String,
}

/// posture_handler가 평가하기 위한 보고서 구조체
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureReport {
    pub device_id: String, // MAC address
    pub os: String,
    pub os_version: String,
    pub installed_software: Vec<SoftwareItem>,
    pub missing_patches: Vec<PatchItem>,
    pub usb_enabled: bool,
    pub bluetooth_enabled: bool,
    pub folder_sharing_enabled: bool,
    pub timestamp: i64,
}

/// 간단한 컴플라이언스 정책
#[derive(Debug, Clone, Default)]
pub struct CompliancePolicy {
    pub required_software: Vec<String>, // 필수 소프트웨어 이름 목록
    pub require_patches: bool,          // missing_patches가 비어야 함
    pub allow_usb: bool,
    pub allow_bluetooth: bool,
    pub allow_folder_sharing: bool,
}

impl CompliancePolicy {
    /// 기본 정책: 패치 필수, USB 허용, Bluetooth 허용
    pub fn default_policy() -> Self {
        Self {
            required_software: vec![],
            require_patches: true,
            allow_usb: true,
            allow_bluetooth: true,
            allow_folder_sharing: false,
        }
    }

    pub fn evaluate(&self, report: &PostureReport) -> bool {
        // 필수 소프트웨어 확인
        for req in &self.required_software {
            if !report
                .installed_software
                .iter()
                .any(|s| s.name.to_lowercase().contains(&req.to_lowercase()))
            {
                return false;
            }
        }
        // 패치 확인
        if self.require_patches && !report.missing_patches.is_empty() {
            return false;
        }
        // USB 확인
        if !self.allow_usb && report.usb_enabled {
            return false;
        }
        // Bluetooth 확인
        if !self.allow_bluetooth && report.bluetooth_enabled {
            return false;
        }
        // 폴더 공유 확인
        if !self.allow_folder_sharing && report.folder_sharing_enabled {
            return false;
        }
        true
    }
}

pub struct PostureRepo<'a> {
    pool: &'a PgPool,
}

impl<'a> PostureRepo<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    /// posture_reports 테이블에 보고서 저장
    pub async fn save(
        &self,
        endpoint_id: Uuid,
        report: &PostureReport,
        is_compliant: bool,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO posture_reports \
             (endpoint_id, os, os_version, installed_sw, missing_patches, \
              usb_enabled, bluetooth_enabled, folder_sharing, is_compliant) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(endpoint_id)
        .bind(&report.os)
        .bind(&report.os_version)
        .bind(serde_json::to_value(&report.installed_software)?)
        .bind(serde_json::to_value(&report.missing_patches)?)
        .bind(report.usb_enabled)
        .bind(report.bluetooth_enabled)
        .bind(report.folder_sharing_enabled)
        .bind(is_compliant)
        .execute(self.pool)
        .await?;
        Ok(())
    }
}
