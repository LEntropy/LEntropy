//! SNMP 기반 스위치 포트 제어 (stub).
//! 실제 SNMP v2c/v3 OID 조작으로 포트 shut/no-shut.
//! 현재는 구조체와 인터페이스 정의만; 실제 SNMP는 추후 snmp2 crate 연동.

use anyhow::Result;
use tracing::{info, warn};

/// SNMP로 제어할 스위치 포트 정보
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SwitchPort {
    pub switch_ip: String,
    pub community: String, // SNMP community string
    pub port_index: u32,   // ifIndex
}

/// SNMP OID: ifAdminStatus (1.3.6.1.2.1.2.2.1.7.<ifIndex>)
/// 1 = up, 2 = down
#[allow(dead_code)]
const IF_ADMIN_STATUS_OID_PREFIX: &str = "1.3.6.1.2.1.2.2.1.7";

#[allow(dead_code)]
pub struct SnmpPortController;

impl SnmpPortController {
    /// 스위치 포트 비활성화 (격리/차단 시)
    #[allow(dead_code)]
    pub async fn shutdown_port(&self, port: &SwitchPort) -> Result<()> {
        // TODO: snmp2 crate 또는 net-snmp bindings으로 실제 SNMP SET 구현
        // OID: ifAdminStatus.{port_index} = 2 (down)
        let oid = format!("{}.{}", IF_ADMIN_STATUS_OID_PREFIX, port.port_index);
        warn!(
            switch = %port.switch_ip,
            port_index = port.port_index,
            oid = %oid,
            "SNMP port shutdown (stub — not yet implemented)"
        );
        Ok(())
    }

    /// 스위치 포트 활성화 (허용 시)
    #[allow(dead_code)]
    pub async fn enable_port(&self, port: &SwitchPort) -> Result<()> {
        let oid = format!("{}.{}", IF_ADMIN_STATUS_OID_PREFIX, port.port_index);
        info!(
            switch = %port.switch_ip,
            port_index = port.port_index,
            oid = %oid,
            "SNMP port enable (stub — not yet implemented)"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_switch_port_creation() {
        let port = SwitchPort {
            switch_ip: "192.168.1.254".to_string(),
            community: "private".to_string(),
            port_index: 10,
        };
        assert_eq!(port.port_index, 10);
    }

    #[tokio::test]
    async fn test_snmp_stub_does_not_panic() {
        let ctrl = SnmpPortController;
        let port = SwitchPort {
            switch_ip: "192.168.1.254".to_string(),
            community: "private".to_string(),
            port_index: 5,
        };
        // stub이므로 에러 없이 Ok 반환
        assert!(ctrl.shutdown_port(&port).await.is_ok());
        assert!(ctrl.enable_port(&port).await.is_ok());
    }
}
