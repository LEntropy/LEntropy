use anyhow::Result;
use async_nats::Client;
use serde::Serialize;

/// NATS로 발행할 이벤트 타입
#[derive(Debug, Serialize)]
pub struct EndpointDetectedEvent {
    pub mac_address: String,
    pub ip_address: String,
    pub interface: String,
    pub source: String, // "arp", "dhcp"
    pub timestamp: i64,
    // 핑거프린팅 결과 (DHCP 경로에서 채워짐)
    pub hostname: Option<String>,
    pub os_family: Option<String>,
    pub os_version: Option<String>,
    pub device_type: Option<String>,
    pub vendor: Option<String>,
}

pub struct NatsPublisher {
    client: Client,
}

impl NatsPublisher {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub async fn publish_endpoint_detected(&self, event: &EndpointDetectedEvent) -> Result<()> {
        let payload = serde_json::to_vec(event)?;
        self.client
            .publish("nac.events.endpoint.detected", payload.into())
            .await?;
        Ok(())
    }
}
