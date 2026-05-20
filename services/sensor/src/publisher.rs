use anyhow::Result;
use async_nats::Client;
use serde::Serialize;

/// NATS로 발행할 이벤트 타입
#[derive(Debug, Serialize)]
pub struct EndpointDetectedEvent {
    pub mac_address: String,
    pub ip_address: String,
    pub interface: String,
    pub source: String, // "arp", "dhcp", "ndp"
    pub timestamp: i64,
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
