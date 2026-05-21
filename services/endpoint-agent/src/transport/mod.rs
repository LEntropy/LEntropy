//! gRPC transport — agent-gateway 연결 및 체크인.

use anyhow::Result;
use nac_proto::agent::{agent_service_client::AgentServiceClient, RegisterRequest, StatusReport};
use tonic::transport::Channel;
use tracing::{debug, info};

pub struct AgentTransport {
    client: AgentServiceClient<Channel>,
    device_id: String,
}

impl AgentTransport {
    pub async fn connect(endpoint: &str, device_id: String) -> Result<Self> {
        info!(endpoint, "connecting to agent-gateway");
        let channel = Channel::from_shared(endpoint.to_string())?
            .connect()
            .await?;
        let client = AgentServiceClient::new(channel);
        Ok(Self { client, device_id })
    }

    pub async fn register(&mut self, os: &str, version: &str) -> Result<String> {
        let req = RegisterRequest {
            device_id: self.device_id.clone(),
            os: os.to_string(),
            version: version.to_string(),
        };
        let resp = self.client.register(tonic::Request::new(req)).await?;
        let token = resp.into_inner().token;
        debug!(token_len = token.len(), "register success");
        Ok(token)
    }

    pub async fn report_status(
        &mut self,
        usb_enabled: bool,
        bluetooth_enabled: bool,
        folder_sharing_enabled: bool,
    ) -> Result<String> {
        let req = StatusReport {
            device_id: self.device_id.clone(),
            installed_software: vec![],
            missing_patches: vec![],
            usb_enabled,
            bluetooth_enabled,
            folder_sharing_enabled,
        };
        let resp = self.client.report_status(tonic::Request::new(req)).await?;
        Ok(resp.into_inner().action)
    }
}
