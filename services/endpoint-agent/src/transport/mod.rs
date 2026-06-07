//! gRPC transport — agent-gateway 연결 및 체크인.

use anyhow::Result;
use nac_proto::agent::{
    agent_service_client::AgentServiceClient, RegisterRequest, SoftwareItem as ProtoSoftwareItem,
    StatusReport,
};
use tonic::{metadata::MetadataValue, transport::Channel};
use tracing::info;

use crate::software::InstalledSoftware;

pub struct AgentTransport {
    client: AgentServiceClient<Channel>,
    device_id: String,
    /// register() 후 서버에서 발급된 JWT 토큰
    token: Option<String>,
}

impl AgentTransport {
    pub async fn connect(endpoint: &str, device_id: String) -> Result<Self> {
        info!(endpoint, "connecting to agent-gateway");
        let channel = Channel::from_shared(endpoint.to_string())?
            .connect()
            .await?;
        let client = AgentServiceClient::new(channel);
        Ok(Self {
            client,
            device_id,
            token: None,
        })
    }

    pub async fn register(
        &mut self,
        os: &str,
        version: &str,
        primary_mac: &str,
        hostname: &str,
    ) -> Result<String> {
        let req = RegisterRequest {
            device_id: self.device_id.clone(),
            os: os.to_string(),
            version: version.to_string(),
            primary_mac: primary_mac.to_string(),
            hostname: hostname.to_string(),
        };
        let resp = self.client.register(tonic::Request::new(req)).await?;
        let token = resp.into_inner().token;
        if token.is_empty() {
            return Err(anyhow::anyhow!("server returned empty token"));
        }
        info!(token_len = token.len(), "registered — JWT token stored");
        self.token = Some(token.clone());
        Ok(token)
    }

    pub async fn report_status(
        &mut self,
        software: &[InstalledSoftware],
        usb_enabled: bool,
        bluetooth_enabled: bool,
        folder_sharing_enabled: bool,
        os: &str,
        os_version: &str,
    ) -> Result<String> {
        let installed_software = software
            .iter()
            .map(|s| ProtoSoftwareItem {
                name: s.name.clone(),
                version: s.version.clone(),
            })
            .collect();

        let payload = StatusReport {
            device_id: self.device_id.clone(),
            installed_software,
            missing_patches: vec![],
            usb_enabled,
            bluetooth_enabled,
            folder_sharing_enabled,
            os: os.to_string(),
            os_version: os_version.to_string(),
        };

        let mut request = tonic::Request::new(payload);

        // JWT 토큰을 메타데이터로 첨부
        if let Some(token) = &self.token {
            if let Ok(val) = MetadataValue::try_from(format!("Bearer {token}")) {
                request.metadata_mut().insert("authorization", val);
            }
        }

        let resp = self.client.report_status(request).await?;
        Ok(resp.into_inner().action)
    }
}
