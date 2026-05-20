use nac_auth::{jwt, NacClaims};
use nac_proto::agent::agent_service_server::AgentService;
use nac_proto::agent::{
    AgentPolicyRequest, AgentPolicyResponse, RegisterRequest, RegisterResponse, StatusAck,
    StatusReport,
};
use nac_store::endpoint::{EndpointRepo, UpsertEndpoint};
use nac_store::posture::{PatchItem, PostureReport, SoftwareItem};
use sqlx::PgPool;
use time::OffsetDateTime;
use tonic::{Request, Response, Status};
use tracing::{debug, warn};

pub struct AgentServiceImpl {
    pub nats: async_nats::Client,
    pub pool: PgPool,
    pub jwt_secret: Vec<u8>,
}

#[tonic::async_trait]
impl AgentService for AgentServiceImpl {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();
        debug!(device_id = %req.device_id, os = %req.os, "agent register");

        let repo = EndpointRepo::new(&self.pool);
        let ep = UpsertEndpoint {
            mac_address: req.device_id.clone(),
            ip_address: None,
            hostname: None,
            os_family: Some(req.os.clone()),
            os_version: Some(req.version.clone()),
            device_type: None,
            vendor: None,
            interface: None,
        };

        repo.upsert(&ep).await.map_err(|e| {
            tracing::error!(error = %e, "failed to upsert endpoint");
            Status::internal("database error")
        })?;

        let now = OffsetDateTime::now_utc();
        let claims = NacClaims {
            sub: req.device_id.clone(),
            groups: vec![],
            exp: (now + time::Duration::hours(24)).unix_timestamp(),
            iat: now.unix_timestamp(),
        };

        let token = jwt::sign_token(&claims, &self.jwt_secret).map_err(|e| {
            tracing::error!(error = %e, "failed to sign JWT");
            Status::internal("token error")
        })?;

        Ok(Response::new(RegisterResponse { token }))
    }

    async fn report_status(
        &self,
        request: Request<StatusReport>,
    ) -> Result<Response<StatusAck>, Status> {
        let req = request.into_inner();
        debug!(device_id = %req.device_id, "agent status report");

        let installed_software: Vec<SoftwareItem> = req
            .installed_software
            .iter()
            .map(|s| SoftwareItem {
                name: s.name.clone(),
                version: s.version.clone(),
            })
            .collect();

        let missing_patches: Vec<PatchItem> = req
            .missing_patches
            .iter()
            .map(|p| PatchItem {
                kb_id: p.kb_id.clone(),
                description: p.description.clone(),
            })
            .collect();

        let report = PostureReport {
            device_id: req.device_id.clone(),
            os: String::new(),
            os_version: String::new(),
            installed_software,
            missing_patches,
            usb_enabled: req.usb_enabled,
            bluetooth_enabled: req.bluetooth_enabled,
            folder_sharing_enabled: req.folder_sharing_enabled,
            timestamp: OffsetDateTime::now_utc().unix_timestamp(),
        };

        let payload = serde_json::to_vec(&report).map_err(|e| {
            warn!(error = %e, "failed to serialize posture report");
            Status::internal("serialization error")
        })?;

        self.nats
            .publish("nac.events.posture.report", payload.into())
            .await
            .map_err(|e| {
                warn!(error = %e, "failed to publish posture report");
                Status::internal("nats error")
            })?;

        Ok(Response::new(StatusAck {
            action: "ok".to_string(),
        }))
    }

    async fn get_policy(
        &self,
        request: Request<AgentPolicyRequest>,
    ) -> Result<Response<AgentPolicyResponse>, Status> {
        let req = request.into_inner();
        debug!(device_id = %req.device_id, "agent get policy");

        Ok(Response::new(AgentPolicyResponse {
            required_software: vec![],
            forbidden_software: vec![],
            require_patches: true,
            allow_usb: true,
            allow_bluetooth: true,
            allow_folder_sharing: false,
        }))
    }
}
