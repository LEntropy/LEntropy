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
use tracing::{debug, info, warn};

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
        let remote_ip = request.remote_addr().map(|a| a.ip().to_string());
        let req = request.into_inner();

        let device_id = req.device_id.clone();
        let primary_mac = normalize_mac(&req.primary_mac);
        let hostname = if req.hostname.is_empty() {
            None
        } else {
            Some(req.hostname.clone())
        };

        debug!(
            device_id = %device_id,
            mac = ?primary_mac,
            os = %req.os,
            "agent register"
        );

        let repo = EndpointRepo::new(&self.pool);

        let ep = UpsertEndpoint {
            // primary_mac이 없으면 agent_id 앞 12 hex → MAC (이전 호환)
            mac_address: primary_mac
                .clone()
                .unwrap_or_else(|| legacy_device_id_to_mac(&device_id)),
            ip_address: remote_ip,
            hostname,
            os_family: Some(req.os.clone()),
            os_version: Some(req.version.clone()),
            device_type: None,
            vendor: None,
            interface: None,
            agent_id: Some(device_id.clone()),
        };

        // ── 등록 전략 ────────────────────────────────────────────────────────
        // 1. agent_id로 기존 레코드 업데이트 (MAC 변경 추적)
        // 2. primary_mac으로 기존 레코드에 agent_id 연결 (최초 에이전트 등록)
        // 3. 신규 INSERT

        let row = if let Ok(Some(updated)) = repo.upsert_by_agent_id(&ep).await {
            // 기존 agent_id 레코드 — MAC/IP 업데이트
            info!(
                device_id = %device_id,
                mac = %updated.mac_address,
                ip = ?updated.ip_address,
                "agent re-registered (agent_id matched)"
            );
            updated
        } else {
            // MAC 기준 업서트 (ARP로 이미 발견된 단말에 agent_id 연결 포함)
            let row = repo.upsert(&ep).await.map_err(|e| {
                warn!(error = %e, "failed to upsert endpoint");
                Status::internal("database error")
            })?;
            info!(
                device_id = %device_id,
                mac = %row.mac_address,
                status = %row.status,
                "agent registered"
            );
            row
        };

        let _ = row; // status used for logging above

        // JWT 발급
        let now = OffsetDateTime::now_utc();
        let claims = NacClaims {
            sub: device_id.clone(),
            groups: vec![],
            exp: (now + time::Duration::hours(24)).unix_timestamp(),
            iat: now.unix_timestamp(),
        };

        let token = jwt::sign_token(&claims, &self.jwt_secret).map_err(|e| {
            warn!(error = %e, "failed to sign JWT");
            Status::internal("token error")
        })?;

        Ok(Response::new(RegisterResponse { token }))
    }

    async fn report_status(
        &self,
        request: Request<StatusReport>,
    ) -> Result<Response<StatusAck>, Status> {
        // JWT 검증
        let auth_val = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));

        match auth_val {
            Some(token) => {
                if nac_auth::jwt::verify_token(token, &self.jwt_secret).is_err() {
                    return Err(Status::unauthenticated("invalid or expired token"));
                }
            }
            None => return Err(Status::unauthenticated("missing authorization token")),
        }

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

        // agent_id로 단말 상태 조회
        let repo = EndpointRepo::new(&self.pool);
        let action = match repo.find_by_agent_id(&req.device_id).await {
            Ok(Some(ep)) => match ep.status.as_str() {
                "denied" => "Deny",
                "quarantined" => "Quarantine",
                _ => "Allow",
            },
            _ => "Allow",
        };

        Ok(Response::new(StatusAck {
            action: action.to_string(),
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

/// MAC 주소 정규화: "AA-BB-CC-DD-EE-FF" / "AABBCCDDEEEE" → "aa:bb:cc:dd:ee:ff"
/// 빈 문자열이면 None 반환
fn normalize_mac(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() == 12 {
        Some(
            (0..6)
                .map(|i| hex[i * 2..i * 2 + 2].to_lowercase())
                .collect::<Vec<_>>()
                .join(":"),
        )
    } else {
        None
    }
}

/// 이전 버전 호환: UUID device_id 앞 12 hex → MAC (primary_mac 없는 구버전 에이전트용)
fn legacy_device_id_to_mac(device_id: &str) -> String {
    let hex: String = device_id
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(12)
        .collect();
    if hex.len() == 12 {
        (0..6)
            .map(|i| hex[i * 2..i * 2 + 2].to_lowercase())
            .collect::<Vec<_>>()
            .join(":")
    } else {
        "00:00:00:00:00:00".to_string()
    }
}
