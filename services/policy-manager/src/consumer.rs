use anyhow::Result;
use async_nats::Client;
use futures_util::StreamExt;
use nac_store::endpoint::{EndpointRepo, UpsertEndpoint};
use serde::Deserialize;
use sqlx::PgPool;
use tracing::{debug, error, info, warn};

const SUBJECT: &str = "nac.events.endpoint.detected";

/// sensor 서비스가 발행하는 이벤트 페이로드 (publisher.rs와 동일 구조)
#[derive(Debug, Deserialize)]
struct EndpointDetectedEvent {
    mac_address: String,
    ip_address: String,
    interface: String,
    source: String,
    #[allow(dead_code)]
    timestamp: i64,
}

/// NATS 구독 루프 — 단말 탐지 이벤트를 수신해 DB에 업서트
pub async fn run(nats: Client, pool: PgPool) -> Result<()> {
    let mut sub = nats.subscribe(SUBJECT).await?;
    info!(subject = SUBJECT, "NATS consumer started");

    while let Some(msg) = sub.next().await {
        let payload = match serde_json::from_slice::<EndpointDetectedEvent>(&msg.payload) {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "failed to parse endpoint event — skipping");
                continue;
            }
        };

        debug!(
            mac = %payload.mac_address,
            ip  = %payload.ip_address,
            src = %payload.source,
            "endpoint event received"
        );

        let ep = UpsertEndpoint {
            mac_address: payload.mac_address.clone(),
            ip_address: Some(payload.ip_address.clone()),
            hostname: None,
            os_family: None,
            os_version: None,
            device_type: None,
            vendor: None,
            interface: Some(payload.interface.clone()),
        };

        let repo = EndpointRepo::new(&pool);
        match repo.upsert(&ep).await {
            Ok(row) => {
                debug!(
                    id     = %row.id,
                    mac    = %row.mac_address,
                    status = %row.status,
                    "endpoint upserted"
                );
            }
            Err(e) => {
                error!(
                    mac   = %payload.mac_address,
                    error = %e,
                    "failed to upsert endpoint"
                );
            }
        }
    }

    info!("NATS consumer stopped");
    Ok(())
}
