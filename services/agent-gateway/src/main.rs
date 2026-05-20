//! agent-gateway: gRPC endpoint for NAC agent communication.

mod agent_service;

use agent_service::AgentServiceImpl;
use nac_proto::agent::agent_service_server::AgentServiceServer;
use sqlx::postgres::PgPoolOptions;
use tonic::transport::Server;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!(service = "agent-gateway", "starting up");

    let config = nac_config::AppConfig::load()?;

    // DB 연결 풀
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await?;
    tracing::info!("database connected");

    // NATS 연결
    let nats = async_nats::connect(&config.nats_url).await?;
    tracing::info!(nats_url = %config.nats_url, "NATS connected");

    // JWT 시크릿 (환경변수 또는 기본값)
    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "change-me-in-production".to_string())
        .into_bytes();

    // gRPC 서버 주소
    let grpc_addr: std::net::SocketAddr = std::env::var("GRPC_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:50051".to_string())
        .parse()?;

    let svc = AgentServiceImpl {
        nats,
        pool,
        jwt_secret,
    };

    tracing::info!(addr = %grpc_addr, "gRPC server listening (plain — TLS via reverse proxy)");

    // TLS 환경변수 감지 시 경고 (실제 TLS는 리버스 프록시 또는 tonic tls feature 활성화 필요)
    if std::env::var("TLS_CERT_PATH").is_ok() {
        tracing::warn!(
            "TLS_CERT_PATH is set but TLS is handled by the reverse proxy in this build"
        );
    }

    Server::builder()
        .add_service(AgentServiceServer::new(svc))
        .serve_with_shutdown(grpc_addr, async {
            tokio::signal::ctrl_c().await.ok();
        })
        .await?;

    tracing::info!("shutting down");
    Ok(())
}
