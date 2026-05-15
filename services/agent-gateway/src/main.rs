//! agent-gateway: mTLS gRPC endpoint for NAC agent communication.

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

    let _config = nac_config::AppConfig::load()?;

    tracing::info!("configuration loaded — starting mTLS gRPC server");

    // TODO: configure mTLS via nac-crypto::tls,
    //       register tonic services (nac-proto::agent),
    //       forward agent health/posture reports to NATS.

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}
