//! policy-manager: REST API + gRPC server for NAC policy lifecycle management.

use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialise structured JSON logging; fall back to INFO if RUST_LOG is unset.
    fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!(service = "policy-manager", "starting up");

    // Load configuration from environment variables.
    let _config = nac_config::AppConfig::load()?;

    tracing::info!("configuration loaded");

    // TODO: initialise DB pool (nac-store), NATS bus (nac-bus), and axum/tonic servers.

    // Keep the process alive until signalled.
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}
