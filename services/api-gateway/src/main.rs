//! api-gateway: REST API gateway with JWT authentication for external consumers.

use axum::{routing::get, Router};
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!(service = "api-gateway", "starting up");

    let config = nac_config::AppConfig::load()?;

    let app = Router::new().route("/healthz", get(health_check));

    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    tracing::info!(addr = %config.listen_addr, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("shutting down");
    Ok(())
}

/// Simple liveness probe.
async fn health_check() -> &'static str {
    "ok"
}

/// Wait for SIGINT / SIGTERM.
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl-C handler");
}
