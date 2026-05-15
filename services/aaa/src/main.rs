//! aaa: Authentication, Authorization, and Accounting service.
//!      Provides RADIUS and Captive Portal endpoints.

use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!(service = "aaa", "starting up");

    let _config = nac_config::AppConfig::load()?;

    tracing::info!("configuration loaded — starting RADIUS + Captive Portal");

    // TODO: bind RADIUS UDP socket (1812/1813),
    //       start axum captive-portal HTTP server,
    //       authenticate via nac-auth LDAP client.

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}
