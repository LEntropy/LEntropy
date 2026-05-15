//! dhcp: DHCPv4/v6 server with NAC-aware lease management.

use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!(service = "dhcp", "starting up");

    let _config = nac_config::AppConfig::load()?;

    tracing::info!("configuration loaded — starting DHCPv4/v6 server");

    // TODO: bind UDP sockets on port 67 (DHCPv4) and 547 (DHCPv6),
    //       process leases via dhcproto,
    //       publish binding events to NATS for sensor correlation.

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}
