//! sensor: ARP/DHCP/NDP snooping service for device discovery and fingerprinting.

use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!(service = "sensor", "starting up");

    let _config = nac_config::AppConfig::load()?;

    tracing::info!("configuration loaded — beginning packet capture");

    // TODO: open raw sockets via nac-netproto, start ARP/DHCP snooping tasks,
    //       publish discovered endpoints to NATS via nac-bus.

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}
