//! enforcement: Policy Enforcement Agent — ARP-spoofing and VLAN reassignment.

use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!(service = "enforcement", "starting up");

    let _config = nac_config::AppConfig::load()?;

    tracing::info!("configuration loaded — subscribing to enforcement events");

    // TODO: subscribe to NATS enforcement topics via nac-bus,
    //       execute ARP spoofing via nac-netproto::arp::craft_gratuitous_arp,
    //       apply VLAN changes via SNMP/NETCONF.

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}
