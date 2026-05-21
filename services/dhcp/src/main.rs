//! dhcp: DHCPv4 server with NAC-aware lease management.

use tracing_subscriber::{fmt, EnvFilter};

mod pool;
mod server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!(service = "dhcp", "starting up");

    let config = nac_config::AppConfig::load()?;
    let nats = async_nats::connect(&config.nats_url).await?;
    tracing::info!(nats_url = %config.nats_url, "NATS connected");

    // 환경변수에서 DHCP 설정 로드
    let pool_start: std::net::Ipv4Addr = std::env::var("DHCP_POOL_START")
        .unwrap_or_else(|_| "192.168.1.100".to_string())
        .parse()?;
    let pool_end: std::net::Ipv4Addr = std::env::var("DHCP_POOL_END")
        .unwrap_or_else(|_| "192.168.1.200".to_string())
        .parse()?;
    let subnet_mask: std::net::Ipv4Addr = std::env::var("DHCP_SUBNET_MASK")
        .unwrap_or_else(|_| "255.255.255.0".to_string())
        .parse()?;
    let gateway: std::net::Ipv4Addr = std::env::var("DHCP_GATEWAY")
        .unwrap_or_else(|_| "192.168.1.1".to_string())
        .parse()?;
    let server_ip: std::net::Ipv4Addr = std::env::var("DHCP_SERVER_IP")
        .unwrap_or_else(|_| "192.168.1.1".to_string())
        .parse()?;
    let bind_addr = std::env::var("DHCP_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:67".to_string());

    let lease_pool = pool::LeasePool::new(pool_start, pool_end, subnet_mask, gateway);
    let dhcp_server = server::DhcpServer {
        pool: lease_pool,
        server_ip,
        nats,
    };

    tracing::info!(
        pool_start = %pool_start,
        pool_end = %pool_end,
        "DHCP pool configured"
    );

    dhcp_server.run(&bind_addr).await?;

    Ok(())
}
