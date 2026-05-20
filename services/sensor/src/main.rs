use std::time::SystemTime;

use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

mod arp;
mod dhcp;
mod publisher;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!(service = "sensor", "starting up");

    let config = nac_config::AppConfig::load()?;

    let nats = async_nats::connect(&config.nats_url).await?;
    info!(nats_url = %config.nats_url, "NATS connected");
    let publisher = std::sync::Arc::new(publisher::NatsPublisher::new(nats));

    let (arp_tx, mut arp_rx) = mpsc::channel::<arp::ArpEvent>(1024);
    let (dhcp_tx, mut dhcp_rx) = mpsc::channel::<dhcp::DhcpEvent>(1024);

    let interfaces = arp::list_physical_interfaces();
    if interfaces.is_empty() {
        warn!("no suitable network interfaces found — running in passive mode");
    } else {
        for iface in &interfaces {
            info!(interface = %iface.name, "starting ARP snooper");
            let tx = arp_tx.clone();
            let name = iface.name.clone();
            tokio::task::spawn_blocking(move || {
                if let Err(e) = arp::snoop(name.clone(), tx) {
                    error!(interface = %name, error = %e, "ARP snooper error");
                }
            });

            info!(interface = %iface.name, "starting DHCP snooper");
            let tx = dhcp_tx.clone();
            let name = iface.name.clone();
            tokio::task::spawn_blocking(move || {
                if let Err(e) = dhcp::snoop(name.clone(), tx) {
                    error!(interface = %name, error = %e, "DHCP snooper error");
                }
            });
        }
    }
    drop(arp_tx);
    drop(dhcp_tx);

    let pub_arp = publisher.clone();
    let pub_dhcp = publisher.clone();

    // ARP 이벤트 처리
    let arp_task = tokio::spawn(async move {
        while let Some(event) = arp_rx.recv().await {
            let p = pub_arp.clone();
            tokio::spawn(async move {
                let nats_event = publisher::EndpointDetectedEvent {
                    mac_address: event.mac_address.clone(),
                    ip_address: event.ip_address.to_string(),
                    interface: event.interface.clone(),
                    source: "arp".to_string(),
                    timestamp: now_secs(),
                    hostname: None,
                    os_family: None,
                    os_version: None,
                    device_type: None,
                    vendor: None,
                };
                if let Err(e) = p.publish_endpoint_detected(&nats_event).await {
                    warn!(mac = %event.mac_address, error = %e, "failed to publish ARP event");
                }
            });
        }
    });

    // DHCP 이벤트 처리
    let dhcp_task = tokio::spawn(async move {
        while let Some(event) = dhcp_rx.recv().await {
            let p = pub_dhcp.clone();
            tokio::spawn(async move {
                let nats_event = publisher::EndpointDetectedEvent {
                    mac_address: event.mac_address.clone(),
                    ip_address: String::new(), // DHCP DISCOVER 시점엔 IP 미확정
                    interface: String::new(),
                    source: "dhcp".to_string(),
                    timestamp: now_secs(),
                    hostname: event.hostname,
                    os_family: event.os_family,
                    os_version: event.os_version,
                    device_type: event.device_type,
                    vendor: event.vendor,
                };
                if let Err(e) = p.publish_endpoint_detected(&nats_event).await {
                    warn!(mac = %event.mac_address, error = %e, "failed to publish DHCP event");
                }
            });
        }
    });

    info!("sensor event processors running");
    tokio::try_join!(arp_task, dhcp_task)?;

    info!("shutting down");
    Ok(())
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
