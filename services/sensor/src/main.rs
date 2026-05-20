use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

mod arp;
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

    // NATS 연결
    let nats = async_nats::connect(&config.nats_url).await?;
    info!(nats_url = %config.nats_url, "NATS connected");
    let publisher = std::sync::Arc::new(publisher::NatsPublisher::new(nats));

    // ARP 이벤트 채널
    let (arp_tx, mut arp_rx) = mpsc::channel::<arp::ArpEvent>(1024);

    // 물리 인터페이스 목록
    let interfaces = arp::list_physical_interfaces();
    if interfaces.is_empty() {
        warn!("no suitable network interfaces found — running in passive mode");
    } else {
        for iface in &interfaces {
            info!(interface = %iface.name, "starting ARP snooper");
            let tx = arp_tx.clone();
            let name = iface.name.clone();
            // pnet는 blocking I/O → spawn_blocking
            tokio::task::spawn_blocking(move || {
                if let Err(e) = arp::snoop(name.clone(), tx) {
                    error!(interface = %name, error = %e, "ARP snooper error");
                }
            });
        }
    }
    drop(arp_tx); // 남은 sender 제거

    // ARP 이벤트 처리 루프
    info!("ARP event processor running");
    while let Some(event) = arp_rx.recv().await {
        let pub_clone = publisher.clone();
        tokio::spawn(async move {
            let nats_event = publisher::EndpointDetectedEvent {
                mac_address: event.mac_address.clone(),
                ip_address: event.ip_address.to_string(),
                interface: event.interface.clone(),
                source: "arp".to_string(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
            };

            if let Err(e) = pub_clone.publish_endpoint_detected(&nats_event).await {
                warn!(
                    mac = %event.mac_address,
                    error = %e,
                    "failed to publish ARP event"
                );
            }
        });
    }

    info!("shutting down");
    Ok(())
}
