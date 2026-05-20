//! enforcement: Policy Enforcement Agent — ARP-spoofing and VLAN reassignment.

use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing_subscriber::{fmt, EnvFilter};

mod arp_spoof;
mod consumer;
mod gateway_lock;
mod ipv6_block;
mod snmp_port;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!(service = "enforcement", "starting up");

    let config = nac_config::AppConfig::load()?;

    // NATS 연결
    let nats = async_nats::connect(&config.nats_url).await?;
    tracing::info!(nats_url = %config.nats_url, "NATS connected");

    // 첫 번째 물리 인터페이스로 Spoofer 초기화
    let spoofer: Arc<Mutex<Option<arp_spoof::Spoofer>>> = {
        use pnet::datalink;
        let interfaces: Vec<_> = datalink::interfaces()
            .into_iter()
            .filter(|i| {
                !i.is_loopback()
                    && i.is_up()
                    && !i.name.starts_with("docker")
                    && !i.name.starts_with("br-")
                    && !i.name.starts_with("veth")
                    && !i.ips.is_empty()
                    && i.mac.is_some()
            })
            .collect();

        if interfaces.is_empty() {
            tracing::warn!("no suitable interfaces found — ARP enforcement disabled");
            Arc::new(Mutex::new(None))
        } else {
            let iface = &interfaces[0];
            tracing::info!(interface = %iface.name, "initializing ARP spoofer");
            match arp_spoof::Spoofer::new(&iface.name) {
                Ok(s) => {
                    tracing::info!(interface = %iface.name, "ARP spoofer initialized");
                    Arc::new(Mutex::new(Some(s)))
                }
                Err(e) => {
                    tracing::warn!(error = %e, "ARP spoofer init failed — enforcement disabled");
                    Arc::new(Mutex::new(None))
                }
            }
        }
    };

    // NATS consumer 태스크
    let consumer_nats = nats.clone();
    let consumer_spoofer = spoofer.clone();
    tokio::spawn(async move {
        if let Err(e) = consumer::run(consumer_nats, consumer_spoofer).await {
            tracing::error!(error = %e, "enforcement consumer error");
        }
    });

    // ARP re-poison loop — 격리된 단말 재독살 (30초 주기)
    // 실제 운영에서는 격리 목록을 별도 상태로 관리하지만,
    // 여기서는 NATS 메시지 수신 시 즉각 처리하는 방식을 사용.
    // 재독살 루프는 향후 상태 저장소와 연동 시 확장 가능.
    let _repoisoning_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            tracing::debug!("ARP re-poison tick (quarantine state TBD)");
        }
    });

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}
