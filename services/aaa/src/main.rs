//! aaa: Authentication, Authorization, and Accounting service.
//!      Provides Captive Portal HTTP endpoint + RADIUS server (UDP 1812/1813).

use std::sync::Arc;

use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::{fmt, EnvFilter};

mod captive_portal;
pub mod radius;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!(service = "aaa", "starting up");

    let config = nac_config::AppConfig::load()?;

    // ── DB 연결 ────────────────────────────────────────────────────────────
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await?;
    tracing::info!("database connected");

    // ── NATS 연결 ─────────────────────────────────────────────────────────
    let nats = async_nats::connect(&config.nats_url).await?;
    tracing::info!(nats_url = %config.nats_url, "NATS connected");

    // ── LDAP 클라이언트 초기화 (설정 없으면 mock 모드) ───────────────────
    let ldap = match (
        &config.ldap_url,
        &config.ldap_bind_dn,
        &config.ldap_bind_pw,
        &config.ldap_user_base,
        &config.ldap_user_filter,
    ) {
        (Some(url), Some(bind_dn), Some(bind_pw), Some(user_base), Some(user_filter)) => {
            tracing::info!(ldap_url = %url, "LDAP client initialized");
            Some(nac_auth::LdapClient::new(
                url.clone(),
                bind_dn.clone(),
                bind_pw.clone(),
                user_base.clone(),
                user_filter.clone(),
            ))
        }
        _ => {
            tracing::warn!("LDAP not configured — captive portal running in mock-denied mode");
            None
        }
    };

    // ── JWT 시크릿 ────────────────────────────────────────────────────────
    let jwt_secret = config
        .jwt_secret
        .as_deref()
        .unwrap_or("change-me-in-production-min-32-chars")
        .as_bytes()
        .to_vec();

    // ── RADIUS 서버 태스크 (UDP 1812/1813) ───────────────────────────────
    let radius_secret = config
        .radius_secret
        .clone()
        .unwrap_or_else(|| "radius-shared-secret".to_string());
    let radius_auth_addr = config
        .radius_auth_addr
        .clone()
        .unwrap_or_else(|| "0.0.0.0:1812".to_string());
    let radius_acct_addr = config
        .radius_acct_addr
        .clone()
        .unwrap_or_else(|| "0.0.0.0:1813".to_string());
    let radius_pool = pool.clone();
    let radius_nats = nats.clone();
    tokio::spawn(async move {
        if let Err(e) = radius::run_radius_server(
            &radius_auth_addr,
            &radius_acct_addr,
            radius_secret.into_bytes(),
            radius_pool,
            radius_nats,
        )
        .await
        {
            tracing::error!(error = %e, "RADIUS server error");
        }
    });

    // ── Captive Portal 상태 ───────────────────────────────────────────────
    let state = Arc::new(captive_portal::PortalState {
        ldap,
        nats,
        jwt_secret,
        pool,
        default_mac: None,
    });

    // ── HTTP 서버 바인딩 ─────────────────────────────────────────────────
    let addr = config
        .captive_portal_addr
        .as_deref()
        .unwrap_or("0.0.0.0:8080");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(addr = %addr, "captive portal listening");

    let app = captive_portal::router(state);

    // ConnectInfo 추출을 위해 with_connect_info 필요
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    tracing::info!("shutting down");
    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl-C handler");
}
