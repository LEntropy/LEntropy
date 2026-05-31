//! api-gateway: REST API gateway with JWT authentication for external consumers.
//! Proxies requests to internal services and validates JWT tokens.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing_subscriber::{fmt, EnvFilter};

mod auth;

#[derive(Clone)]
struct AppState {
    jwt_secret: Vec<u8>,
    policy_manager_url: String,
}

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
    let jwt_secret = config
        .jwt_secret
        .as_deref()
        .unwrap_or("change-me-in-production-min-32-chars")
        .as_bytes()
        .to_vec();
    let policy_manager_url =
        std::env::var("POLICY_MANAGER_URL").unwrap_or_else(|_| "http://localhost:8001".to_string());

    let state = Arc::new(AppState {
        jwt_secret,
        policy_manager_url,
    });

    let protected = Router::new()
        .route("/endpoints", get(list_endpoints))
        .route("/endpoints/{id}/allow", post(allow_endpoint))
        .route("/endpoints/{id}/block", post(block_endpoint))
        .route("/endpoints/{id}/quarantine", post(quarantine_endpoint))
        .route("/policies", get(list_policies).post(create_policy))
        .route("/policies/evaluate", post(evaluate_policies))
        .route("/policies/{id}", put(update_policy).delete(delete_policy))
        .route("/audit", get(list_audit))
        .route("/stats", get(get_stats))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    let app = Router::new()
        .route("/healthz", get(health_check))
        .route("/api/auth/login", post(login))
        .nest("/api", protected)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    tracing::info!(addr = %config.listen_addr, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("shutting down");
    Ok(())
}

async fn health_check() -> &'static str {
    "ok"
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

async fn login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    // 단순 관리자 인증 (프로덕션에서는 LDAP/OIDC 연동)
    let admin_user = std::env::var("ADMIN_USER").unwrap_or_else(|_| "admin".to_string());
    let admin_pass = std::env::var("ADMIN_PASS").unwrap_or_else(|_| "changeme".to_string());

    if req.username != admin_user || req.password != admin_pass {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token = auth::create_token(&state.jwt_secret, &req.username)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(LoginResponse { token }))
}

// ── Policy Manager 프록시 핸들러들 ────────────────────────────────────────

async fn list_endpoints(State(state): State<Arc<AppState>>) -> Result<Response, StatusCode> {
    proxy_get(&state.policy_manager_url, "/api/v1/endpoints").await
}

async fn allow_endpoint(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, StatusCode> {
    proxy_post(
        &state.policy_manager_url,
        &format!("/api/v1/endpoints/{id}/allow"),
    )
    .await
}

async fn block_endpoint(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, StatusCode> {
    proxy_post(
        &state.policy_manager_url,
        &format!("/api/v1/endpoints/{id}/block"),
    )
    .await
}

async fn quarantine_endpoint(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, StatusCode> {
    proxy_post(
        &state.policy_manager_url,
        &format!("/api/v1/endpoints/{id}/quarantine"),
    )
    .await
}

async fn list_policies(State(state): State<Arc<AppState>>) -> Result<Response, StatusCode> {
    proxy_get(&state.policy_manager_url, "/api/v1/policies").await
}

async fn evaluate_policies(State(state): State<Arc<AppState>>) -> Result<Response, StatusCode> {
    proxy_post(&state.policy_manager_url, "/api/v1/policies/evaluate").await
}

async fn create_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, StatusCode> {
    proxy_post_body(&state.policy_manager_url, "/api/v1/policies", headers, body).await
}

async fn update_policy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, StatusCode> {
    proxy_put_body(
        &state.policy_manager_url,
        &format!("/api/v1/policies/{id}"),
        headers,
        body,
    )
    .await
}

async fn delete_policy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, StatusCode> {
    proxy_delete(&state.policy_manager_url, &format!("/api/v1/policies/{id}")).await
}

async fn list_audit(State(state): State<Arc<AppState>>) -> Result<Response, StatusCode> {
    proxy_get(&state.policy_manager_url, "/api/v1/audit").await
}

async fn get_stats(State(state): State<Arc<AppState>>) -> Result<Response, StatusCode> {
    proxy_get(&state.policy_manager_url, "/api/v1/stats").await
}

// ── HTTP 프록시 헬퍼 ──────────────────────────────────────────────────────

async fn proxy_get(base: &str, path: &str) -> Result<Response, StatusCode> {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}{path}"))
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let body = resp.bytes().await.map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok((status, body).into_response())
}

async fn proxy_post(base: &str, path: &str) -> Result<Response, StatusCode> {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}{path}"))
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let body = resp.bytes().await.map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok((status, body).into_response())
}

async fn proxy_post_body(
    base: &str,
    path: &str,
    _headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, StatusCode> {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}{path}"))
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let body = resp.bytes().await.map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok((status, body).into_response())
}

async fn proxy_put_body(
    base: &str,
    path: &str,
    _headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, StatusCode> {
    let client = reqwest::Client::new();
    let resp = client
        .put(format!("{base}{path}"))
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let body = resp.bytes().await.map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok((status, body).into_response())
}

async fn proxy_delete(base: &str, path: &str) -> Result<Response, StatusCode> {
    let client = reqwest::Client::new();
    let resp = client
        .delete(format!("{base}{path}"))
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let body = resp.bytes().await.map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok((status, body).into_response())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl-C handler");
}
