//! Captive portal HTTP server for NAC authentication.
//!
//! Routes:
//!   GET  /         → HTML login page
//!   POST /login    → LDAP auth → JWT → NATS event
//!   GET  /success  → success page
//!   GET  /denied   → denied page
//!   GET  /health   → {"status":"ok"}

use std::sync::Arc;

use async_nats::Client as NatsClient;
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Router,
};
use nac_auth::{jwt::sign_token, LdapClient, NacClaims};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use tracing::{error, info, warn};

// ── State ────────────────────────────────────────────────────────────────────

pub struct PortalState {
    pub ldap: Option<LdapClient>,
    pub nats: NatsClient,
    pub jwt_secret: Vec<u8>,
    /// MAC address of the endpoint making the request (if known from query param)
    pub default_mac: Option<String>,
}

pub type SharedState = Arc<PortalState>;

// ── Router ───────────────────────────────────────────────────────────────────

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/", get(login_page))
        .route("/login", post(handle_login))
        .route("/success", get(success_page))
        .route("/denied", get(denied_page))
        .route("/health", get(health))
        .with_state(state)
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn health() -> impl IntoResponse {
    axum::Json(json!({"status": "ok"}))
}

async fn login_page() -> Html<&'static str> {
    Html(LOGIN_HTML)
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    /// Optional: forwarded by enforcement/redirect for session correlation
    mac: Option<String>,
    endpoint_id: Option<String>,
    session_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct AuthResponseEvent {
    session_id: Option<String>,
    endpoint_id: Option<String>,
    mac_address: String,
    success: bool,
    username: Option<String>,
    groups: Vec<String>,
    reason: Option<String>,
}

async fn handle_login(State(state): State<SharedState>, Form(form): Form<LoginForm>) -> Response {
    let mac = form
        .mac
        .clone()
        .or_else(|| state.default_mac.clone())
        .unwrap_or_default();

    // Require LDAP client; if not configured, respond with error
    let ldap = match &state.ldap {
        Some(c) => c,
        None => {
            warn!("LDAP not configured — denying login attempt");
            return Redirect::to("/denied?reason=ldap_not_configured").into_response();
        }
    };

    info!(username = %form.username, mac = %mac, "login attempt");

    match ldap.authenticate(&form.username, &form.password).await {
        Ok(identity) => {
            info!(
                username = %identity.username,
                groups   = ?identity.groups,
                "LDAP authentication successful"
            );

            // Build JWT claims (1-hour expiry)
            let now = OffsetDateTime::now_utc().unix_timestamp();
            let claims = NacClaims {
                sub: identity.username.clone(),
                groups: identity.groups.clone(),
                iat: now,
                exp: now + 3600,
            };

            let token = match sign_token(&claims, &state.jwt_secret) {
                Ok(t) => t,
                Err(e) => {
                    error!(error = %e, "JWT signing failed");
                    return Redirect::to("/denied?reason=internal_error").into_response();
                }
            };

            info!(username = %identity.username, "JWT issued");

            // Publish auth.response to NATS
            let event = AuthResponseEvent {
                session_id: form.session_id.clone(),
                endpoint_id: form.endpoint_id.clone(),
                mac_address: mac.clone(),
                success: true,
                username: Some(identity.username.clone()),
                groups: identity.groups.clone(),
                reason: None,
            };

            publish_auth_response(&state.nats, &event, &token).await;

            Redirect::to("/success").into_response()
        }
        Err(e) => {
            warn!(
                username = %form.username,
                mac      = %mac,
                error    = %e,
                "LDAP authentication failed"
            );

            // Publish failure event
            let event = AuthResponseEvent {
                session_id: form.session_id.clone(),
                endpoint_id: form.endpoint_id.clone(),
                mac_address: mac.clone(),
                success: false,
                username: None,
                groups: vec![],
                reason: Some("invalid_credentials".to_string()),
            };
            publish_auth_response(&state.nats, &event, "").await;

            Redirect::to("/denied?reason=invalid_credentials").into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
struct DeniedQuery {
    reason: Option<String>,
}

async fn success_page() -> Html<&'static str> {
    Html(SUCCESS_HTML)
}

async fn denied_page(Query(q): Query<DeniedQuery>) -> Html<String> {
    let reason = q.reason.unwrap_or_else(|| "알 수 없는 오류".to_string());
    let html = DENIED_HTML.replace("{{REASON}}", &reason);
    Html(html)
}

// ── NATS publish ─────────────────────────────────────────────────────────────

async fn publish_auth_response(nats: &NatsClient, event: &AuthResponseEvent, _token: &str) {
    let subject = "nac.events.auth.response";
    match serde_json::to_vec(event) {
        Ok(payload) => {
            if let Err(e) = nats.publish(subject, payload.into()).await {
                error!(error = %e, subject, "failed to publish auth response");
            } else {
                info!(
                    subject,
                    success  = event.success,
                    username = ?event.username,
                    "auth response published"
                );
            }
        }
        Err(e) => {
            error!(error = %e, "failed to serialize auth response event");
        }
    }
}

// ── Static HTML ───────────────────────────────────────────────────────────────

static LOGIN_HTML: &str = r##"<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NAC 네트워크 인증</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f0f2f5;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
  }
  .container {
    background: #fff;
    border-radius: 12px;
    box-shadow: 0 4px 24px rgba(0,0,0,.12);
    padding: 48px 40px;
    width: 100%;
    max-width: 400px;
  }
  .logo { text-align: center; margin-bottom: 32px; }
  .logo svg { width: 48px; height: 48px; }
  h1 { font-size: 22px; font-weight: 700; color: #1a1a1a; text-align: center; margin-bottom: 8px; }
  p { color: #666; font-size: 14px; text-align: center; margin-bottom: 28px; }
  label { display: block; font-size: 13px; font-weight: 600; color: #444; margin-bottom: 6px; }
  input {
    width: 100%; padding: 12px 14px;
    border: 1.5px solid #ddd; border-radius: 8px;
    font-size: 15px; outline: none;
    transition: border-color .2s;
    margin-bottom: 16px;
  }
  input:focus { border-color: #4f46e5; }
  button {
    width: 100%; padding: 13px;
    background: #4f46e5; color: #fff;
    border: none; border-radius: 8px;
    font-size: 16px; font-weight: 600;
    cursor: pointer; transition: background .2s;
    margin-top: 4px;
  }
  button:hover { background: #4338ca; }
  .footer { text-align: center; margin-top: 24px; font-size: 12px; color: #aaa; }
</style>
</head>
<body>
<div class="container">
  <div class="logo">
    <svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect width="48" height="48" rx="12" fill="#4f46e5"/>
      <path d="M24 12C17.4 12 12 17.4 12 24s5.4 12 12 12 12-5.4 12-12S30.6 12 24 12zm0 4a4 4 0 110 8 4 4 0 010-8zm0 17c-3.3 0-6.2-1.7-8-4.2.04-2.7 5.33-4.1 8-4.1s7.96 1.4 8 4.1C30.2 31.3 27.3 33 24 33z" fill="white"/>
    </svg>
  </div>
  <h1>네트워크 접속 인증</h1>
  <p>이 네트워크를 사용하려면 로그인이 필요합니다.</p>
  <form method="POST" action="/login">
    <label for="username">사용자명</label>
    <input type="text" id="username" name="username" placeholder="사용자명 입력" required autocomplete="username">
    <label for="password">비밀번호</label>
    <input type="password" id="password" name="password" placeholder="비밀번호 입력" required autocomplete="current-password">
    <button type="submit">로그인</button>
  </form>
  <div class="footer">NAC Platform &mdash; 네트워크 접근 제어 시스템</div>
</div>
</body>
</html>"##;

static SUCCESS_HTML: &str = r##"<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>인증 성공</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f0f2f5;
    display: flex; align-items: center; justify-content: center; min-height: 100vh;
  }
  .container {
    background: #fff; border-radius: 12px;
    box-shadow: 0 4px 24px rgba(0,0,0,.12);
    padding: 48px 40px; width: 100%; max-width: 400px; text-align: center;
  }
  .icon { font-size: 64px; margin-bottom: 24px; }
  h1 { font-size: 24px; color: #16a34a; margin-bottom: 12px; }
  p { color: #666; font-size: 15px; }
</style>
</head>
<body>
<div class="container">
  <div class="icon">✅</div>
  <h1>인증 성공</h1>
  <p>네트워크 접속이 허가되었습니다.<br>잠시 후 자동으로 연결됩니다.</p>
</div>
</body>
</html>"##;

static DENIED_HTML: &str = r##"<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>인증 실패</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f0f2f5;
    display: flex; align-items: center; justify-content: center; min-height: 100vh;
  }
  .container {
    background: #fff; border-radius: 12px;
    box-shadow: 0 4px 24px rgba(0,0,0,.12);
    padding: 48px 40px; width: 100%; max-width: 400px; text-align: center;
  }
  .icon { font-size: 64px; margin-bottom: 24px; }
  h1 { font-size: 24px; color: #dc2626; margin-bottom: 12px; }
  p { color: #666; font-size: 15px; margin-bottom: 24px; }
  a {
    display: inline-block; padding: 12px 28px;
    background: #4f46e5; color: #fff;
    border-radius: 8px; text-decoration: none; font-weight: 600;
  }
  a:hover { background: #4338ca; }
  .reason { font-size: 12px; color: #aaa; margin-top: 16px; }
</style>
</head>
<body>
<div class="container">
  <div class="icon">❌</div>
  <h1>인증 실패</h1>
  <p>사용자명 또는 비밀번호가 올바르지 않습니다.</p>
  <a href="/">다시 시도</a>
  <div class="reason">사유: {{REASON}}</div>
</div>
</body>
</html>"##;
