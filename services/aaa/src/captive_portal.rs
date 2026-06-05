//! Captive portal HTTP server for NAC authentication.
//!
//! Routes:
//!   GET  /                   → status-aware landing page
//!   POST /login              → LDAP (or local DB fallback) auth → JWT → NATS event
//!   GET  /success            → success page
//!   GET  /denied             → denied page
//!   GET  /blocked            → hard-blocked page
//!   GET  /health             → {"status":"ok"}
//!   GET  /ncsi.txt           → Windows NCSI connectivity probe
//!   GET  /generate_204       → Android/Chrome connectivity probe
//!   GET  /hotspot-detect.html → iOS/macOS connectivity probe
//!   *    (fallback)          → redirect based on endpoint status

use std::net::SocketAddr;
use std::sync::Arc;

use async_nats::Client as NatsClient;
use axum::{
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Router,
};
use nac_auth::{jwt::sign_token, LdapClient, LocalAuth, NacClaims};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use time::OffsetDateTime;
use tracing::{error, info, warn};

// ── State ────────────────────────────────────────────────────────────────────

pub struct PortalState {
    pub ldap: Option<LdapClient>,
    pub local_auth: LocalAuth,
    pub nats: NatsClient,
    pub jwt_secret: Vec<u8>,
    pub pool: PgPool,
    pub default_mac: Option<String>,
}

pub type SharedState = Arc<PortalState>;

// ── Router ───────────────────────────────────────────────────────────────────

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/", get(landing_page))
        .route("/login", post(handle_login))
        .route("/success", get(success_page))
        .route("/denied", get(denied_page))
        .route("/blocked", get(blocked_page))
        .route("/health", get(health))
        // OS connectivity probes — must return correct response when endpoint is allowed
        .route("/ncsi.txt", get(ncsi_probe))
        .route("/generate_204", get(generate_204))
        .route("/hotspot-detect.html", get(hotspot_detect))
        .fallback(catch_all)
        .with_state(state)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

async fn health() -> impl IntoResponse {
    axum::Json(json!({"status": "ok"}))
}

/// DB에서 IP로 엔드포인트 MAC 조회 (캡티브 포털 로그인 시 MAC 특정용)
async fn mac_from_db(pool: &PgPool, ip: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT mac_address::TEXT FROM endpoints \
         WHERE ip_address = $1 OR ip_address = $2 LIMIT 1",
    )
    .bind(format!("{ip}/32"))
    .bind(ip)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

/// DB에서 IP로 엔드포인트 상태 조회
async fn endpoint_status(pool: &PgPool, ip: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT status FROM endpoints WHERE ip_address = $1 OR ip_address = $2 LIMIT 1",
    )
    .bind(format!("{ip}/32"))
    .bind(ip)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

// ── Connectivity probes (Windows NCSI / Android / iOS) ───────────────────────
//
// OS들은 네트워크 연결 시 이 URL들로 프로브를 보낸다.
// - blocked/quarantined: nftables가 이 요청을 Pi로 redirect → captive portal로 안내
// - allowed: nftables 규칙 없음 → 실제 서버에 도달해야 하지만 혹시 여기 오면 정상 응답

async fn ncsi_probe(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    let ip = addr.ip().to_string();
    match endpoint_status(&state.pool, &ip).await.as_deref() {
        Some("denied") => Redirect::to("/blocked").into_response(),
        Some("quarantined") => Redirect::to("/").into_response(),
        // allowed이거나 상태 미확인: Windows NCSI 정상 응답 반환 → OS 팝업 해제
        _ => (StatusCode::OK, "Microsoft NCSI\r\n").into_response(),
    }
}

async fn generate_204(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    let ip = addr.ip().to_string();
    match endpoint_status(&state.pool, &ip).await.as_deref() {
        Some("denied") => Redirect::to("/blocked").into_response(),
        Some("quarantined") => Redirect::to("/").into_response(),
        _ => StatusCode::NO_CONTENT.into_response(),
    }
}

async fn hotspot_detect(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    let ip = addr.ip().to_string();
    match endpoint_status(&state.pool, &ip).await.as_deref() {
        Some("denied") => Redirect::to("/blocked").into_response(),
        Some("quarantined") => Redirect::to("/").into_response(),
        _ => Html("<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>")
            .into_response(),
    }
}

// ── Page handlers ─────────────────────────────────────────────────────────────

async fn landing_page(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    let ip = addr.ip().to_string();
    let mac = mac_from_db(&state.pool, &ip).await.unwrap_or_default();
    match endpoint_status(&state.pool, &ip).await.as_deref() {
        Some("denied") => {
            info!(ip, "blocked endpoint accessed captive portal");
            Html(BLOCKED_HTML).into_response()
        }
        Some("quarantined") => {
            info!(ip, "quarantined endpoint accessing captive portal");
            Html(login_html(&mac)).into_response()
        }
        _ => Html(login_html(&mac)).into_response(),
    }
}

async fn catch_all(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    let ip = addr.ip().to_string();
    match endpoint_status(&state.pool, &ip).await.as_deref() {
        Some("denied") => Redirect::to("/blocked").into_response(),
        Some("quarantined") => Redirect::to("/").into_response(),
        // allowed이거나 미등록: 204로 응답해 OS가 연결됐다고 인식하게 함
        _ => StatusCode::NO_CONTENT.into_response(),
    }
}

async fn blocked_page() -> Html<&'static str> {
    Html(BLOCKED_HTML)
}

// ── Login ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
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

async fn handle_login(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Form(form): Form<LoginForm>,
) -> Response {
    let client_ip = addr.ip().to_string();
    let mac = if let Some(m) = form.mac.as_deref().filter(|m| !m.is_empty()) {
        m.to_string()
    } else if let Some(m) = state.default_mac.clone() {
        m
    } else {
        mac_from_db(&state.pool, &client_ip)
            .await
            .unwrap_or_default()
    };

    info!(username = %form.username, mac = %mac, "login attempt");

    // LDAP 우선, 없으면 로컬 DB 인증 fallback
    let identity_result: anyhow::Result<nac_auth::UserIdentity> = if let Some(ldap) = &state.ldap {
        ldap.authenticate(&form.username, &form.password).await
    } else {
        state
            .local_auth
            .authenticate(&form.username, &form.password)
            .await
            .map_err(anyhow::Error::from)
    };

    match identity_result {
        Ok(identity) => {
            info!(
                username = %identity.username,
                groups   = ?identity.groups,
                "authentication successful"
            );

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
                "authentication failed"
            );

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
    Html(DENIED_HTML.replace("{{REASON}}", &reason))
}

// ── NATS publish ──────────────────────────────────────────────────────────────

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
        Err(e) => error!(error = %e, "failed to serialize auth response event"),
    }
}

// ── Static HTML ───────────────────────────────────────────────────────────────

fn login_html(mac: &str) -> String {
    LOGIN_HTML_TEMPLATE.replace("{{MAC}}", mac)
}

static LOGIN_HTML_TEMPLATE: &str = r##"<!DOCTYPE html>
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
    <input type="hidden" name="mac" value="{{MAC}}">
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
  .btn {
    display: inline-block; margin-top: 24px; padding: 12px 32px;
    background: #4f46e5; color: #fff; border-radius: 8px;
    text-decoration: none; font-weight: 600; font-size: 15px;
  }
</style>
<script>
  // 인증 성공 후 3초마다 연결 상태를 확인해 OS 팝업이 자동으로 닫히도록 한다
  let tries = 0;
  const check = setInterval(async () => {
    try {
      const r = await fetch('/generate_204');
      if (r.status === 204) { clearInterval(check); }
    } catch (_) {}
    if (++tries > 10) clearInterval(check);
  }, 3000);
</script>
</head>
<body>
<div class="container">
  <div class="icon">✅</div>
  <h1>인증 성공</h1>
  <p>네트워크 접속이 허가되었습니다.<br>브라우저를 닫고 다시 접속해보세요.</p>
  <a class="btn" href="http://www.msftncsi.com/ncsi.txt" onclick="window.open(this.href);return false;">연결 확인</a>
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

static BLOCKED_HTML: &str = r##"<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>네트워크 접근 차단됨</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #fef2f2;
    display: flex; align-items: center; justify-content: center; min-height: 100vh;
  }
  .container {
    background: #fff; border-radius: 12px;
    box-shadow: 0 4px 24px rgba(0,0,0,.12);
    padding: 48px 40px; width: 100%; max-width: 480px; text-align: center;
  }
  .icon { font-size: 72px; margin-bottom: 24px; }
  h1 { font-size: 24px; font-weight: 700; color: #dc2626; margin-bottom: 12px; }
  .subtitle { font-size: 15px; color: #666; margin-bottom: 28px; line-height: 1.6; }
  .info-box {
    background: #fef2f2; border: 1px solid #fecaca;
    border-radius: 8px; padding: 16px 20px;
    text-align: left; margin-bottom: 24px;
  }
  .info-box p { font-size: 13px; color: #7f1d1d; margin-bottom: 6px; }
  .info-box p:last-child { margin-bottom: 0; }
  .info-box strong { color: #dc2626; }
  .contact {
    font-size: 13px; color: #888;
    padding-top: 20px; border-top: 1px solid #f3f4f6;
  }
  .contact a { color: #4f46e5; text-decoration: none; }
</style>
</head>
<body>
<div class="container">
  <div class="icon">🚫</div>
  <h1>네트워크 접근이 차단되었습니다</h1>
  <p class="subtitle">
    귀하의 단말은 보안 정책에 의해<br>네트워크 접근이 제한된 상태입니다.
  </p>
  <div class="info-box">
    <p>⚠️ <strong>차단 사유:</strong> 보안 정책 위반 또는 관리자 설정</p>
    <p>📋 <strong>현재 상태:</strong> 인터넷 및 내부망 접근 불가</p>
    <p>🔒 <strong>조치:</strong> 네트워크 관리자에게 문의하세요</p>
  </div>
  <div class="contact">
    문의: 네트워크 관리자<br>
    <a href="mailto:admin@example.com">admin@example.com</a>
  </div>
</div>
</body>
</html>"##;
