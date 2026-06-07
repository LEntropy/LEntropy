//! NATS consumer for `nac.events.auth.response`.
//!
//! When the captive portal (aaa service) authenticates a user it publishes an
//! AuthResponse event.  This handler:
//!   1. Looks up the session (by session_id, or falls back to finding the
//!      active session for the endpoint).
//!   2. On success: transitions the session to "active", updates the endpoint
//!      username, re-evaluates policy (with user groups), and publishes an
//!      enforcement allow command.
//!   3. On failure: terminates the session and writes an audit log entry.

use anyhow::Result;
use async_nats::Client;
use futures_util::StreamExt;
use nac_policy_engine::evaluator;
use nac_policy_engine::PolicyDecision;
use nac_store::audit::AuditRepo;
use nac_store::endpoint::{EndpointRepo, UpsertEndpoint};
use nac_store::policy::{decision_to_status, PolicyRepo};
use nac_store::session::SessionRepo;
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

const SUBJECT: &str = "nac.events.auth.response";
const ENFORCEMENT_SUBJECT: &str = "nac.commands.enforcement";

/// Payload published by the aaa service after a login attempt.
#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    pub session_id: Option<Uuid>,
    pub endpoint_id: Option<Uuid>,
    pub mac_address: String,
    #[serde(default)]
    pub ip_address: String,
    pub success: bool,
    pub username: Option<String>,
    pub groups: Vec<String>,
    pub reason: Option<String>,
}

/// Subscribes to `nac.events.auth.response` and processes each message.
pub async fn run(nats: Client, pool: PgPool) -> Result<()> {
    let mut sub = nats.subscribe(SUBJECT).await?;
    info!(subject = SUBJECT, "auth response consumer started");

    while let Some(msg) = sub.next().await {
        let resp = match serde_json::from_slice::<AuthResponse>(&msg.payload) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "failed to parse auth.response — skipping");
                continue;
            }
        };

        debug!(
            mac     = %resp.mac_address,
            success = resp.success,
            user    = ?resp.username,
            "auth response received"
        );

        if let Err(e) = process_auth_response(&nats, &pool, resp).await {
            error!(error = %e, "error processing auth response");
        }
    }

    info!("auth response consumer stopped");
    Ok(())
}

async fn process_auth_response(nats: &Client, pool: &PgPool, resp: AuthResponse) -> Result<()> {
    let session_repo = SessionRepo::new(pool);
    let endpoint_repo = EndpointRepo::new(pool);
    let policy_repo = PolicyRepo::new(pool);
    let audit_repo = AuditRepo::new(pool);

    // ── Resolve endpoint ─────────────────────────────────────────────────
    // MAC이 비어있으면 find_by_mac이 "invalid input syntax for type macaddr" DB 에러를 반환
    if resp.endpoint_id.is_none() && resp.mac_address.is_empty() {
        warn!(ip = %resp.ip_address, "auth response has no MAC and no endpoint_id — skipping");
        return Ok(());
    }
    let endpoint = match &resp.endpoint_id {
        Some(eid) => endpoint_repo.find_by_id(*eid).await?,
        None => endpoint_repo.find_by_mac(&resp.mac_address).await?,
    };

    let endpoint = match endpoint {
        Some(ep) => ep,
        None => {
            // 캡티브 포털 인증 시 ARP sync 전에 로그인할 수 있음 — 자동 등록
            if resp.mac_address.is_empty() {
                warn!(ip = %resp.ip_address, "endpoint not found and no MAC in auth response");
                return Ok(());
            }
            info!(
                mac = %resp.mac_address,
                ip  = %resp.ip_address,
                "endpoint not in DB — auto-registering from auth event"
            );
            let ip_opt = if resp.ip_address.is_empty() {
                None
            } else {
                Some(resp.ip_address.clone())
            };
            endpoint_repo
                .upsert(&UpsertEndpoint {
                    mac_address: resp.mac_address.clone(),
                    ip_address: ip_opt,
                    hostname: None,
                    os_family: None,
                    os_version: None,
                    device_type: None,
                    vendor: None,
                    interface: None,
                    agent_id: None,
                })
                .await?
        }
    };

    // ── Resolve session ──────────────────────────────────────────────────
    let session = match resp.session_id {
        Some(sid) => session_repo.find_by_id(sid).await?,
        None => session_repo.find_active_by_endpoint(endpoint.id).await?,
    };

    // ── Handle auth failure ──────────────────────────────────────────────
    if !resp.success {
        if let Some(sess) = &session {
            session_repo.terminate(sess.id).await?;
            info!(session_id = %sess.id, mac = %resp.mac_address, "session terminated after auth failure");
        }

        audit_repo
            .log(
                "auth_failed",
                Some(endpoint.id),
                "aaa/captive_portal",
                json!({
                    "mac": resp.mac_address,
                    "reason": resp.reason,
                }),
            )
            .await?;

        return Ok(());
    }

    // ── Auth success ─────────────────────────────────────────────────────
    let username = resp.username.as_deref().unwrap_or("");

    // Update endpoint username
    if !username.is_empty() {
        endpoint_repo.set_username(endpoint.id, username).await?;
        debug!(endpoint_id = %endpoint.id, username, "endpoint username updated");
    }

    // Transition session to "active"
    if let Some(sess) = &session {
        session_repo
            .transition(sess.id, "active", Some(username))
            .await?;
        info!(session_id = %sess.id, username, "session transitioned to active");
    } else {
        debug!(mac = %resp.mac_address, "no active session found; skipping session transition");
    }

    // ── Re-evaluate policy with user groups ──────────────────────────────
    let mut rules = policy_repo.load_rules().await?;
    if rules.is_empty() {
        debug!(mac = %resp.mac_address, "no policies — skipping re-evaluation");
        return Ok(());
    }

    let ctx = nac_policy_engine::PolicyContext {
        mac_address: endpoint.mac_address.clone(),
        ip_address: endpoint.ip_address.clone(),
        hostname: endpoint.hostname.clone(),
        os_family: endpoint.os_family.clone(),
        device_type: endpoint.device_type.clone(),
        username: Some(username.to_string()),
        groups: resp.groups.clone(),
        is_compliant: None,
        switch_port: endpoint.switch_port.clone(),
    };

    let decision = evaluator::evaluate(&mut rules, &ctx)?;
    let new_status = decision_to_status(&decision);

    info!(
        mac      = %resp.mac_address,
        username,
        decision = ?decision,
        status   = new_status,
        "policy re-evaluated after auth"
    );

    // Update endpoint status if changed
    if endpoint.status != new_status {
        endpoint_repo.set_status(endpoint.id, new_status).await?;
    }

    // ── Publish enforcement command ───────────────────────────────────────
    publish_enforcement_command(
        nats,
        &resp.mac_address,
        &endpoint.ip_address,
        new_status,
        &decision,
    )
    .await;

    // ── Audit log ────────────────────────────────────────────────────────
    audit_repo
        .log(
            "auth_success",
            Some(endpoint.id),
            "aaa/captive_portal",
            json!({
                "mac":      resp.mac_address,
                "username": username,
                "groups":   resp.groups,
                "decision": format!("{:?}", decision),
                "status":   new_status,
            }),
        )
        .await?;

    Ok(())
}

async fn publish_enforcement_command(
    nats: &Client,
    mac: &str,
    ip: &Option<String>,
    status: &str,
    decision: &PolicyDecision,
) {
    let action = match status {
        "quarantined" => "quarantine",
        "denied" => "block",
        "allowed" => "allow",
        _ => "allow",
    };

    let vlan_id = match decision {
        PolicyDecision::Quarantine { vlan, .. } => Some(*vlan),
        PolicyDecision::AllowVlan(v) => Some(*v),
        _ => None,
    };

    let cmd = json!({
        "mac_address": mac,
        "ip_address":  ip.as_deref().unwrap_or(""),
        "action":      action,
        "gateway_ip":  "",
        "gateway_mac": null,
        "vlan_id":     vlan_id,
    });

    match serde_json::to_vec(&cmd) {
        Ok(payload) => {
            if let Err(e) = nats.publish(ENFORCEMENT_SUBJECT, payload.into()).await {
                warn!(error = %e, mac, "failed to publish enforcement command");
            } else {
                debug!(mac, action, "enforcement command published after auth");
            }
        }
        Err(e) => {
            warn!(error = %e, "failed to serialize enforcement command");
        }
    }
}
