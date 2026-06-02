pub mod audit;
pub mod endpoints;
pub mod evaluate;
pub mod health;
pub mod network;
pub mod policies;
pub mod stats;
pub mod users;

use async_nats::Client as NatsClient;
use axum::Router;
use sqlx::PgPool;

/// API 핸들러에서 공유하는 애플리케이션 상태
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub nats: NatsClient,
}

/// 기존 핸들러가 State<PgPool>로 추출할 수 있도록 FromRef 구현
impl axum::extract::FromRef<AppState> for PgPool {
    fn from_ref(state: &AppState) -> Self {
        state.pool.clone()
    }
}

/// 전체 API 라우터
pub fn router(pool: PgPool, nats: NatsClient) -> Router {
    Router::new()
        .nest("/api/v1", v1_router(pool, nats))
        .route("/healthz", axum::routing::get(health::health_check))
}

fn v1_router(pool: PgPool, nats: NatsClient) -> Router {
    use axum::routing::{delete, get, post, put};

    let state = AppState { pool, nats };

    Router::new()
        // Endpoints
        .route("/endpoints", get(endpoints::list_endpoints))
        .route("/endpoints/mac/{mac}", get(endpoints::get_endpoint_by_mac))
        .route("/endpoints/{id}", get(endpoints::get_endpoint))
        .route("/endpoints/{id}/allow", post(endpoints::allow_endpoint))
        .route("/endpoints/{id}/block", post(endpoints::block_endpoint))
        .route(
            "/endpoints/{id}/quarantine",
            post(endpoints::quarantine_endpoint),
        )
        .route("/endpoints/{id}/policy", post(endpoints::assign_policy))
        .route("/endpoints/{id}/exempt", post(endpoints::set_exempt))
        // Policies
        .route(
            "/policies",
            get(policies::list_policies).post(policies::create_policy),
        )
        .route("/policies/evaluate", post(evaluate::evaluate_policies))
        .route(
            "/policies/{id}",
            get(policies::get_policy)
                .put(policies::update_policy)
                .delete(policies::delete_policy),
        )
        // Network management (ARP scan + subnet view)
        .route("/network/hosts", get(network::list_hosts))
        // Audit log
        .route("/audit", get(audit::list_audit))
        // Stats
        .route("/stats", get(stats::get_stats))
        // Users (로컬 인증용)
        .route("/users", get(users::list_users).post(users::create_user))
        .route("/users/{id}", delete(users::delete_user))
        .route("/users/{id}/password", put(users::change_password))
        .route("/users/{id}/{action}", post(users::set_enabled))
        .with_state(state)
}
