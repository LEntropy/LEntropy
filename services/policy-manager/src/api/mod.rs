pub mod audit;
pub mod endpoints;
pub mod evaluate;
pub mod health;
pub mod policies;
pub mod stats;

use axum::Router;
use sqlx::PgPool;

/// 전체 API 라우터
pub fn router(pool: PgPool) -> Router {
    Router::new()
        .nest("/api/v1", v1_router(pool))
        .route("/healthz", axum::routing::get(health::health_check))
}

fn v1_router(pool: PgPool) -> Router {
    use axum::routing::{get, post};
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
        // Audit log
        .route("/audit", get(audit::list_audit))
        // Stats
        .route("/stats", get(stats::get_stats))
        .with_state(pool)
}
