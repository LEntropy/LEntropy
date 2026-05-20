pub mod audit;
pub mod endpoints;
pub mod health;
pub mod policies;

use axum::Router;
use sqlx::PgPool;

/// 전체 API 라우터
pub fn router(pool: PgPool) -> Router {
    Router::new()
        .nest("/api/v1", v1_router(pool))
        .route("/healthz", axum::routing::get(health::health_check))
}

fn v1_router(pool: PgPool) -> Router {
    use axum::routing::get;
    Router::new()
        // Endpoints
        .route("/endpoints", get(endpoints::list_endpoints))
        .route("/endpoints/:id", get(endpoints::get_endpoint))
        .route("/endpoints/mac/:mac", get(endpoints::get_endpoint_by_mac))
        // Policies
        .route("/policies", get(policies::list_policies).post(policies::create_policy))
        .route(
            "/policies/:id",
            get(policies::get_policy)
                .put(policies::update_policy)
                .delete(policies::delete_policy),
        )
        // Audit log
        .route("/audit", get(audit::list_audit))
        .with_state(pool)
}
