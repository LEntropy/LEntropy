pub mod endpoints;
pub mod health;

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
        .route("/endpoints", get(endpoints::list_endpoints))
        .route("/endpoints/:id", get(endpoints::get_endpoint))
        .route("/endpoints/mac/:mac", get(endpoints::get_endpoint_by_mac))
        .with_state(pool)
}
