//! policy-manager REST API 통합 테스트 진입점.
//!
//! 실제 DB 연결이 필요합니다. `cargo test --features integration` 으로 실행하세요.

fn main() {}

#[cfg(feature = "integration")]
mod tests {
    use reqwest::Client;

    fn base_url() -> String {
        std::env::var("POLICY_MANAGER_URL").unwrap_or_else(|_| "http://localhost:8001".to_string())
    }

    #[tokio::test]
    async fn test_health_check() {
        let client = Client::new();
        let resp = client
            .get(format!("{}/healthz", base_url()))
            .send()
            .await
            .expect("failed to connect to policy-manager");
        assert!(resp.status().is_success(), "healthz should return 200");
    }

    #[tokio::test]
    async fn test_list_endpoints_empty() {
        let client = Client::new();
        let resp = client
            .get(format!("{}/api/v1/endpoints", base_url()))
            .send()
            .await
            .expect("failed to GET /api/v1/endpoints");
        assert!(
            resp.status().is_success(),
            "list endpoints should return 2xx"
        );
        let body: serde_json::Value = resp.json().await.expect("response should be JSON");
        assert!(body.get("total").is_some(), "response should have 'total'");
        assert!(body.get("items").is_some(), "response should have 'items'");
    }

    #[tokio::test]
    async fn test_create_and_delete_policy() {
        let client = Client::new();
        let payload = serde_json::json!({
            "name": "integration-test-policy",
            "description": "created by integration test",
            "priority": 100,
            "action": "allow",
            "enabled": true,
            "conditions": {}
        });
        let create_resp = client
            .post(format!("{}/api/v1/policies", base_url()))
            .json(&payload)
            .send()
            .await
            .expect("failed to POST /api/v1/policies");
        assert_eq!(
            create_resp.status().as_u16(),
            201,
            "create policy should return 201"
        );
        let created: serde_json::Value = create_resp.json().await.expect("response should be JSON");
        let id = created["id"].as_str().expect("response should contain id");

        let delete_resp = client
            .delete(format!("{}/api/v1/policies/{}", base_url(), id))
            .send()
            .await
            .expect("failed to DELETE policy");
        assert_eq!(
            delete_resp.status().as_u16(),
            204,
            "delete policy should return 204"
        );
    }

    #[tokio::test]
    async fn test_stats_endpoint() {
        let client = Client::new();
        let resp = client
            .get(format!("{}/api/v1/stats", base_url()))
            .send()
            .await
            .expect("failed to GET /api/v1/stats");
        assert!(resp.status().is_success(), "stats should return 2xx");
        let body: serde_json::Value = resp.json().await.expect("response should be JSON");
        assert!(
            body.get("total_endpoints").is_some(),
            "stats should have 'total_endpoints'"
        );
        assert!(body.get("allowed").is_some(), "stats should have 'allowed'");
        assert!(body.get("blocked").is_some(), "stats should have 'blocked'");
        assert!(
            body.get("recent_events").is_some(),
            "stats should have 'recent_events'"
        );
    }
}
