// Integration tests for the AXIS gateway API.
// Tests the full HTTP stack (router + handlers) without needing native apps.
//
// Run with: cargo test -p axis-gateway --test api_integration

use axis_gateway::{start_gateway, GatewayConfig, GatewayState};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Start a gateway on a random port and return its address.
async fn spawn_test_gateway() -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let (event_tx, _) = broadcast::channel(64);
    let state = Arc::new(GatewayState::new(event_tx));

    // Find a free port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // Release port for gateway to bind.

    let config = GatewayConfig { bind_addr: addr };
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        start_gateway(config, state, shutdown_rx).await.ok();
    });

    // Wait for server to be ready — retry connect.
    for _ in 0..20 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    (addr, shutdown_tx)
}

async fn get(addr: SocketAddr, path: &str) -> (u16, serde_json::Value) {
    let url = format!("http://{addr}{path}");
    let resp = reqwest::get(&url).await.unwrap();
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.unwrap();
    (status, body)
}

async fn post(addr: SocketAddr, path: &str) -> (u16, serde_json::Value) {
    let url = format!("http://{addr}{path}");
    let client = reqwest::Client::new();
    let resp = client.post(&url)
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.unwrap();
    (status, body)
}

async fn delete(addr: SocketAddr, path: &str) -> (u16, serde_json::Value) {
    let url = format!("http://{addr}{path}");
    let client = reqwest::Client::new();
    let resp = client.delete(&url).send().await.unwrap();
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.unwrap();
    (status, body)
}

async fn options(addr: SocketAddr, path: &str) -> reqwest::Response {
    let url = format!("http://{addr}{path}");
    let client = reqwest::Client::new();
    client
        .request(reqwest::Method::OPTIONS, &url)
        .header("origin", "https://axis.local")
        .header("access-control-request-method", "POST")
        .send()
        .await
        .unwrap()
}

// ── Health ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn health_returns_ok_with_version() {
    let (addr, _shutdown) = spawn_test_gateway().await;
    let (status, body) = get(addr, "/api/v1/health").await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");
    assert!(body["version"].as_str().unwrap().len() > 0);
}

// ── CORS ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn cors_preflight_returns_204() {
    let (addr, _shutdown) = spawn_test_gateway().await;
    let resp = options(addr, "/api/v1/agents").await;
    assert_eq!(resp.status(), 204);
    assert_eq!(
        resp.headers().get("access-control-allow-origin").unwrap(),
        "*"
    );
    assert!(
        resp.headers()
            .get("access-control-allow-methods")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("POST")
    );
}

#[tokio::test]
async fn responses_include_cors_headers() {
    let (addr, _shutdown) = spawn_test_gateway().await;
    let url = format!("http://{addr}/api/v1/health");
    let resp = reqwest::get(&url).await.unwrap();
    assert_eq!(
        resp.headers().get("access-control-allow-origin").unwrap(),
        "*"
    );
}

// ── Sandboxes ───────────────────────────────────────────────────────────

#[tokio::test]
async fn list_sandboxes_returns_empty_array() {
    let (addr, _shutdown) = spawn_test_gateway().await;
    let (status, body) = get(addr, "/api/v1/sandboxes").await;
    assert_eq!(status, 200);
    assert_eq!(body["sandboxes"], serde_json::json!([]));
}

#[tokio::test]
async fn destroy_sandbox_returns_id() {
    let (addr, _shutdown) = spawn_test_gateway().await;
    let (status, body) = delete(addr, "/api/v1/sandboxes/abc-123").await;
    assert_eq!(status, 200);
    assert_eq!(body["destroyed"], "abc-123");
}

// ── Agents ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_agents_returns_array() {
    let (addr, _shutdown) = spawn_test_gateway().await;
    let (status, body) = get(addr, "/api/v1/agents").await;
    assert_eq!(status, 200);
    assert!(body["agents"].is_array());
}

#[tokio::test]
async fn run_nonexistent_agent_returns_not_found() {
    let (addr, _shutdown) = spawn_test_gateway().await;
    let (status, body) = post(addr, "/api/v1/agents/fake-agent-999/run").await;
    assert_eq!(status, 404);
    assert!(body["error"].as_str().unwrap().contains("not installed"));
}

#[tokio::test]
async fn run_installed_agent_returns_sandbox_id() {
    let (addr, _shutdown) = spawn_test_gateway().await;
    // This test will pass only if agents are installed (e.g., claude-code).
    // On CI without agents, it returns 404 which is also valid.
    let (status, body) = post(addr, "/api/v1/agents/claude-code/run").await;
    if status == 200 {
        assert!(body["sandbox_id"].as_str().unwrap().len() > 0);
        assert_eq!(body["agent"], "claude-code");
    } else {
        assert_eq!(status, 404);
    }
}

// ── 404 ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn unknown_path_returns_404() {
    let (addr, _shutdown) = spawn_test_gateway().await;
    let (status, body) = get(addr, "/api/v1/nonexistent").await;
    assert_eq!(status, 404);
    assert_eq!(body["error"], "not found");
}

#[tokio::test]
async fn wrong_method_returns_404() {
    let (addr, _shutdown) = spawn_test_gateway().await;
    let (status, _) = delete(addr, "/api/v1/health").await;
    assert_eq!(status, 404);
}
