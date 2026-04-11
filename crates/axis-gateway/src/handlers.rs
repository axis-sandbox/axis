// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! REST API request handlers.

use crate::router::json_response;
use crate::GatewayState;
use http_body_util::Full;
use hyper::{body::Bytes, Request, Response, StatusCode};
use std::sync::Arc;

type BoxBody = Full<Bytes>;

/// GET /api/v1/sandboxes — list running sandboxes.
pub async fn list_sandboxes(state: Arc<GatewayState>) -> Response<BoxBody> {
    if let Some(ref backend) = state.sandbox_backend {
        let sandboxes = backend.list_sandboxes().await;
        json_response(StatusCode::OK, serde_json::json!({ "sandboxes": sandboxes }))
    } else {
        json_response(StatusCode::OK, serde_json::json!({ "sandboxes": [] }))
    }
}

/// POST /api/v1/sandboxes — create a new sandbox.
pub async fn create_sandbox(
    _req: Request<hyper::body::Incoming>,
    _state: Arc<GatewayState>,
) -> Response<BoxBody> {
    // TODO: Parse body, create sandbox via SandboxManager.
    json_response(
        StatusCode::NOT_IMPLEMENTED,
        serde_json::json!({
            "error": "sandbox creation via gateway not yet wired to daemon"
        }),
    )
}

/// DELETE /api/v1/sandboxes/:id — destroy a sandbox.
pub async fn destroy_sandbox(
    id: &str,
    state: Arc<GatewayState>,
) -> Response<BoxBody> {
    tracing::info!("destroy sandbox requested: {id}");
    if let Some(ref backend) = state.sandbox_backend {
        match backend.destroy_sandbox(id).await {
            Ok(()) => json_response(StatusCode::OK, serde_json::json!({ "destroyed": id })),
            Err(e) => json_response(StatusCode::INTERNAL_SERVER_ERROR, serde_json::json!({ "error": e })),
        }
    } else {
        json_response(StatusCode::OK, serde_json::json!({ "destroyed": id }))
    }
}

/// GET /api/v1/agents — list installed agents.
pub async fn list_agents(_state: Arc<GatewayState>) -> Response<BoxBody> {
    let agents = discover_installed_agents();
    json_response(
        StatusCode::OK,
        serde_json::json!({ "agents": agents }),
    )
}

/// POST /api/v1/agents/:name/run — one-click agent launch.
/// Finds the agent binary, resolves its policy, creates a sandbox, returns sandbox_id.
pub async fn run_agent(
    name: &str,
    state: Arc<GatewayState>,
) -> Response<BoxBody> {
    tracing::info!("run agent requested: {name}");

    // Check if agent is installed.
    let agents = discover_installed_agents();
    let agent = agents.iter().find(|a| a["name"].as_str() == Some(name));

    if agent.is_none() {
        return json_response(
            StatusCode::NOT_FOUND,
            serde_json::json!({
                "error": format!("agent '{name}' is not installed"),
                "hint": format!("Run: axis install {name}")
            }),
        );
    }

    // Find the agent's wrapper script (which contains the real binary path).
    let (binary, policy_path) = match find_agent_binary(name) {
        Some(pair) => pair,
        None => {
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({
                    "error": format!("agent '{name}' is installed but wrapper not found")
                }),
            );
        }
    };

    // Read the policy YAML.
    let policy_yaml = match std::fs::read_to_string(&policy_path) {
        Ok(yaml) => yaml,
        Err(e) => {
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "error": format!("cannot read policy: {e}") }),
            );
        }
    };

    // Create sandbox via backend if available, otherwise return mock.
    if let Some(ref backend) = state.sandbox_backend {
        match backend.create_sandbox(&policy_yaml, binary, vec![]).await {
            Ok(sandbox_id) => {
                json_response(StatusCode::OK, serde_json::json!({
                    "sandbox_id": sandbox_id,
                    "agent": name,
                    "status": "running"
                }))
            }
            Err(e) => {
                json_response(StatusCode::INTERNAL_SERVER_ERROR, serde_json::json!({
                    "error": format!("sandbox creation failed: {e}")
                }))
            }
        }
    } else {
        // No backend — return mock sandbox_id for UI testing.
        let sandbox_id = uuid::Uuid::new_v4().to_string();
        json_response(StatusCode::OK, serde_json::json!({
            "sandbox_id": sandbox_id,
            "agent": name,
            "status": "created (mock — no daemon backend)"
        }))
    }
}

/// Find an agent's real binary path and policy path from its wrapper script.
fn find_agent_binary(name: &str) -> Option<(String, String)> {
    let axis_root = if cfg!(windows) {
        std::env::var("LOCALAPPDATA").unwrap_or_default() + "\\axis"
    } else {
        std::env::var("HOME").unwrap_or("/tmp".into()) + "/.axis"
    };

    let bin_dir = std::path::Path::new(&axis_root).join("bin");
    let policies_dir = std::path::Path::new(&axis_root).join("policies").join("agents");

    // Read the .cmd wrapper to extract the real binary path.
    let wrapper = if cfg!(windows) {
        bin_dir.join(agent_binary_name(name)).with_extension("cmd")
    } else {
        bin_dir.join(agent_binary_name(name))
    };

    if let Ok(content) = std::fs::read_to_string(&wrapper) {
        // Parse the wrapper to find the real binary and policy.
        // Windows .cmd format: ... run --policy "POLICY" -- "BINARY" ...
        let binary = extract_quoted_after(&content, "-- \"")
            .or_else(|| extract_quoted_after(&content, "-- '"));
        let policy = extract_quoted_after(&content, "--policy \"")
            .or_else(|| extract_quoted_after(&content, "--policy '"));

        if let (Some(bin), Some(pol)) = (binary, policy) {
            return Some((bin, pol));
        }
    }

    // Fallback: look for a well-known policy file.
    let policy_file = policies_dir.join(format!("{name}.yaml"));
    if !policy_file.exists() {
        // Try common aliases.
        let aliases = [
            (name, format!("{name}.yaml")),
            ("claude-code", "claude-code.yaml".to_string()),
        ];
        for (agent_name, pol_name) in &aliases {
            if *agent_name == name {
                let p = policies_dir.join(pol_name);
                if p.exists() {
                    return Some((name.to_string(), p.to_string_lossy().to_string()));
                }
            }
        }
    }

    None
}

/// Map agent name to its binary name.
fn agent_binary_name(name: &str) -> &str {
    match name {
        "claude-code" => "claude",
        "gemini-cli" => "gemini",
        other => other,
    }
}

/// Extract a quoted string after a marker in text.
fn extract_quoted_after(text: &str, marker: &str) -> Option<String> {
    let idx = text.find(marker)?;
    let start = idx + marker.len();
    let quote = marker.chars().last()?;
    let rest = &text[start..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

/// Discover installed agents from the filesystem.
fn discover_installed_agents() -> Vec<serde_json::Value> {
    let axis_root = if cfg!(windows) {
        std::env::var("LOCALAPPDATA")
            .unwrap_or_else(|_| "C:\\Users\\Public".into())
            + "\\axis"
    } else {
        std::env::var("HOME").unwrap_or("/tmp".into()) + "/.axis"
    };

    let tools_dir = std::path::Path::new(&axis_root).join("tools");
    let mut agents = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&tools_dir) {
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let name = entry.file_name().to_string_lossy().to_string();
                agents.push(serde_json::json!({
                    "name": name,
                    "installed": true,
                }));
            }
        }
    }

    agents
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GatewayState;
    use http_body_util::BodyExt;
    use tokio::sync::broadcast;

    fn test_state() -> Arc<GatewayState> {
        let (tx, _) = broadcast::channel(16);
        Arc::new(GatewayState::new(tx))
    }

    async fn body_json(resp: Response<BoxBody>) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn test_list_sandboxes_returns_empty() {
        let resp = list_sandboxes(test_state()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["sandboxes"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn test_list_agents_returns_array() {
        let resp = list_agents(test_state()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert!(json["agents"].is_array());
    }

    #[tokio::test]
    async fn test_destroy_sandbox_returns_id() {
        let resp = destroy_sandbox("test-id-123", test_state()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["destroyed"], "test-id-123");
    }

    #[tokio::test]
    async fn test_run_nonexistent_agent_returns_404() {
        let resp = run_agent("nonexistent-agent-xyz", test_state()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let json = body_json(resp).await;
        assert!(json["error"].as_str().unwrap().contains("not installed"));
    }
}
