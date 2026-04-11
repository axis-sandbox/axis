// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! HTTP request router for the gateway.

use crate::GatewayState;
use http_body_util::Full;
use hyper::{body::Bytes, Request, Response, StatusCode};
use std::sync::Arc;

type BoxBody = Full<Bytes>;

/// Route incoming HTTP requests to the appropriate handler.
pub async fn route(
    req: Request<hyper::body::Incoming>,
    state: Arc<GatewayState>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    // Handle CORS preflight (OPTIONS) for all paths.
    if method == hyper::Method::OPTIONS {
        let response = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("access-control-allow-origin", "*")
            .header("access-control-allow-methods", "GET, POST, PUT, DELETE, OPTIONS")
            .header("access-control-allow-headers", "content-type, authorization")
            .header("access-control-max-age", "86400")
            .body(Full::new(Bytes::new()))
            .unwrap();
        return Ok(response);
    }

    // Parse path segments for dynamic routing.
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();

    let response = match (method.as_str(), segments.as_slice()) {
        // GET /api/v1/health
        ("GET", ["api", "v1", "health"]) => {
            json_response(StatusCode::OK, serde_json::json!({
                "status": "ok",
                "version": env!("CARGO_PKG_VERSION"),
            }))
        }

        // GET /api/v1/sandboxes
        ("GET", ["api", "v1", "sandboxes"]) => {
            super::handlers::list_sandboxes(state).await
        }

        // POST /api/v1/sandboxes
        ("POST", ["api", "v1", "sandboxes"]) => {
            super::handlers::create_sandbox(req, state).await
        }

        // DELETE /api/v1/sandboxes/:id
        ("DELETE", ["api", "v1", "sandboxes", id]) => {
            super::handlers::destroy_sandbox(id, state).await
        }

        // GET /api/v1/agents
        ("GET", ["api", "v1", "agents"]) => {
            super::handlers::list_agents(state).await
        }

        // POST /api/v1/agents/:name/run
        ("POST", ["api", "v1", "agents", name, "run"]) => {
            super::handlers::run_agent(name, state).await
        }

        // WebSocket: GET /ws/v1/events
        ("GET", ["ws", "v1", "events"]) => {
            return super::events::handle_ws_upgrade(req, state).await;
        }

        // 404
        _ => {
            json_response(StatusCode::NOT_FOUND, serde_json::json!({
                "error": "not found",
                "path": path,
            }))
        }
    };

    Ok(response)
}

/// Helper to create a JSON HTTP response with CORS headers.
pub fn json_response(status: StatusCode, body: serde_json::Value) -> Response<BoxBody> {
    let json = serde_json::to_string(&body).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("access-control-allow-origin", "*")
        .header("access-control-allow-methods", "GET, POST, PUT, DELETE, OPTIONS")
        .header("access-control-allow-headers", "content-type, authorization")
        .body(Full::new(Bytes::from(json)))
        .unwrap()
}
