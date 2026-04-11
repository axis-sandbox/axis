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

    let response = match (method.as_str(), path.as_str()) {
        // Health check
        ("GET", "/api/v1/health") => {
            json_response(StatusCode::OK, serde_json::json!({
                "status": "ok",
                "version": env!("CARGO_PKG_VERSION"),
            }))
        }

        // Sandbox management
        ("GET", "/api/v1/sandboxes") => {
            super::handlers::list_sandboxes(state).await
        }
        ("POST", "/api/v1/sandboxes") => {
            super::handlers::create_sandbox(req, state).await
        }

        // Agent management
        ("GET", "/api/v1/agents") => {
            super::handlers::list_agents(state).await
        }

        // WebSocket upgrade for event streaming
        ("GET", "/ws/v1/events") => {
            return super::events::handle_ws_upgrade(req, state).await;
        }

        // 404 for everything else
        _ => {
            json_response(StatusCode::NOT_FOUND, serde_json::json!({
                "error": "not found",
                "path": path,
            }))
        }
    };

    Ok(response)
}

/// Helper to create a JSON HTTP response.
pub fn json_response(status: StatusCode, body: serde_json::Value) -> Response<BoxBody> {
    let json = serde_json::to_string(&body).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("access-control-allow-origin", "*")
        .body(Full::new(Bytes::from(json)))
        .unwrap()
}
