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
pub async fn list_sandboxes(_state: Arc<GatewayState>) -> Response<BoxBody> {
    // TODO: Wire to SandboxManager via shared Arc<Mutex<>> once daemon integration is done.
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "sandboxes": []
        }),
    )
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
            "error": "not yet implemented"
        }),
    )
}

/// GET /api/v1/agents — list installed agents.
pub async fn list_agents(_state: Arc<GatewayState>) -> Response<BoxBody> {
    // Read installed agents from the filesystem.
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
                agents.push(serde_json::json!({
                    "name": entry.file_name().to_string_lossy(),
                    "installed": true,
                }));
            }
        }
    }

    json_response(
        StatusCode::OK,
        serde_json::json!({ "agents": agents }),
    )
}
