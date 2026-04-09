// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! HTTP health check endpoint for axisd.
//!
//! Runs a minimal HTTP server on a configurable port (default 18517).
//! Returns JSON with daemon status for monitoring/alerting.

use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// Shared health state updated by the sandbox manager.
pub struct HealthState {
    pub sandbox_count: AtomicUsize,
    pub start_time: std::time::Instant,
}

impl HealthState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sandbox_count: AtomicUsize::new(0),
            start_time: std::time::Instant::now(),
        })
    }
}

/// Start the health check HTTP server.
pub async fn serve_health(state: Arc<HealthState>) {
    let port: u16 = std::env::var("AXIS_HEALTH_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(18517);

    let listener = match TcpListener::bind(format!("127.0.0.1:{port}")).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("health endpoint: cannot bind port {port}: {e}");
            return;
        }
    };

    tracing::info!("health endpoint on http://127.0.0.1:{port}/health");

    loop {
        let Ok((stream, _)) = listener.accept().await else { break };
        let state = state.clone();

        tokio::spawn(async move {
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).await.is_err() { return; }

            // Consume headers.
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).await.is_err() { return; }
                if line.trim().is_empty() { break; }
            }

            let body = serde_json::json!({
                "status": "ok",
                "version": env!("CARGO_PKG_VERSION"),
                "uptime_sec": state.start_time.elapsed().as_secs(),
                "sandbox_count": state.sandbox_count.load(Ordering::Relaxed),
                "pid": std::process::id(),
            });

            let body_str = body.to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_str}",
                body_str.len()
            );
            let _ = writer.write_all(resp.as_bytes()).await;
        });
    }
}
