// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! HTTP + WebSocket gateway for the AXIS daemon.
//!
//! Provides a REST API for sandbox management and WebSocket endpoints for
//! real-time event streaming and PTY terminal access. This is the primary
//! interface for GUI applications.

pub mod router;
pub mod events;
pub mod handlers;

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Gateway configuration.
pub struct GatewayConfig {
    /// Address to bind the HTTP+WS server.
    pub bind_addr: SocketAddr,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        let port: u16 = std::env::var("AXIS_GATEWAY_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(18519);
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], port)),
        }
    }
}

/// Trait for sandbox management — implemented by the daemon's SandboxManager.
/// Allows the gateway to create/destroy/list sandboxes without depending on axis-daemon.
///
/// All methods take `&self` and use interior mutability (Arc<Mutex<>>) since
/// the gateway serves concurrent requests.
pub trait SandboxBackend: Send + Sync {
    fn create_sandbox(
        &self,
        policy_yaml: &str,
        command: String,
        args: Vec<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + '_>>;

    fn destroy_sandbox(
        &self,
        id: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>>;

    fn list_sandboxes(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<serde_json::Value>> + Send + '_>>;

    /// Subscribe to a sandbox's stdout/stderr output stream.
    /// Returns (buffered_past_output, live_receiver).
    fn subscribe_output(
        &self,
        id: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<(Vec<Vec<u8>>, tokio::sync::broadcast::Receiver<Vec<u8>>)>> + Send + '_>>;

    /// Send input data to a sandbox's stdin.
    fn send_input(
        &self,
        id: &str,
        data: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>>;
}

/// Shared gateway state passed to all handlers.
pub struct GatewayState {
    /// Broadcast channel for audit events.
    pub event_tx: broadcast::Sender<axis_core::audit::AuditEvent>,
    /// Optional sandbox backend (connected when running inside axisd).
    pub sandbox_backend: Option<Arc<dyn SandboxBackend>>,
}

impl GatewayState {
    pub fn new(event_tx: broadcast::Sender<axis_core::audit::AuditEvent>) -> Self {
        Self {
            event_tx,
            sandbox_backend: None,
        }
    }

    pub fn with_backend(
        event_tx: broadcast::Sender<axis_core::audit::AuditEvent>,
        backend: Arc<dyn SandboxBackend>,
    ) -> Self {
        Self {
            event_tx,
            sandbox_backend: Some(backend),
        }
    }

    /// Subscribe to the event stream.
    pub fn subscribe_events(&self) -> broadcast::Receiver<axis_core::audit::AuditEvent> {
        self.event_tx.subscribe()
    }
}

/// Start the gateway HTTP+WebSocket server.
///
/// This function spawns the server as a tokio task and returns immediately.
/// The server runs until the provided shutdown signal fires.
pub async fn start_gateway(
    config: GatewayConfig,
    state: Arc<GatewayState>,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), anyhow::Error> {
    use hyper::server::conn::http1;
    use hyper_util::rt::TokioIo;

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    tracing::info!("gateway listening on {}", config.bind_addr);

    let shutdown_fut = async { let _ = shutdown.await; };
    tokio::pin!(shutdown_fut);

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (stream, addr) = accept?;
                let state = state.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = hyper::service::service_fn(move |req| {
                        let state = state.clone();
                        async move { router::route(req, state).await }
                    });
                    if let Err(e) = http1::Builder::new()
                        .serve_connection(io, service)
                        .with_upgrades()
                        .await
                    {
                        if !e.is_incomplete_message() {
                            tracing::debug!("gateway connection error from {addr}: {e}");
                        }
                    }
                });
            }
            _ = &mut shutdown_fut => {
                tracing::info!("gateway shutting down");
                break;
            }
        }
    }

    Ok(())
}
