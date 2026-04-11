// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! WebSocket event streaming handler.

use crate::GatewayState;
use futures_util::{SinkExt, StreamExt};
use http_body_util::Full;
use hyper::{body::Bytes, Request, Response};
use std::sync::Arc;
use tokio_tungstenite::tungstenite::Message;

/// Handle WebSocket upgrade for /ws/v1/events.
///
/// Upgrades the HTTP connection to WebSocket, then streams audit events
/// from the broadcast channel to the client.
pub async fn handle_ws_upgrade(
    mut req: Request<hyper::body::Incoming>,
    state: Arc<GatewayState>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    use base64::Engine;
    use hyper_util::rt::TokioIo;
    use sha1::{Digest, Sha1};

    // Check for WebSocket upgrade headers.
    let upgrade_header = req
        .headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !upgrade_header.eq_ignore_ascii_case("websocket") {
        let resp = Response::builder()
            .status(400)
            .body(Full::new(Bytes::from("expected websocket upgrade")))
            .unwrap();
        return Ok(resp);
    }

    let key = req
        .headers()
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Compute accept key per RFC 6455.
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-5AB5DC11650A");
    let accept = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());

    // Spawn the event streaming task after upgrade completes.
    tokio::spawn(async move {
        let upgraded = match hyper::upgrade::on(&mut req).await {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!("ws upgrade failed: {e}");
                return;
            }
        };

        let io = TokioIo::new(upgraded);
        let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            io,
            tokio_tungstenite::tungstenite::protocol::Role::Server,
            None,
        )
        .await;

        let (mut ws_tx, mut ws_rx) = ws.split();
        let mut event_rx = state.subscribe_events();

        loop {
            tokio::select! {
                event = event_rx.recv() => {
                    match event {
                        Ok(audit_event) => {
                            let json = serde_json::to_string(&audit_event).unwrap_or_default();
                            if ws_tx.send(Message::Text(json)).await.is_err() {
                                break;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!("ws client lagged by {n} events");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
                msg = ws_rx.next() => {
                    match msg {
                        Some(Ok(Message::Close(_))) | None => break,
                        Some(Ok(Message::Ping(data))) => {
                            let _ = ws_tx.send(Message::Pong(data)).await;
                        }
                        _ => {}
                    }
                }
            }
        }

        tracing::debug!("ws event client disconnected");
    });

    // Return the 101 Switching Protocols response.
    let response = Response::builder()
        .status(101)
        .header("upgrade", "websocket")
        .header("connection", "upgrade")
        .header("sec-websocket-accept", accept)
        .body(Full::new(Bytes::new()))
        .unwrap();

    Ok(response)
}

/// Handle WebSocket upgrade for /ws/v1/sandboxes/:id/pty.
///
/// Streams the sandbox's stdout/stderr to the WebSocket client using
/// the binary framing protocol: 0x00 = data, 0x01 = resize, 0x02 = close.
pub async fn handle_pty_upgrade(
    mut req: Request<hyper::body::Incoming>,
    sandbox_id: &str,
    state: Arc<GatewayState>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    use base64::Engine;
    use hyper_util::rt::TokioIo;
    use sha1::{Digest, Sha1};

    let upgrade_header = req
        .headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !upgrade_header.eq_ignore_ascii_case("websocket") {
        let resp = Response::builder()
            .status(400)
            .body(Full::new(Bytes::from("expected websocket upgrade")))
            .unwrap();
        return Ok(resp);
    }

    // Get the output subscription before upgrading.
    let output_rx = if let Some(ref backend) = state.sandbox_backend {
        backend.subscribe_output(sandbox_id).await
    } else {
        None
    };

    let key = req
        .headers()
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-5AB5DC11650A");
    let accept = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());

    let sandbox_id = sandbox_id.to_string();

    tokio::spawn(async move {
        let upgraded = match hyper::upgrade::on(&mut req).await {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!("pty ws upgrade failed: {e}");
                return;
            }
        };

        let io = TokioIo::new(upgraded);
        let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            io,
            tokio_tungstenite::tungstenite::protocol::Role::Server,
            None,
        )
        .await;

        let (mut ws_tx, mut ws_rx) = ws.split();

        if let Some(mut output_rx) = output_rx {
            tracing::info!("pty ws connected for sandbox {sandbox_id}");

            loop {
                tokio::select! {
                    data = output_rx.recv() => {
                        match data {
                            Ok(bytes) => {
                                // Frame type 0x00 = data.
                                let mut frame = Vec::with_capacity(1 + bytes.len());
                                frame.push(0x00);
                                frame.extend_from_slice(&bytes);
                                if ws_tx.send(Message::Binary(frame)).await.is_err() {
                                    break;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                tracing::warn!("pty ws lagged by {n} chunks");
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                // Process exited, send close frame.
                                let _ = ws_tx.send(Message::Text(
                                    "\r\n\r\n[Process exited]\r\n".to_string()
                                )).await;
                                break;
                            }
                        }
                    }
                    msg = ws_rx.next() => {
                        match msg {
                            Some(Ok(Message::Close(_))) | None => break,
                            Some(Ok(Message::Ping(data))) => {
                                let _ = ws_tx.send(Message::Pong(data)).await;
                            }
                            // TODO: Handle input frames (0x00=keystrokes) for interactive PTY.
                            _ => {}
                        }
                    }
                }
            }
        } else {
            // No output subscription — sandbox not found or no captured output.
            let _ = ws_tx.send(Message::Text(
                format!("\r\n  Sandbox {sandbox_id} not found or output not captured.\r\n")
            )).await;
        }

        tracing::debug!("pty ws disconnected for sandbox {sandbox_id}");
    });

    let response = Response::builder()
        .status(101)
        .header("upgrade", "websocket")
        .header("connection", "upgrade")
        .header("sec-websocket-accept", accept)
        .body(Full::new(Bytes::new()))
        .unwrap();

    Ok(response)
}
