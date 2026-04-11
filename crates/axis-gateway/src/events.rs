// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! WebSocket handlers for event streaming and PTY terminal access.

use crate::GatewayState;
use futures_util::{SinkExt, StreamExt};
use http_body_util::Full;
use hyper::{body::Bytes, Request, Response};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio_tungstenite::tungstenite::{
    handshake::derive_accept_key,
    protocol::Role,
    Message,
};

fn ws_upgrade_response(req: &Request<hyper::body::Incoming>) -> Option<(Response<Full<Bytes>>, String)> {
    let key = req.headers().get("sec-websocket-key")?.to_str().ok()?.to_string();
    let accept = derive_accept_key(key.as_bytes());

    let resp = Response::builder()
        .status(101)
        .header("upgrade", "websocket")
        .header("connection", "upgrade")
        .header("sec-websocket-accept", &accept)
        .body(Full::new(Bytes::new()))
        .ok()?;

    Some((resp, key))
}

/// WebSocket upgrade for /ws/v1/events — streams audit events.
pub async fn handle_ws_upgrade(
    mut req: Request<hyper::body::Incoming>,
    state: Arc<GatewayState>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let (response, _key) = match ws_upgrade_response(&req) {
        Some(pair) => pair,
        None => {
            return Ok(Response::builder()
                .status(400)
                .body(Full::new(Bytes::from("missing sec-websocket-key")))
                .unwrap());
        }
    };

    tokio::spawn(async move {
        let upgraded = match hyper::upgrade::on(&mut req).await {
            Ok(u) => u,
            Err(e) => { tracing::warn!("ws upgrade failed: {e}"); return; }
        };

        let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            TokioIo::new(upgraded), Role::Server, None,
        ).await;
        let (mut ws_tx, mut ws_rx) = ws.split();
        let mut event_rx = state.subscribe_events();

        loop {
            tokio::select! {
                event = event_rx.recv() => {
                    match event {
                        Ok(e) => {
                            let json = serde_json::to_string(&e).unwrap_or_default();
                            if ws_tx.send(Message::Text(json)).await.is_err() { break; }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!("ws events lagged {n}");
                        }
                        Err(_) => break,
                    }
                }
                msg = ws_rx.next() => {
                    match msg {
                        Some(Ok(Message::Close(_))) | None => break,
                        Some(Ok(Message::Ping(d))) => { let _ = ws_tx.send(Message::Pong(d)).await; }
                        _ => {}
                    }
                }
            }
        }
        tracing::debug!("ws events client disconnected");
    });

    Ok(response)
}

/// WebSocket upgrade for /ws/v1/sandboxes/:id/pty — streams sandbox output.
pub async fn handle_pty_upgrade(
    mut req: Request<hyper::body::Incoming>,
    sandbox_id: &str,
    state: Arc<GatewayState>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let (response, _key) = match ws_upgrade_response(&req) {
        Some(pair) => pair,
        None => {
            return Ok(Response::builder()
                .status(400)
                .body(Full::new(Bytes::from("missing sec-websocket-key")))
                .unwrap());
        }
    };

    // Get buffered output + live subscription before upgrading.
    let output_sub = if let Some(ref backend) = state.sandbox_backend {
        backend.subscribe_output(sandbox_id).await
    } else {
        None
    };

    let sandbox_id = sandbox_id.to_string();
    let state2 = state.clone();

    tokio::spawn(async move {
        let upgraded = match hyper::upgrade::on(&mut req).await {
            Ok(u) => u,
            Err(e) => { tracing::warn!("pty ws upgrade failed: {e}"); return; }
        };

        let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            TokioIo::new(upgraded), Role::Server, None,
        ).await;
        let (mut ws_tx, mut ws_rx) = ws.split();

        if let Some((buffer, mut output_rx)) = output_sub {
            tracing::info!("pty ws connected for sandbox {sandbox_id}, replaying {} buffered chunks", buffer.len());

            // Replay buffered output first.
            for chunk in &buffer {
                let mut frame = Vec::with_capacity(1 + chunk.len());
                frame.push(0x00);
                frame.extend_from_slice(chunk);
                if ws_tx.send(Message::Binary(frame)).await.is_err() {
                    return;
                }
            }

            // Then stream live.
            loop {
                tokio::select! {
                    data = output_rx.recv() => {
                        match data {
                            Ok(bytes) => {
                                let mut frame = Vec::with_capacity(1 + bytes.len());
                                frame.push(0x00);
                                frame.extend_from_slice(&bytes);
                                if ws_tx.send(Message::Binary(frame)).await.is_err() { break; }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                tracing::warn!("pty ws lagged {n}");
                            }
                            Err(_) => {
                                let _ = ws_tx.send(Message::Text(
                                    "\r\n[Process exited]\r\n".into()
                                )).await;
                                break;
                            }
                        }
                    }
                    msg = ws_rx.next() => {
                        match msg {
                            Some(Ok(Message::Close(_))) | None => break,
                            Some(Ok(Message::Ping(d))) => { let _ = ws_tx.send(Message::Pong(d)).await; }
                            Some(Ok(Message::Binary(data))) if !data.is_empty() && data[0] == 0x00 => {
                                // Input frame: forward to sandbox stdin.
                                if let Some(ref backend) = state2.sandbox_backend {
                                    let _ = backend.send_input(&sandbox_id, data[1..].to_vec()).await;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        } else {
            let _ = ws_tx.send(Message::Text(
                format!("\r\nSandbox {sandbox_id} not found or output not captured.\r\n")
            )).await;
        }
        tracing::debug!("pty ws disconnected for {sandbox_id}");
    });

    Ok(response)
}
