// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! IPC server for axisd ↔ CLI communication.
//! Unix sockets on Linux/macOS, TCP on Windows.

use crate::sandbox_mgr::SandboxManager;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Socket path for the AXIS daemon.
/// Override with AXIS_SOCKET env var.
pub fn default_socket_path() -> PathBuf {
    if let Ok(path) = std::env::var("AXIS_SOCKET") {
        return PathBuf::from(path);
    }
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(xdg).join("axis").join("axisd.sock")
    } else {
        PathBuf::from("/tmp/axis-axisd.sock")
    }
}

/// IPC request from the CLI.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum IpcRequest {
    #[serde(rename = "create")]
    Create {
        policy_yaml: String,
        command: String,
        args: Vec<String>,
        env: Vec<(String, String)>,
    },
    #[serde(rename = "exec")]
    Exec {
        sandbox_id: String,
        command: String,
        args: Vec<String>,
    },
    #[serde(rename = "destroy")]
    Destroy { sandbox_id: String },
    #[serde(rename = "list")]
    List,
}

/// IPC response to the CLI.
#[derive(Debug, Serialize, Deserialize)]
pub struct IpcResponse {
    pub success: bool,
    pub data: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Start the IPC server (platform-specific transport).
pub async fn serve(socket_path: &PathBuf, mgr: &mut SandboxManager) -> Result<()> {
    #[cfg(unix)]
    {
        serve_unix(socket_path, mgr).await
    }

    #[cfg(windows)]
    {
        let _ = socket_path;
        serve_tcp(mgr).await
    }
}

/// Unix socket server (Linux/macOS).
#[cfg(unix)]
async fn serve_unix(socket_path: &PathBuf, mgr: &mut SandboxManager) -> Result<()> {
    use tokio::net::UnixListener;

    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path)?;
    tracing::info!("IPC server listening on {}", socket_path.display());

    loop {
        let (stream, _) = listener.accept().await?;
        let (reader, mut writer) = stream.into_split();
        let response = read_and_handle(reader, mgr).await?;
        let json = serde_json::to_string(&response)?;
        writer.write_all(json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
    }
}

/// TCP server (Windows).
#[cfg(windows)]
async fn serve_tcp(mgr: &mut SandboxManager) -> Result<()> {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:18516").await?;
    tracing::info!("IPC server listening on 127.0.0.1:18516");

    loop {
        let (stream, _) = listener.accept().await?;
        let (reader, mut writer) = stream.into_split();
        let response = read_and_handle(reader, mgr).await?;
        let json = serde_json::to_string(&response)?;
        writer.write_all(json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
    }
}

/// Read a request line and dispatch to handler.
async fn read_and_handle<R: tokio::io::AsyncRead + Unpin>(
    reader: R,
    mgr: &mut SandboxManager,
) -> Result<IpcResponse> {
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        return Ok(IpcResponse {
            success: false,
            data: serde_json::Value::Null,
            error: Some("empty request".into()),
        });
    }

    Ok(match serde_json::from_str::<IpcRequest>(&line) {
        Ok(req) => handle_request(mgr, req).await,
        Err(e) => IpcResponse {
            success: false,
            data: serde_json::Value::Null,
            error: Some(format!("invalid request: {e}")),
        },
    })
}

async fn handle_request(mgr: &mut SandboxManager, req: IpcRequest) -> IpcResponse {
    match req {
        IpcRequest::Create {
            policy_yaml,
            command,
            args,
            env,
        } => match axis_core::policy::Policy::from_yaml(&policy_yaml) {
            Ok(policy) => match mgr.create(policy, command, args, env).await {
                Ok(id) => IpcResponse {
                    success: true,
                    data: serde_json::json!({ "sandbox_id": id.to_string() }),
                    error: None,
                },
                Err(e) => IpcResponse {
                    success: false,
                    data: serde_json::Value::Null,
                    error: Some(e),
                },
            },
            Err(e) => IpcResponse {
                success: false,
                data: serde_json::Value::Null,
                error: Some(format!("invalid policy: {e}")),
            },
        },

        IpcRequest::Exec {
            sandbox_id,
            command,
            args,
        } => match uuid::Uuid::parse_str(&sandbox_id) {
            Ok(uuid) => {
                let id = axis_core::types::SandboxId(uuid);
                match mgr.exec_in_sandbox(&id, command, args) {
                    Ok(exit_code) => IpcResponse {
                        success: true,
                        data: serde_json::json!({ "exit_code": exit_code }),
                        error: None,
                    },
                    Err(e) => IpcResponse {
                        success: false,
                        data: serde_json::Value::Null,
                        error: Some(e),
                    },
                }
            }
            Err(e) => IpcResponse {
                success: false,
                data: serde_json::Value::Null,
                error: Some(format!("invalid sandbox_id: {e}")),
            },
        },

        IpcRequest::Destroy { sandbox_id } => match uuid::Uuid::parse_str(&sandbox_id) {
            Ok(uuid) => {
                let id = axis_core::types::SandboxId(uuid);
                match mgr.destroy(&id) {
                    Ok(()) => IpcResponse {
                        success: true,
                        data: serde_json::json!({ "destroyed": sandbox_id }),
                        error: None,
                    },
                    Err(e) => IpcResponse {
                        success: false,
                        data: serde_json::Value::Null,
                        error: Some(e),
                    },
                }
            }
            Err(e) => IpcResponse {
                success: false,
                data: serde_json::Value::Null,
                error: Some(format!("invalid sandbox_id: {e}")),
            },
        },

        IpcRequest::List => {
            let sandboxes = mgr.list();
            IpcResponse {
                success: true,
                data: serde_json::to_value(sandboxes).unwrap_or_default(),
                error: None,
            }
        }
    }
}
