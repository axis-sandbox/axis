// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Transport abstraction for HIP Remote — UDS, TCP, or named pipe.

use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Transport endpoint for a HIP worker.
#[derive(Debug, Clone)]
pub enum WorkerEndpoint {
    /// Unix domain socket (Linux, preferred for same-host).
    Uds(PathBuf),
    /// TCP loopback (Windows, or cross-host).
    Tcp(std::net::SocketAddr),
}

impl WorkerEndpoint {
    /// Create a UDS endpoint in the sandbox workspace directory.
    pub fn uds_in_workspace(workspace: &std::path::Path, sandbox_id: &str) -> Self {
        Self::Uds(workspace.join(format!("hip-worker-{sandbox_id}.sock")))
    }

    /// Create a TCP loopback endpoint on a given port.
    pub fn tcp_loopback(port: u16) -> Self {
        Self::Tcp(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
    }

    /// Get the connection string for environment variables.
    pub fn to_env_vars(&self) -> Vec<(String, String)> {
        match self {
            Self::Uds(path) => vec![
                ("TF_WORKER_HOST".into(), "localhost".into()),
                ("TF_WORKER_SOCKET".into(), path.to_string_lossy().into()),
            ],
            Self::Tcp(addr) => vec![
                ("TF_WORKER_HOST".into(), addr.ip().to_string()),
                ("TF_WORKER_PORT".into(), addr.port().to_string()),
            ],
        }
    }
}

impl std::fmt::Display for WorkerEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Uds(path) => write!(f, "uds:{}", path.display()),
            Self::Tcp(addr) => write!(f, "tcp:{addr}"),
        }
    }
}
