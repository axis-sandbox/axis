// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! HIP worker lifecycle management.
//!
//! Each sandbox with GPU access gets its own `hip-worker` process.
//! The worker holds the real HIP context and serves API requests
//! from the sandbox's `libamdhip64` client library.

use crate::api_filter::{ApiFilter, GpuPolicy};
use crate::transport::WorkerEndpoint;
use crate::vram_quota::VramTracker;
use axis_core::types::SandboxId;
use std::collections::HashMap;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WorkerError {
    #[error("worker failed to start: {0}")]
    StartFailed(String),

    #[error("worker not found for sandbox {0}")]
    NotFound(SandboxId),

    #[error("worker health check failed: {0}")]
    Unhealthy(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// State for a running HIP worker.
struct ManagedWorker {
    sandbox_id: SandboxId,
    endpoint: WorkerEndpoint,
    pid: Option<u32>,
    api_filter: ApiFilter,
    gpu_device: u32,
}

/// Manages HIP workers across all sandboxes.
pub struct WorkerManager {
    workers: HashMap<SandboxId, ManagedWorker>,
    vram_tracker: VramTracker,
    worker_binary: PathBuf,
}

impl WorkerManager {
    /// Create a new worker manager.
    ///
    /// `worker_binary` is the path to the `hip-worker` executable.
    pub fn new(worker_binary: PathBuf) -> Self {
        Self {
            workers: HashMap::new(),
            vram_tracker: VramTracker::new(),
            worker_binary,
        }
    }

    /// Spawn a HIP worker for a sandbox.
    pub async fn spawn_worker(
        &mut self,
        sandbox_id: SandboxId,
        policy: &GpuPolicy,
        workspace: &std::path::Path,
    ) -> Result<WorkerEndpoint, WorkerError> {
        // Determine transport and endpoint.
        // Currently hip-worker only supports TCP (-p PORT).
        // UDS support will be added upstream. For now, always use TCP.
        let port = 18520 + (self.workers.len() as u16);
        let endpoint = WorkerEndpoint::tcp_loopback(port);

        // Create API filter from policy.
        let api_filter = ApiFilter::from_policy(policy);

        // Register VRAM quota.
        if let Some(limit_mb) = policy.vram_limit_mb {
            self.vram_tracker.register(sandbox_id, limit_mb);
        }

        // Spawn the worker process.
        let mut cmd = std::process::Command::new(&self.worker_binary);
        cmd.arg("-d").arg(policy.device.to_string());

        match &endpoint {
            WorkerEndpoint::Tcp(addr) => {
                cmd.arg("-p").arg(addr.port().to_string());
            }
            WorkerEndpoint::Uds(path) => {
                cmd.arg("-s").arg(path);
            }
        }

        if policy.compute_timeout_sec.is_some() {
            cmd.arg("-v"); // verbose for debugging
        }

        let child = cmd
            .spawn()
            .map_err(|e| WorkerError::StartFailed(format!(
                "cannot spawn {}: {e}",
                self.worker_binary.display(),
            )))?;

        let pid = child.id();
        tracing::info!(
            "gpu: spawned hip-worker for sandbox {sandbox_id} on {endpoint} (pid={pid}, device={})",
            policy.device,
        );

        self.workers.insert(sandbox_id, ManagedWorker {
            sandbox_id,
            endpoint: endpoint.clone(),
            pid: Some(pid),
            api_filter,
            gpu_device: policy.device,
        });

        Ok(endpoint)
    }

    /// Stop a worker for a sandbox.
    pub fn stop_worker(&mut self, sandbox_id: &SandboxId) -> Result<(), WorkerError> {
        let worker = self
            .workers
            .remove(sandbox_id)
            .ok_or(WorkerError::NotFound(*sandbox_id))?;

        if let Some(pid) = worker.pid {
            // Send SIGTERM on Unix, TerminateProcess on Windows.
            #[cfg(unix)]
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
            #[cfg(windows)]
            {
                tracing::info!("gpu: would terminate worker pid={pid}");
            }
        }

        self.vram_tracker.unregister(sandbox_id);
        tracing::info!("gpu: stopped worker for sandbox {sandbox_id}");
        Ok(())
    }

    /// Check if an API call is allowed for a sandbox.
    pub fn check_api(
        &self,
        sandbox_id: &SandboxId,
        category: crate::protocol::ApiCategory,
    ) -> bool {
        self.workers
            .get(sandbox_id)
            .map(|w| w.api_filter.is_allowed(category))
            .unwrap_or(false)
    }

    /// Get the VRAM tracker for quota checks.
    pub fn vram_tracker(&self) -> &VramTracker {
        &self.vram_tracker
    }

    /// Get mutable VRAM tracker.
    pub fn vram_tracker_mut(&mut self) -> &mut VramTracker {
        &mut self.vram_tracker
    }

    /// Get the endpoint for a sandbox's worker.
    pub fn endpoint(&self, sandbox_id: &SandboxId) -> Option<&WorkerEndpoint> {
        self.workers.get(sandbox_id).map(|w| &w.endpoint)
    }

    /// List all active workers.
    pub fn list(&self) -> Vec<WorkerInfo> {
        self.workers
            .values()
            .map(|w| {
                let (used, limit) = self
                    .vram_tracker
                    .usage(&w.sandbox_id)
                    .unwrap_or((0, 0));
                WorkerInfo {
                    sandbox_id: w.sandbox_id,
                    endpoint: w.endpoint.to_string(),
                    pid: w.pid,
                    device: w.gpu_device,
                    vram_used_mb: used / (1024 * 1024),
                    vram_limit_mb: limit / (1024 * 1024),
                }
            })
            .collect()
    }
}

/// Info about a running HIP worker.
#[derive(Debug, serde::Serialize)]
pub struct WorkerInfo {
    pub sandbox_id: SandboxId,
    pub endpoint: String,
    pub pid: Option<u32>,
    pub device: u32,
    pub vram_used_mb: u64,
    pub vram_limit_mb: u64,
}
