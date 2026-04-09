// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox trait and configuration.

use axis_core::policy::Policy;
use axis_core::types::{SandboxId, SandboxStatus};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("sandbox creation failed: {0}")]
    CreationFailed(String),

    #[error("sandbox not found: {0}")]
    NotFound(SandboxId),

    #[error("isolation setup failed: {0}")]
    IsolationFailed(String),

    #[error("process spawn failed: {0}")]
    SpawnFailed(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("platform not supported: {0}")]
    Unsupported(String),
}

/// Configuration for creating a new sandbox.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub id: SandboxId,
    pub policy: Policy,
    pub command: String,
    pub args: Vec<String>,
    pub working_dir: Option<PathBuf>,
    pub workspace_dir: PathBuf,
    pub env: Vec<(String, String)>,
    pub proxy_port: u16,
    /// Capture stdout/stderr to files in workspace (for daemon mode).
    /// When false, child inherits parent's stdio (for standalone/run mode).
    pub capture_output: bool,
    /// Maximum wall-clock time before auto-destroy (seconds). None = no timeout.
    pub timeout_sec: Option<u64>,
}

/// Platform-independent sandbox handle.
///
/// Each platform (Linux, Windows) provides its own implementation.
pub struct Sandbox {
    pub id: SandboxId,
    pub status: SandboxStatus,
    pub pid: Option<u32>,
    pub workspace_dir: PathBuf,
    inner: Box<dyn SandboxImpl>,
    /// Symlinks created for agent state containment (cleaned up on destroy).
    agent_symlinks: Vec<(PathBuf, PathBuf)>,
}

impl Sandbox {
    /// Create a new sandbox with platform-specific isolation.
    pub fn create(config: SandboxConfig) -> Result<Self, SandboxError> {
        // Prepare agent workspace: create ~/.axis/agents/<name>/ and
        // symlink agent-expected directories (e.g., ~/.claude) to it.
        let agent_symlinks = crate::workspace::prepare_agent_workspace(
            &config.policy.name,
            &config.policy.filesystem.read_write,
        ).unwrap_or_else(|e| {
            tracing::warn!("workspace prep: {e}");
            Vec::new()
        });

        let inner = create_platform_sandbox(&config)?;
        Ok(Self {
            id: config.id,
            status: SandboxStatus::Creating,
            pid: None,
            workspace_dir: config.workspace_dir,
            inner,
            agent_symlinks,
        })
    }

    /// Start the sandboxed process.
    pub fn start(&mut self) -> Result<(), SandboxError> {
        let pid = self.inner.start()?;
        self.pid = Some(pid);
        self.status = SandboxStatus::Running;
        Ok(())
    }

    /// Wait for the sandboxed process to exit. Returns the exit code.
    pub async fn wait(&mut self) -> Result<i32, SandboxError> {
        let code = self.inner.wait().await?;
        self.status = SandboxStatus::Stopped;
        Ok(code)
    }

    /// Terminate the sandboxed process and clean up resources.
    pub fn destroy(&mut self) -> Result<(), SandboxError> {
        self.inner.destroy()?;
        // Restore original directories by removing symlinks.
        crate::workspace::cleanup_agent_symlinks(&self.agent_symlinks);
        self.status = SandboxStatus::Stopped;
        Ok(())
    }
}

/// Platform-specific sandbox implementation trait.
pub(crate) trait SandboxImpl: Send {
    /// Start the isolated process. Returns the PID.
    fn start(&mut self) -> Result<u32, SandboxError>;

    /// Wait for the process to exit.
    fn wait(&mut self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<i32, SandboxError>> + Send + '_>>;

    /// Kill the process and clean up isolation resources.
    fn destroy(&mut self) -> Result<(), SandboxError>;
}

/// Create the platform-appropriate sandbox implementation.
fn create_platform_sandbox(config: &SandboxConfig) -> Result<Box<dyn SandboxImpl>, SandboxError> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(crate::linux::LinuxSandbox::new(config)?))
    }

    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(crate::macos::MacosSandbox::new(config)?))
    }

    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(crate::windows::WindowsSandbox::new(config)?))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = config;
        Err(SandboxError::Unsupported(format!(
            "platform '{}' is not yet supported",
            std::env::consts::OS
        )))
    }
}
