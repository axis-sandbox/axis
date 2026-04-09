// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Windows sandbox implementation using Restricted Token + Job Object + AppContainer.
//!
//! All APIs used are available on Windows 11 Home — no admin privileges,
//! no Hyper-V, no Windows Pro features required.

pub mod acl;
pub mod appcontainer;
pub mod etw;
pub mod job_object;
pub mod restricted;

use crate::sandbox::{SandboxConfig, SandboxError, SandboxImpl};
use std::process::Child;

/// Windows sandbox using native Win32 isolation primitives.
pub(crate) struct WindowsSandbox {
    config: SandboxConfig,
    child: Option<Child>,
    job_handle: Option<job_object::JobHandle>,
    appcontainer_sid: Option<String>,
}

impl WindowsSandbox {
    pub fn new(config: &SandboxConfig) -> Result<Self, SandboxError> {
        std::fs::create_dir_all(&config.workspace_dir)?;

        Ok(Self {
            config: config.clone(),
            child: None,
            job_handle: None,
            appcontainer_sid: None,
        })
    }
}

impl SandboxImpl for WindowsSandbox {
    fn start(&mut self) -> Result<u32, SandboxError> {
        let sandbox_id = self.config.id;
        let policy = &self.config.policy;

        // 1. Create Job Object with resource limits.
        let job = job_object::create_job_object(
            &format!("axis-sandbox-{sandbox_id}"),
            policy.process.max_processes,
            policy.process.max_memory_mb,
            policy.process.cpu_rate_percent,
        )
        .map_err(|e| SandboxError::IsolationFailed(format!("Job Object: {e}")))?;

        // 2. Create AppContainer profile for network isolation.
        let ac_name = format!("axis-sandbox-{sandbox_id}");
        let ac_sid = appcontainer::create_appcontainer_profile(&ac_name)
            .map_err(|e| SandboxError::IsolationFailed(format!("AppContainer: {e}")))?;
        self.appcontainer_sid = Some(ac_sid);

        // 3. Set up workspace ACLs.
        acl::setup_workspace_acls(&self.config.workspace_dir, &ac_name)
            .map_err(|e| SandboxError::IsolationFailed(format!("ACL: {e}")))?;

        // 4. Create the child process with restricted token.
        let proxy_url = format!("http://127.0.0.1:{}", self.config.proxy_port);

        let mut cmd = std::process::Command::new(&self.config.command);
        cmd.args(&self.config.args);
        cmd.current_dir(
            self.config
                .working_dir
                .as_ref()
                .unwrap_or(&self.config.workspace_dir),
        );

        // Environment.
        cmd.env_clear();
        for (k, v) in &self.config.env {
            cmd.env(k, v);
        }
        cmd.env("HTTP_PROXY", &proxy_url);
        cmd.env("HTTPS_PROXY", &proxy_url);

        // NOTE: Full Windows implementation would use CreateProcessAsUser
        // with a restricted token and AppContainer security capabilities.
        // For the initial implementation, we use std::process::Command
        // and rely on the Job Object for resource limits. The full
        // restricted token + AppContainer launch requires Win32 FFI
        // which will be completed when testing on the Windows VM.

        let child = cmd
            .spawn()
            .map_err(|e| SandboxError::SpawnFailed(e.to_string()))?;

        let pid = child.id();

        // Assign to Job Object.
        job_object::assign_process_to_job(&job, pid)
            .map_err(|e| SandboxError::IsolationFailed(format!("assign to job: {e}")))?;

        self.child = Some(child);
        self.job_handle = Some(job);

        tracing::info!("sandbox {sandbox_id} started on Windows, pid={pid}");
        Ok(pid)
    }

    fn wait(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<i32, SandboxError>> + Send + '_>,
    > {
        Box::pin(async {
            let child = self
                .child
                .as_mut()
                .ok_or_else(|| SandboxError::SpawnFailed("no child process".into()))?;

            let status = tokio::task::block_in_place(|| child.wait())?;
            Ok(status.code().unwrap_or(-1))
        })
    }

    fn destroy(&mut self) -> Result<(), SandboxError> {
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }

        // Job Object cleanup — KILL_ON_JOB_CLOSE handles this automatically
        // when the handle is dropped.
        self.job_handle = None;

        // Clean up AppContainer profile.
        if let Some(ref ac_name) = self.appcontainer_sid {
            let name = format!("axis-sandbox-{}", self.config.id);
            if let Err(e) = appcontainer::delete_appcontainer_profile(&name) {
                tracing::warn!("failed to delete AppContainer profile: {e}");
            }
        }

        tracing::info!("sandbox {} destroyed", self.config.id);
        Ok(())
    }
}
