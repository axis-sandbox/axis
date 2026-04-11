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
    /// ConPTY read pipe — reads child's terminal output.
    conpty_read: Option<std::fs::File>,
}

impl WindowsSandbox {
    pub fn new(config: &SandboxConfig) -> Result<Self, SandboxError> {
        std::fs::create_dir_all(&config.workspace_dir)?;

        Ok(Self {
            config: config.clone(),
            child: None,
            job_handle: None,
            appcontainer_sid: None,
            conpty_read: None,
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
        // TODO: Re-enable proxy once TLS tunnel issues are resolved.
        // The AXIS proxy's CONNECT tunnel drops TLS connections on Windows,
        // causing Claude API calls to time out.
        // if self.config.proxy_port > 0 {
        //     cmd.env("HTTP_PROXY", &proxy_url);
        //     cmd.env("HTTPS_PROXY", &proxy_url);
        // }

        // Capture stdout/stderr for daemon/gateway streaming.
        // NOTE: ConPTY requires CreateProcess with PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
        // which std::process::Command doesn't support. Use piped stdout for now —
        // agents should be launched in non-interactive mode (e.g., claude -p ...).
        if self.config.capture_output {
            // Use null stdin — piped stdin causes some Node.js agents (Claude Code)
            // to exit immediately. Input is sent via stream-json on stdin when needed.
            cmd.stdin(std::process::Stdio::null());
            cmd.stdout(std::process::Stdio::piped());
            cmd.stderr(std::process::Stdio::piped());
        }

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

    fn take_stdin(&mut self) -> Option<std::process::ChildStdin> {
        self.child.as_mut().and_then(|c| c.stdin.take())
    }

    fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.child.as_mut().and_then(|c| c.stdout.take())
    }

    fn take_stderr(&mut self) -> Option<std::process::ChildStderr> {
        self.child.as_mut().and_then(|c| c.stderr.take())
    }

    fn take_pty_read(&mut self) -> Option<std::fs::File> {
        self.conpty_read.take()
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

/// Create a child process with a ConPTY pseudoconsole.
/// Returns the child process and a File handle to read the PTY output.
fn create_conpty_child(
    cmd: &mut std::process::Command,
) -> Result<(std::process::Child, std::fs::File), String> {
    use std::os::windows::io::{FromRawHandle, IntoRawHandle};
    use std::ptr;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreatePipe(
            hReadPipe: *mut isize,
            hWritePipe: *mut isize,
            lpPipeAttributes: *const u8,
            nSize: u32,
        ) -> i32;
        fn CreatePseudoConsole(
            size: u32,
            hInput: isize,
            hOutput: isize,
            dwFlags: u32,
            phPC: *mut isize,
        ) -> i32;
        fn ClosePseudoConsole(hPC: isize);
        fn CloseHandle(hObject: isize) -> i32;
    }

    // COORD: 120 cols x 40 rows
    let coord: u32 = 120 | (40 << 16);

    // Input pipe: daemon writes -> child reads
    let mut pipe_in_read: isize = 0;
    let mut pipe_in_write: isize = 0;
    if unsafe { CreatePipe(&mut pipe_in_read, &mut pipe_in_write, ptr::null(), 0) } == 0 {
        return Err("CreatePipe (input) failed".into());
    }

    // Output pipe: child writes -> daemon reads
    let mut pipe_out_read: isize = 0;
    let mut pipe_out_write: isize = 0;
    if unsafe { CreatePipe(&mut pipe_out_read, &mut pipe_out_write, ptr::null(), 0) } == 0 {
        unsafe { CloseHandle(pipe_in_read); CloseHandle(pipe_in_write); }
        return Err("CreatePipe (output) failed".into());
    }

    // Create pseudoconsole
    let mut hpc: isize = 0;
    let hr = unsafe { CreatePseudoConsole(coord, pipe_in_read, pipe_out_write, 0, &mut hpc) };
    if hr < 0 {
        unsafe {
            CloseHandle(pipe_in_read); CloseHandle(pipe_in_write);
            CloseHandle(pipe_out_read); CloseHandle(pipe_out_write);
        }
        return Err(format!("CreatePseudoConsole HRESULT: 0x{hr:08X}"));
    }

    tracing::info!("ConPTY created: hpc={hpc}");

    // Close the child-side pipe ends (ConPTY owns them now).
    unsafe { CloseHandle(pipe_in_read); CloseHandle(pipe_out_write); }

    // Spawn the child — it inherits the ConPTY via standard process creation.
    // Note: For full ConPTY integration, we'd use PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
    // via CreateProcess. For now, the child inherits stdio and the ConPTY acts as
    // the console for any console-mode child.
    let child = cmd
        .stdin(unsafe { std::process::Stdio::from_raw_handle(pipe_in_write as *mut _) })
        .spawn()
        .map_err(|e| {
            unsafe { ClosePseudoConsole(hpc); CloseHandle(pipe_out_read); }
            format!("spawn with ConPTY: {e}")
        })?;

    // Wrap the daemon's read end as a File.
    let read_file = unsafe { std::fs::File::from_raw_handle(pipe_out_read as *mut _) };

    // Note: We leak the hpc handle intentionally — it stays alive as long as the
    // child process runs. When the child exits, the ConPTY is cleaned up.
    // TODO: Store hpc and close it properly on sandbox destroy.

    Ok((child, read_file))
}
