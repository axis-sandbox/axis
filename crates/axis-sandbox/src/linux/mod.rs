// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Linux sandbox implementation using Landlock, seccomp-BPF, and network namespaces.

pub mod landlock;
pub mod netns;
pub mod seccomp;

use crate::sandbox::{SandboxConfig, SandboxError, SandboxImpl};
use std::process::Child;

/// Linux sandbox using native isolation primitives.
pub(crate) struct LinuxSandbox {
    config: SandboxConfig,
    child: Option<Child>,
    netns_name: Option<String>,
}

impl LinuxSandbox {
    pub fn new(config: &SandboxConfig) -> Result<Self, SandboxError> {
        std::fs::create_dir_all(&config.workspace_dir)?;

        Ok(Self {
            config: config.clone(),
            child: None,
            netns_name: None,
        })
    }
}

impl SandboxImpl for LinuxSandbox {
    fn start(&mut self) -> Result<u32, SandboxError> {
        use std::os::unix::process::CommandExt;
        use std::process::Command;

        let sandbox_id = self.config.id;
        let proxy_port = self.config.proxy_port;

        // ── Step 1: Create network namespace (parent side) ──
        // This creates the netns, veth pair, and iptables rules.
        // The child will enter this namespace via setns() in pre_exec.
        let netns_fd: Option<i32> = match self.config.policy.network.mode {
            axis_core::policy::NetworkMode::Proxy => {
                let ns_name = format!("{sandbox_id}");
                match netns::create_netns(&ns_name, proxy_port) {
                    Ok(name) => {
                        self.netns_name = Some(name.clone());
                        // Open the netns fd for the child to setns() into.
                        match netns::enter_netns(&name) {
                            Ok(fd) => Some(fd),
                            Err(e) => {
                                tracing::warn!("netns: cannot open fd for '{name}': {e}");
                                None
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("netns: creation failed: {e} (sandbox will run without network isolation)");
                        None
                    }
                }
            }
            _ => None,
        };

        // ── Step 2: Build child process with pre_exec isolation ──
        let policy = self.config.policy.clone();
        let workspace = self.config.workspace_dir.clone();

        let mut cmd = Command::new(&self.config.command);
        cmd.args(&self.config.args);

        if let Some(dir) = &self.config.working_dir {
            cmd.current_dir(dir);
        } else {
            cmd.current_dir(&self.config.workspace_dir);
        }

        // Capture output to workspace files (daemon mode) or inherit stdio (standalone).
        if self.config.capture_output {
            let stdout_file = std::fs::File::create(self.config.workspace_dir.join("stdout.log"))
                .map_err(|e| SandboxError::SpawnFailed(format!("stdout log: {e}")))?;
            let stderr_file = std::fs::File::create(self.config.workspace_dir.join("stderr.log"))
                .map_err(|e| SandboxError::SpawnFailed(format!("stderr log: {e}")))?;
            cmd.stdout(std::process::Stdio::from(stdout_file));
            cmd.stderr(std::process::Stdio::from(stderr_file));
        }
        // else: inherit parent's stdio (standalone/run mode)

        // Set environment.
        cmd.env_clear();
        for (k, v) in &self.config.env {
            cmd.env(k, v);
        }

        // Inject proxy env vars (only when proxy is active).
        if proxy_port > 0 {
            let proxy_host = if netns_fd.is_some() { "10.200.0.1" } else { "127.0.0.1" };
            let proxy_url = format!("http://{proxy_host}:{proxy_port}");
            cmd.env("HTTP_PROXY", &proxy_url);
            cmd.env("HTTPS_PROXY", &proxy_url);
            cmd.env("http_proxy", &proxy_url);
            cmd.env("https_proxy", &proxy_url);
            cmd.env("NO_PROXY", "localhost,127.0.0.1,::1");
            cmd.env("no_proxy", "localhost,127.0.0.1,::1");
        }

        // Safety: pre_exec runs after fork, before exec in the child process.
        unsafe {
            cmd.pre_exec(move || {
                // 1. Own process group.
                nix::unistd::setpgid(nix::unistd::Pid::from_raw(0), nix::unistd::Pid::from_raw(0))
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

                // 2. Enter network namespace (if created by parent).
                if let Some(fd) = netns_fd {
                    let ret = libc::setns(fd, libc::CLONE_NEWNET);
                    libc::close(fd);
                    if ret < 0 {
                        let err = std::io::Error::last_os_error();
                        tracing::warn!("setns(CLONE_NEWNET) failed: {err}");
                        // Continue without netns — best-effort.
                    } else {
                        tracing::info!("entered network namespace");
                    }
                }

                // 3. Prevent SUID escalation.
                nix::sys::prctl::set_no_new_privs()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

                // 4. Apply Landlock filesystem policy.
                if let Err(e) = landlock::apply_landlock(&policy.filesystem, &workspace) {
                    tracing::warn!("landlock not applied: {e}");
                }

                // 5. seccomp-BPF syscall filter (must be last — it restricts further syscalls).
                if let Err(e) = seccomp::apply_seccomp(&policy.process) {
                    tracing::warn!("seccomp not applied: {e}");
                }

                Ok(())
            });
        }

        let child = cmd
            .spawn()
            .map_err(|e| SandboxError::SpawnFailed(e.to_string()))?;

        let pid = child.id();
        self.child = Some(child);

        tracing::info!("sandbox {sandbox_id} started, pid={pid}");
        Ok(pid)
    }

    fn wait(&mut self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<i32, SandboxError>> + Send + '_>> {
        Box::pin(async {
            let child = self.child.as_mut().ok_or_else(|| {
                SandboxError::SpawnFailed("no child process".into())
            })?;

            let status = tokio::task::block_in_place(|| child.wait())?;
            Ok(status.code().unwrap_or(-1))
        })
    }

    fn destroy(&mut self) -> Result<(), SandboxError> {
        if let Some(ref mut child) = self.child {
            let pid = child.id() as i32;
            // Kill both the process and its group to catch any children.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::kill(-pid, libc::SIGKILL);
            }
            let _ = child.wait();
            // Reap any orphaned children in the process group.
            unsafe { libc::waitpid(-pid, std::ptr::null_mut(), libc::WNOHANG); }
        }

        if let Some(ref ns_name) = self.netns_name {
            if let Err(e) = netns::destroy_netns(ns_name) {
                tracing::warn!("failed to destroy netns '{ns_name}': {e}");
            }
        }

        tracing::info!("sandbox {} destroyed", self.config.id);
        Ok(())
    }
}
