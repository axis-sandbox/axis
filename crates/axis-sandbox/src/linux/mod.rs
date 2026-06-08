// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Linux sandbox implementation using Landlock, seccomp-BPF, and network namespaces.

pub mod landlock;
pub mod netns;
pub mod seccomp;
pub mod strategy;

use crate::sandbox::{SandboxConfig, SandboxError, SandboxImpl};
use std::io;
use std::process::Child;

const CLOSED_FD: i32 = -1;

#[derive(Debug, Clone)]
struct ResolvedIdentity {
    uid: u32,
    gid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildSetupErrorKind {
    SetProcessGroup = 1,
    EnterNetworkNamespace = 2,
    NoNewPrivs = 3,
    Landlock = 4,
    SetGroups = 5,
    SetGid = 6,
    SetUid = 7,
    CloseFileDescriptors = 8,
    Seccomp = 9,
}

impl ChildSetupErrorKind {
    fn label(self) -> &'static str {
        match self {
            Self::SetProcessGroup => "set process group",
            Self::EnterNetworkNamespace => "enter network namespace",
            Self::NoNewPrivs => "set no_new_privs",
            Self::Landlock => "apply Landlock",
            Self::SetGroups => "clear supplementary groups",
            Self::SetGid => "drop group id",
            Self::SetUid => "drop user id",
            Self::CloseFileDescriptors => "close inherited file descriptors",
            Self::Seccomp => "apply seccomp",
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::SetProcessGroup),
            2 => Some(Self::EnterNetworkNamespace),
            3 => Some(Self::NoNewPrivs),
            4 => Some(Self::Landlock),
            5 => Some(Self::SetGroups),
            6 => Some(Self::SetGid),
            7 => Some(Self::SetUid),
            8 => Some(Self::CloseFileDescriptors),
            9 => Some(Self::Seccomp),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct ChildSetupErrorPipe {
    read_fd: i32,
    write_fd: i32,
}

impl ChildSetupErrorPipe {
    fn new() -> Result<Self, io::Error> {
        let mut fds = [0; 2];
        let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self {
                read_fd: fds[0],
                write_fd: fds[1],
            })
        }
    }

    fn close_write(&mut self) {
        if self.write_fd != CLOSED_FD {
            unsafe {
                libc::close(self.write_fd);
            }
            self.write_fd = CLOSED_FD;
        }
    }

    fn read_error_kind(&mut self) -> Option<ChildSetupErrorKind> {
        self.close_write();
        if self.read_fd == CLOSED_FD {
            return None;
        }

        let mut byte = 0u8;
        let ret = unsafe { libc::read(self.read_fd, &mut byte as *mut u8 as *mut libc::c_void, 1) };
        if ret == 1 {
            ChildSetupErrorKind::from_byte(byte)
        } else {
            None
        }
    }
}

impl Drop for ChildSetupErrorPipe {
    fn drop(&mut self) {
        if self.read_fd != CLOSED_FD {
            unsafe {
                libc::close(self.read_fd);
            }
            self.read_fd = CLOSED_FD;
        }
        self.close_write();
    }
}

/// Linux sandbox using native isolation primitives.
pub(crate) struct LinuxSandbox {
    config: SandboxConfig,
    plan: strategy::LinuxIsolationPlan,
    child: Option<Child>,
    exit_code: Option<i32>,
    netns_name: Option<String>,
    tmpdir_active: bool,
}

impl LinuxSandbox {
    pub fn new(config: &SandboxConfig) -> Result<Self, SandboxError> {
        std::fs::create_dir_all(&config.workspace_dir)?;
        let plan = strategy::build_isolation_plan(config)
            .map_err(|e| SandboxError::IsolationFailed(e.to_string()))?;

        Ok(Self {
            config: config.clone(),
            plan,
            child: None,
            exit_code: None,
            netns_name: None,
            tmpdir_active: false,
        })
    }

    fn cleanup_netns(&mut self) {
        self.cleanup_netns_with(netns::destroy_netns);
    }

    fn cleanup_netns_with<F>(&mut self, destroy: F)
    where
        F: FnOnce(&str) -> Result<(), String>,
    {
        if let Some(ns_name) = self.netns_name.take() {
            if let Err(e) = destroy(&ns_name) {
                tracing::warn!("failed to destroy netns '{ns_name}': {e}");
            }
        }
    }

    fn cleanup_parent_resources_after_setup_failure(
        &mut self,
        netns_fd: Option<i32>,
    ) -> Option<String> {
        self.cleanup_parent_resources_after_setup_failure_with(netns_fd, netns::destroy_netns)
    }

    fn cleanup_parent_resources_after_setup_failure_with<F>(
        &mut self,
        netns_fd: Option<i32>,
        destroy: F,
    ) -> Option<String>
    where
        F: FnOnce(&str) -> Result<(), String>,
    {
        close_fd(netns_fd);
        self.cleanup_netns_with(destroy);
        self.cleanup_tmpdir_for_setup_failure()
    }

    fn cleanup_tmpdir_after_stop(&mut self) {
        if let Err(e) = self.cleanup_tmpdir() {
            tracing::warn!("sandbox {}: tmpdir cleanup failed: {e}", self.config.id);
        }
    }

    fn cleanup_tmpdir_for_setup_failure(&mut self) -> Option<String> {
        self.cleanup_tmpdir().err()
    }

    fn cleanup_tmpdir(&mut self) -> Result<(), String> {
        if !self.tmpdir_active {
            return Ok(());
        }
        landlock::cleanup_tmpdir(&self.config.workspace_dir)?;
        self.tmpdir_active = false;
        Ok(())
    }

    fn resolve_identity(&self) -> Result<Option<ResolvedIdentity>, SandboxError> {
        match &self.plan.identity {
            strategy::IdentityStrategy::CurrentUser => Ok(None),
            strategy::IdentityStrategy::RunAsUser { username } => {
                let user = nix::unistd::User::from_name(username)
                    .map_err(|e| {
                        SandboxError::IsolationFailed(format!(
                            "cannot resolve run_as_user '{username}': {e}"
                        ))
                    })?
                    .ok_or_else(|| {
                        SandboxError::IsolationFailed(format!(
                            "run_as_user '{username}' does not exist"
                        ))
                    })?;
                if user.uid.as_raw() == 0 || user.gid.as_raw() == 0 {
                    return Err(SandboxError::IsolationFailed(format!(
                        "run_as_user '{username}' must not resolve to UID or GID 0"
                    )));
                }
                Ok(Some(ResolvedIdentity {
                    uid: user.uid.as_raw(),
                    gid: user.gid.as_raw(),
                }))
            }
        }
    }
}

fn close_fd(fd: Option<i32>) {
    if let Some(fd) = fd {
        unsafe {
            libc::close(fd);
        }
    }
}

fn child_setup_error(write_fd: i32, kind: ChildSetupErrorKind, errno: i32) -> io::Error {
    let byte = kind as u8;
    unsafe {
        libc::write(write_fd, &byte as *const u8 as *const libc::c_void, 1);
    }
    io::Error::from_raw_os_error(errno)
}

fn spawn_error(e: io::Error, child_error_pipe: &mut ChildSetupErrorPipe) -> SandboxError {
    if let Some(kind) = child_error_pipe.read_error_kind() {
        SandboxError::IsolationFailed(format!("{} failed: {e}", kind.label()))
    } else {
        SandboxError::SpawnFailed(e.to_string())
    }
}

fn append_cleanup_failure(error: SandboxError, cleanup_error: Option<String>) -> SandboxError {
    let Some(cleanup_error) = cleanup_error else {
        return error;
    };
    match error {
        SandboxError::IsolationFailed(message) => SandboxError::IsolationFailed(format!(
            "{message}; tmpdir cleanup failed: {cleanup_error}"
        )),
        SandboxError::SpawnFailed(message) => {
            SandboxError::SpawnFailed(format!("{message}; tmpdir cleanup failed: {cleanup_error}"))
        }
        other => other,
    }
}

fn seccomp_options_for_network(network: &strategy::NetworkStrategy) -> seccomp::SeccompOptions {
    match network {
        strategy::NetworkStrategy::BlockedBySeccomp => {
            seccomp::SeccompOptions::deny_network_socket_domains()
        }
        strategy::NetworkStrategy::AllowHost | strategy::NetworkStrategy::Proxy { .. } => {
            seccomp::SeccompOptions::default()
        }
    }
}

fn child_fd_close_on_exec_range() -> (u32, u32, libc::c_uint) {
    (3, u32::MAX, libc::CLOSE_RANGE_CLOEXEC)
}

fn close_child_fd_range(first: u32, last: u32, flags: libc::c_uint) -> Result<(), i32> {
    if first > last {
        return Ok(());
    }

    let ret = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            first as libc::c_uint,
            last as libc::c_uint,
            flags,
        )
    };
    if ret < 0 {
        Err(current_errno())
    } else {
        Ok(())
    }
}

fn mark_unexpected_child_fds_close_on_exec() -> Result<(), i32> {
    let (first, last, flags) = child_fd_close_on_exec_range();
    close_child_fd_range(first, last, flags)
}

fn current_errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

impl SandboxImpl for LinuxSandbox {
    fn start(&mut self) -> Result<u32, SandboxError> {
        use std::os::unix::process::CommandExt;
        use std::process::Command;

        let sandbox_id = self.config.id;
        tracing::debug!(
            "sandbox {sandbox_id}: linux isolation plan: {:?}",
            self.plan
        );
        let resolved_identity = self.resolve_identity()?;
        let tmpdir_required = landlock::policy_uses_tmpdir(&self.config.policy.filesystem);
        let prepared_landlock =
            landlock::prepare_landlock(&self.config.policy.filesystem, &self.config.workspace_dir)
                .map_err(SandboxError::IsolationFailed)?;
        self.tmpdir_active = tmpdir_required;
        let seccomp_options = seccomp_options_for_network(&self.plan.network);
        let prepared_seccomp = match seccomp::prepare_seccomp_with_options(
            &self.config.policy.process,
            seccomp_options,
        ) {
            Ok(filter) => filter,
            Err(e) => {
                let cleanup_error = self.cleanup_tmpdir_for_setup_failure();
                return Err(append_cleanup_failure(
                    SandboxError::IsolationFailed(e),
                    cleanup_error,
                ));
            }
        };

        // ── Step 1: Create network namespace (parent side) ──
        // This creates the netns, veth pair, and iptables rules.
        // The child will enter this namespace via setns() in pre_exec.
        let netns_fd: Option<i32> = match &self.plan.network {
            strategy::NetworkStrategy::Proxy {
                setup: strategy::ProxyNetworkSetup::IpNetnsWithCapNetAdmin,
                proxy_port,
                ..
            } => {
                let ns_name = format!("{sandbox_id}");
                match netns::create_netns(&ns_name, *proxy_port) {
                    Ok(name) => {
                        self.netns_name = Some(name.clone());
                        // Open the netns fd for the child to setns() into.
                        match netns::enter_netns(&name) {
                            Ok(fd) => Some(fd),
                            Err(e) => {
                                let _ = netns::destroy_netns(&name);
                                self.netns_name = None;
                                let cleanup_error = self.cleanup_tmpdir_for_setup_failure();
                                return Err(append_cleanup_failure(
                                    SandboxError::IsolationFailed(format!(
                                        "netns: cannot open fd for '{name}': {e}"
                                    )),
                                    cleanup_error,
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        let cleanup_error = self.cleanup_tmpdir_for_setup_failure();
                        return Err(append_cleanup_failure(
                            SandboxError::IsolationFailed(format!("netns: creation failed: {e}")),
                            cleanup_error,
                        ));
                    }
                }
            }
            _ => None,
        };

        // ── Step 2: Build child process with pre_exec isolation ──
        let mut cmd = Command::new(&self.config.command);
        cmd.args(&self.config.args);

        if let Some(dir) = &self.config.working_dir {
            cmd.current_dir(dir);
        } else {
            cmd.current_dir(&self.config.workspace_dir);
        }

        // Capture output to workspace files (daemon mode) or inherit stdio (standalone).
        if self.config.capture_output {
            cmd.stdin(std::process::Stdio::null());
            let stdout_file =
                match std::fs::File::create(self.config.workspace_dir.join("stdout.log")) {
                    Ok(file) => file,
                    Err(e) => {
                        let cleanup_error =
                            self.cleanup_parent_resources_after_setup_failure(netns_fd);
                        return Err(append_cleanup_failure(
                            SandboxError::SpawnFailed(format!("stdout log: {e}")),
                            cleanup_error,
                        ));
                    }
                };
            let stderr_file =
                match std::fs::File::create(self.config.workspace_dir.join("stderr.log")) {
                    Ok(file) => file,
                    Err(e) => {
                        let cleanup_error =
                            self.cleanup_parent_resources_after_setup_failure(netns_fd);
                        return Err(append_cleanup_failure(
                            SandboxError::SpawnFailed(format!("stderr log: {e}")),
                            cleanup_error,
                        ));
                    }
                };
            cmd.stdout(std::process::Stdio::from(stdout_file));
            cmd.stderr(std::process::Stdio::from(stderr_file));
        }
        // else: inherit parent's stdio (standalone/run mode)

        // Set environment.
        cmd.env_clear();
        for (k, v) in &self.config.env {
            cmd.env(k, v);
        }

        // Inject proxy env vars only when the plan requires a proxy.
        if let strategy::ProxyStrategy::Required {
            sandbox_addr, port, ..
        } = &self.plan.proxy
        {
            let proxy_url = format!("http://{sandbox_addr}:{port}");
            cmd.env("HTTP_PROXY", &proxy_url);
            cmd.env("HTTPS_PROXY", &proxy_url);
            cmd.env("http_proxy", &proxy_url);
            cmd.env("https_proxy", &proxy_url);
            cmd.env("NO_PROXY", "localhost,127.0.0.1,::1");
            cmd.env("no_proxy", "localhost,127.0.0.1,::1");
        }

        // Safety: pre_exec runs after fork, before exec in the child process.
        let mut child_error_pipe = match ChildSetupErrorPipe::new() {
            Ok(pipe) => pipe,
            Err(e) => {
                let cleanup_error = self.cleanup_parent_resources_after_setup_failure(netns_fd);
                return Err(append_cleanup_failure(
                    SandboxError::SpawnFailed(format!("child setup error pipe: {e}")),
                    cleanup_error,
                ));
            }
        };
        let child_error_write_fd = child_error_pipe.write_fd;
        unsafe {
            cmd.pre_exec(move || {
                // 1. Own process group.
                if libc::setpgid(0, 0) < 0 {
                    return Err(child_setup_error(
                        child_error_write_fd,
                        ChildSetupErrorKind::SetProcessGroup,
                        current_errno(),
                    ));
                }

                // 2. Enter network namespace (if created by parent).
                if let Some(fd) = netns_fd {
                    let ret = libc::setns(fd, libc::CLONE_NEWNET);
                    libc::close(fd);
                    if ret < 0 {
                        return Err(child_setup_error(
                            child_error_write_fd,
                            ChildSetupErrorKind::EnterNetworkNamespace,
                            current_errno(),
                        ));
                    }
                }

                // 3. Prevent SUID escalation.
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                    return Err(child_setup_error(
                        child_error_write_fd,
                        ChildSetupErrorKind::NoNewPrivs,
                        current_errno(),
                    ));
                }

                // 4. Apply Landlock filesystem policy.
                if let Err(e) = prepared_landlock.restrict_current_process() {
                    return Err(child_setup_error(
                        child_error_write_fd,
                        ChildSetupErrorKind::Landlock,
                        e,
                    ));
                }

                // 5. Drop to the configured sandbox user after Landlock setup.
                if let Some(identity) = &resolved_identity {
                    if libc::setgroups(0, std::ptr::null()) < 0 {
                        return Err(child_setup_error(
                            child_error_write_fd,
                            ChildSetupErrorKind::SetGroups,
                            current_errno(),
                        ));
                    }
                    if libc::setgid(identity.gid) < 0 {
                        return Err(child_setup_error(
                            child_error_write_fd,
                            ChildSetupErrorKind::SetGid,
                            current_errno(),
                        ));
                    }
                    if libc::setuid(identity.uid) < 0 {
                        return Err(child_setup_error(
                            child_error_write_fd,
                            ChildSetupErrorKind::SetUid,
                            current_errno(),
                        ));
                    }
                }

                // 6. Prevent inherited descriptors from surviving a successful exec.
                if let Err(errno) = mark_unexpected_child_fds_close_on_exec() {
                    return Err(child_setup_error(
                        child_error_write_fd,
                        ChildSetupErrorKind::CloseFileDescriptors,
                        errno,
                    ));
                }

                // 7. seccomp-BPF syscall filter (must be last — it restricts further syscalls).
                if let Err(e) = prepared_seccomp.apply_current_process() {
                    return Err(child_setup_error(
                        child_error_write_fd,
                        ChildSetupErrorKind::Seccomp,
                        e,
                    ));
                }

                Ok(())
            });
        }

        let child = match cmd.spawn() {
            Ok(child) => {
                close_fd(netns_fd);
                drop(child_error_pipe);
                child
            }
            Err(e) => {
                let cleanup_error = self.cleanup_parent_resources_after_setup_failure(netns_fd);
                return Err(append_cleanup_failure(
                    spawn_error(e, &mut child_error_pipe),
                    cleanup_error,
                ));
            }
        };

        let pid = child.id();
        self.child = Some(child);

        tracing::info!("sandbox {sandbox_id} started, pid={pid}");
        Ok(pid)
    }

    fn wait(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<i32, SandboxError>> + Send + '_>>
    {
        Box::pin(async {
            if let Some(code) = self.exit_code {
                return Ok(code);
            }

            let mut child = self
                .child
                .take()
                .ok_or_else(|| SandboxError::SpawnFailed("no child process".into()))?;
            let pid = child.id() as i32;

            let status = tokio::task::block_in_place(move || child.wait())?;
            let code = status.code().unwrap_or(-1);
            self.exit_code = Some(code);
            kill_process_group(pid);
            self.cleanup_tmpdir_after_stop();
            Ok(code)
        })
    }

    fn destroy(&mut self) -> Result<(), SandboxError> {
        if let Some(mut child) = self.child.take() {
            let pid = child.id() as i32;
            // Kill both the process and its group to catch any children.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::kill(-pid, libc::SIGKILL);
            }
            if let Ok(status) = child.wait() {
                self.exit_code = Some(status.code().unwrap_or(-1));
            } else {
                self.exit_code = Some(-1);
            }
            kill_process_group(pid);
        }

        self.cleanup_netns();
        self.cleanup_tmpdir_after_stop();

        tracing::info!("sandbox {} destroyed", self.config.id);
        Ok(())
    }
}

fn kill_process_group(pid: i32) {
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
        while libc::waitpid(-pid, std::ptr::null_mut(), libc::WNOHANG) > 0 {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axis_core::policy::{
        FilesystemPolicy, GpuPolicy, InferencePolicy, NetworkMode, NetworkPolicy, Policy,
        ProcessPolicy, SshPolicy,
    };
    use axis_core::types::SandboxId;
    use std::io::Write;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::os::unix::io::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    #[test]
    fn spawn_error_maps_child_setup_pipe_failures() {
        let mut pipe = ChildSetupErrorPipe::new().unwrap();
        let byte = ChildSetupErrorKind::Landlock as u8;
        unsafe {
            libc::write(pipe.write_fd, &byte as *const u8 as *const libc::c_void, 1);
        }
        let err = io::Error::from_raw_os_error(libc::EPERM);

        match spawn_error(err, &mut pipe) {
            SandboxError::IsolationFailed(message) => {
                assert!(message.contains("apply Landlock failed"));
            }
            other => panic!("expected IsolationFailed, got {other:?}"),
        }
    }

    #[test]
    fn spawn_error_keeps_plain_spawn_failures() {
        let mut pipe = ChildSetupErrorPipe::new().unwrap();
        let err = io::Error::new(io::ErrorKind::NotFound, "command not found");

        match spawn_error(err, &mut pipe) {
            SandboxError::SpawnFailed(message) => {
                assert_eq!(message, "command not found");
            }
            other => panic!("expected SpawnFailed, got {other:?}"),
        }
    }

    #[test]
    fn real_pre_exec_failure_maps_to_isolation_failed() {
        let mut pipe = ChildSetupErrorPipe::new().unwrap();
        let write_fd = pipe.write_fd;
        let mut cmd = Command::new("true");
        unsafe {
            cmd.pre_exec(move || {
                Err(child_setup_error(
                    write_fd,
                    ChildSetupErrorKind::Seccomp,
                    libc::EPERM,
                ))
            });
        }

        let err = cmd.spawn().unwrap_err();

        match spawn_error(err, &mut pipe) {
            SandboxError::IsolationFailed(message) => {
                assert!(message.contains("apply seccomp failed"));
            }
            other => panic!("expected IsolationFailed, got {other:?}"),
        }
    }

    #[test]
    fn fd_close_on_exec_range_covers_full_descriptor_space() {
        assert_eq!(
            child_fd_close_on_exec_range(),
            (3, u32::MAX, libc::CLOSE_RANGE_CLOEXEC)
        );
    }

    #[test]
    fn close_on_exec_guard_prevents_exec_target_from_inheriting_descriptors() {
        if !Path::new("/bin/sh").exists() {
            eprintln!("/bin/sh unavailable (test skipped)");
            return;
        }

        let workspace = tempfile::tempdir().unwrap();
        let marker_path = workspace.path().join("fd-leak-marker");
        let mut marker = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&marker_path)
            .unwrap();
        let marker_fd = marker.as_raw_fd();
        clear_cloexec(marker_fd);

        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(format!("printf leaked >&{marker_fd}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            cmd.pre_exec(move || {
                mark_unexpected_child_fds_close_on_exec().map_err(std::io::Error::from_raw_os_error)
            });
        }

        let status = cmd.status().unwrap();
        marker.flush().unwrap();

        assert!(!status.success());
        assert_eq!(std::fs::read_to_string(marker_path).unwrap(), "");
    }

    #[test]
    fn close_on_exec_guard_preserves_std_exec_error_reporting() {
        let mut cmd = Command::new("/axis/definitely/not/a/real/program");
        unsafe {
            cmd.pre_exec(|| {
                mark_unexpected_child_fds_close_on_exec().map_err(std::io::Error::from_raw_os_error)
            });
        }

        let err = cmd.spawn().unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wait_reaps_child_and_clears_handle() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let child = Command::new("true").spawn().unwrap();
        let mut sandbox = test_sandbox(id, workspace.path(), Some(child));
        let tmpdir = landlock::sandbox_tmpdir(workspace.path());
        std::fs::create_dir_all(&tmpdir).unwrap();
        sandbox.tmpdir_active = true;

        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();
        let code_again = SandboxImpl::wait(&mut sandbox).await.unwrap();

        assert_eq!(code, 0);
        assert_eq!(code_again, 0);
        assert!(sandbox.child.is_none());
        assert!(!tmpdir.exists());
        sandbox.destroy().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wait_kills_background_process_group_after_foreground_exit() {
        if !Path::new("/bin/sh").exists() {
            eprintln!("/bin/sh unavailable (test skipped)");
            return;
        }

        let workspace = tempfile::tempdir().unwrap();
        let marker = workspace.path().join("background-survived");
        let id = SandboxId::new();
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("(sleep 1; printf survived > \"$MARKER\") &")
            .env("MARKER", &marker);
        unsafe {
            cmd.pre_exec(|| {
                if libc::setpgid(0, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().unwrap();
        let mut sandbox = test_sandbox(id, workspace.path(), Some(child));

        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

        assert_eq!(code, 0);
        assert!(!marker.exists(), "background process survived sandbox wait");
        sandbox.destroy().unwrap();
    }

    #[test]
    fn destroy_is_idempotent_after_killing_child() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let child = Command::new("sleep").arg("10").spawn().unwrap();
        let mut sandbox = test_sandbox(id, workspace.path(), Some(child));

        sandbox.destroy().unwrap();
        assert!(sandbox.child.is_none());
        sandbox.destroy().unwrap();
    }

    #[test]
    fn cleanup_netns_takes_name_after_destroy_attempt() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.netns_name = Some("axis-test-cleanup".into());

        sandbox.cleanup_netns_with(|name| {
            assert_eq!(name, "axis-test-cleanup");
            Err("expected fake cleanup failure".into())
        });

        assert!(sandbox.netns_name.is_none());
        sandbox.cleanup_netns_with(|_| panic!("cleanup must be idempotent"));
    }

    #[test]
    fn setup_failure_cleanup_closes_fd_and_takes_netns_name() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.netns_name = Some("axis-test-cleanup".into());
        let tmpdir = landlock::sandbox_tmpdir(workspace.path());
        std::fs::create_dir_all(&tmpdir).unwrap();
        sandbox.tmpdir_active = true;
        let mut fds = [0; 2];
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(ret, 0);

        let cleanup_error =
            sandbox.cleanup_parent_resources_after_setup_failure_with(Some(fds[0]), |name| {
                assert_eq!(name, "axis-test-cleanup");
                Ok(())
            });

        assert!(cleanup_error.is_none());
        assert!(sandbox.netns_name.is_none());
        assert!(!tmpdir.exists());
        unsafe {
            libc::close(fds[1]);
        }
    }

    #[test]
    fn setup_failure_cleanup_closes_netns_fd() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        let mut fds = [0; 2];
        let ret = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        assert_eq!(ret, 0);

        let cleanup_error = sandbox
            .cleanup_parent_resources_after_setup_failure_with(Some(fds[0]), |_| {
                panic!("no netns cleanup should run without a netns name")
            });

        assert!(cleanup_error.is_none());
        let byte = [0u8; 1];
        let send_result = unsafe {
            libc::send(
                fds[1],
                byte.as_ptr() as *const libc::c_void,
                byte.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        assert_eq!(send_result, -1);
        assert_eq!(current_errno(), libc::EPIPE);
        unsafe {
            libc::close(fds[1]);
        }
    }

    #[test]
    fn setup_failure_cleanup_surfaces_tmpdir_cleanup_error() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        let tmpdir = landlock::sandbox_tmpdir(workspace.path());
        std::fs::write(&tmpdir, b"not a directory").unwrap();
        sandbox.tmpdir_active = true;

        let cleanup_error = sandbox.cleanup_parent_resources_after_setup_failure_with(None, |_| {
            panic!("no netns cleanup should run without a netns name")
        });

        let cleanup_error = cleanup_error.expect("tmpdir cleanup failure should be returned");
        assert!(cleanup_error.contains("cannot remove tmpdir"));
        std::fs::remove_file(&tmpdir).unwrap();
    }

    #[test]
    fn inactive_tmpdir_cleanup_does_not_remove_preexisting_path() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        let tmpdir = landlock::sandbox_tmpdir(workspace.path());
        std::fs::create_dir_all(&tmpdir).unwrap();

        sandbox.cleanup_tmpdir_after_stop();

        assert!(tmpdir.exists());
    }

    #[test]
    fn seccomp_options_follow_network_strategy() {
        assert!(
            seccomp_options_for_network(&strategy::NetworkStrategy::BlockedBySeccomp)
                .denies_non_unix_socket_domains()
        );
        assert!(
            !seccomp_options_for_network(&strategy::NetworkStrategy::AllowHost)
                .denies_non_unix_socket_domains()
        );
        assert!(
            !seccomp_options_for_network(&strategy::NetworkStrategy::Proxy {
                setup: strategy::ProxyNetworkSetup::IpNetnsWithCapNetAdmin,
                firewall: Some(strategy::FirewallTool::Iptables),
                host_addr: Ipv4Addr::new(10, 200, 0, 1),
                sandbox_addr: Ipv4Addr::new(10, 200, 0, 2),
                proxy_port: 3128,
            })
            .denies_non_unix_socket_domains()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn block_mode_sandbox_denies_ip_sockets_preserves_unix_and_omits_proxy_env() {
        if !contract_landlock_available() {
            return;
        }

        let Some(python) =
            find_on_path("python3").and_then(|path| std::fs::canonicalize(path).ok())
        else {
            eprintln!("python3 unavailable (test skipped)");
            return;
        };
        let Ok(baseline) = Command::new(&python).arg("-c").arg("pass").status() else {
            eprintln!("python3 baseline failed to start (test skipped)");
            return;
        };
        if !baseline.success() {
            eprintln!("python3 baseline failed (test skipped)");
            return;
        }

        let workspace = tempfile::tempdir().unwrap();
        let (inherited_socket, _peer_socket) = localhost_tcp_pair().unwrap();
        let inherited_fd = inherited_socket.as_raw_fd();
        clear_cloexec(inherited_fd);
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.config.command = python.to_string_lossy().into_owned();
        sandbox.config.args = vec!["-c".into(), block_mode_python_probe().into()];
        sandbox.config.capture_output = true;
        sandbox.config.env = vec![("LEAKED_FD".into(), inherited_fd.to_string())];
        sandbox.config.policy.network.mode = NetworkMode::Block;
        sandbox.config.policy.filesystem = FilesystemPolicy {
            read_only: runtime_read_only_paths_for(&python),
            ..Default::default()
        };
        sandbox.plan.network = strategy::NetworkStrategy::BlockedBySeccomp;
        sandbox.plan.proxy = strategy::ProxyStrategy::None;

        SandboxImpl::start(&mut sandbox).unwrap();
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();

        let stderr =
            std::fs::read_to_string(workspace.path().join("stderr.log")).unwrap_or_default();
        assert_eq!(code, 0, "block-mode probe failed with stderr:\n{stderr}");
        sandbox.destroy().unwrap();
    }

    #[test]
    fn start_cleans_tmpdir_when_seccomp_policy_preparation_fails() {
        if !contract_landlock_available() {
            return;
        }

        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.config.policy.filesystem = FilesystemPolicy {
            read_write: vec!["{tmpdir}".into()],
            ..Default::default()
        };
        sandbox.config.policy.process = ProcessPolicy {
            blocked_syscalls: vec!["not_a_real_syscall".into()],
            ..Default::default()
        };
        let tmpdir = landlock::sandbox_tmpdir(workspace.path());

        match SandboxImpl::start(&mut sandbox) {
            Err(SandboxError::IsolationFailed(message)) => {
                assert!(message.contains("unknown syscall"));
            }
            other => panic!("expected seccomp preparation failure, got {other:?}"),
        }

        assert!(!tmpdir.exists());
        assert!(!sandbox.tmpdir_active);
    }

    fn clear_cloexec(fd: i32) {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0, "fcntl(F_GETFD) failed");
        let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
        assert_eq!(ret, 0, "fcntl(F_SETFD) failed");
    }

    fn localhost_tcp_pair() -> std::io::Result<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let addr = listener.local_addr()?;
        let client = TcpStream::connect(addr)?;
        let (server, _) = listener.accept()?;
        Ok((client, server))
    }

    #[test]
    fn resolve_identity_rejects_root_aliases() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.plan.identity = strategy::IdentityStrategy::RunAsUser {
            username: "root".into(),
        };

        match sandbox.resolve_identity() {
            Err(SandboxError::IsolationFailed(message)) => {
                assert!(message.contains("UID or GID 0"));
            }
            other => panic!("expected UID/GID 0 rejection, got {other:?}"),
        }
    }

    #[test]
    fn resolve_identity_rejects_missing_user() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.plan.identity = strategy::IdentityStrategy::RunAsUser {
            username: format!("axis-missing-user-{id}"),
        };

        match sandbox.resolve_identity() {
            Err(SandboxError::IsolationFailed(message)) => {
                assert!(message.contains("does not exist"));
            }
            other => panic!("expected missing user rejection, got {other:?}"),
        }
    }

    fn test_sandbox(id: SandboxId, workspace: &Path, child: Option<Child>) -> LinuxSandbox {
        LinuxSandbox {
            config: SandboxConfig {
                id,
                policy: test_policy(),
                command: "true".into(),
                args: Vec::new(),
                working_dir: None,
                workspace_dir: workspace.to_path_buf(),
                env: Vec::new(),
                proxy_port: 0,
                proxy_addr: None,
                capture_output: false,
                timeout_sec: None,
            },
            plan: test_plan(id, workspace),
            child,
            exit_code: None,
            netns_name: None,
            tmpdir_active: false,
        }
    }

    fn test_policy() -> Policy {
        Policy {
            version: 1,
            name: "test-policy".into(),
            filesystem: FilesystemPolicy::default(),
            process: ProcessPolicy::default(),
            network: NetworkPolicy {
                mode: NetworkMode::Allow,
                policies: Vec::new(),
            },
            inference: InferencePolicy::default(),
            gpu: GpuPolicy::default(),
            ssh: SshPolicy::default(),
            amd: None,
        }
    }

    fn test_plan(id: SandboxId, workspace: &Path) -> strategy::LinuxIsolationPlan {
        strategy::LinuxIsolationPlan {
            sandbox_id: id,
            workspace_dir: workspace.to_path_buf(),
            filesystem: strategy::FilesystemStrategy::Landlock { abi: 7 },
            seccomp: strategy::SeccompStrategy::Native,
            network: strategy::NetworkStrategy::AllowHost,
            resources: strategy::ResourceStrategy::RlimitFallback {
                memory_limit: false,
                process_limit: strategy::ProcessLimitFallback::NotRequested,
                cpu_limit: strategy::CpuLimitFallback::NotRequested,
            },
            identity: strategy::IdentityStrategy::CurrentUser,
            proxy: strategy::ProxyStrategy::None,
            fallbacks: Vec::new(),
        }
    }

    fn contract_landlock_available() -> bool {
        match landlock::detect_abi_version() {
            Ok(v) if v >= 3 => true,
            Ok(v) => {
                eprintln!(
                    "Landlock ABI {v} cannot enforce the AXIS filesystem contract (test skipped)"
                );
                false
            }
            Err(e) => {
                eprintln!("Landlock not available: {e} (test skipped)");
                false
            }
        }
    }

    fn find_on_path(binary: &str) -> Option<PathBuf> {
        let path = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(binary);
            if candidate.exists() {
                return Some(candidate);
            }
        }
        None
    }

    fn runtime_read_only_paths_for(binary: &Path) -> Vec<String> {
        let mut paths = vec![
            "/bin".into(),
            "/usr".into(),
            "/lib".into(),
            "/lib64".into(),
            "/nix/store".into(),
            "/etc".into(),
        ];
        if let Some(parent) = binary.parent() {
            paths.push(parent.to_string_lossy().into_owned());
        }
        paths
    }

    fn block_mode_python_probe() -> &'static str {
        r#"
import errno
import os
import socket
import sys

for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    if key in os.environ:
        print(f"unexpected proxy env: {key}", file=sys.stderr)
        sys.exit(10)

leaked_fd = os.environ.get("LEAKED_FD")
if leaked_fd is not None:
    try:
        os.write(int(leaked_fd), b"fd-leak")
    except OSError as exc:
        if exc.errno != errno.EBADF:
            print(f"unexpected inherited fd errno: {exc.errno}", file=sys.stderr)
            sys.exit(11)
    else:
        print("inherited fd unexpectedly remained open", file=sys.stderr)
        sys.exit(12)

for family in (socket.AF_INET, socket.AF_INET6):
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
    except OSError as exc:
        if exc.errno != errno.EPERM:
            print(f"unexpected socket errno for {family}: {exc.errno}", file=sys.stderr)
            sys.exit(20)
    else:
        sock.close()
        print(f"socket unexpectedly succeeded for {family}", file=sys.stderr)
        sys.exit(21)

try:
    left, right = socket.socketpair()
except OSError as exc:
    print(f"AF_UNIX socketpair failed: {exc.errno}", file=sys.stderr)
    sys.exit(30)
else:
    left.close()
    right.close()

sys.exit(0)
"#
    }
}
