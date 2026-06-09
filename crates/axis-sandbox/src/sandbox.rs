// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox trait and configuration.

use axis_core::connect_attribution::ConnectAttributionStore;
use axis_core::policy::Policy;
use axis_core::types::{SandboxId, SandboxStatus};
use std::path::{Path, PathBuf};
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
    pub proxy_addr: Option<std::net::SocketAddr>,
    pub connect_attribution: Option<ConnectAttributionStore>,
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
    /// Captured stdout from the child process (when capture_output=true).
    pub stdout: Option<std::process::ChildStdout>,
    /// Captured stderr from the child process (when capture_output=true).
    pub stderr: Option<std::process::ChildStderr>,
    /// Captured stdin for writing input to the child process.
    pub stdin: Option<std::process::ChildStdin>,
    /// ConPTY read handle (Windows) — merged TTY output with ANSI codes.
    pub pty_read: Option<std::fs::File>,
}

impl Sandbox {
    /// Create a new sandbox with platform-specific isolation.
    pub fn create(config: SandboxConfig) -> Result<Self, SandboxError> {
        Self::create_inner_with_backend(config, true, PlatformBackendSelection::Default)
    }

    /// Create an isolated process for an already prepared managed workspace.
    ///
    /// This skips agent workspace symlink setup/cleanup so short-lived daemon
    /// exec commands do not disturb symlinks owned by the primary sandbox.
    pub fn create_for_exec(config: SandboxConfig) -> Result<Self, SandboxError> {
        Self::create_inner_with_backend(config, false, PlatformBackendSelection::Default)
    }

    fn create_inner_with_backend(
        mut config: SandboxConfig,
        manage_agent_workspace: bool,
        backend: PlatformBackendSelection,
    ) -> Result<Self, SandboxError> {
        config
            .policy
            .validate()
            .map_err(|e| SandboxError::CreationFailed(format!("invalid sandbox policy: {e}")))?;

        let agent_symlinks = prepare_managed_agent_workspace(&mut config, manage_agent_workspace)?;

        let inner = match create_platform_sandbox_with_backend(&config, backend) {
            Ok(inner) => inner,
            Err(err) => {
                crate::workspace::cleanup_agent_symlinks(&agent_symlinks);
                return Err(err);
            }
        };
        Ok(Self {
            id: config.id,
            status: SandboxStatus::Creating,
            pid: None,
            workspace_dir: config.workspace_dir,
            inner,
            agent_symlinks,
            stdout: None,
            stderr: None,
            stdin: None,
            pty_read: None,
        })
    }

    /// Start the sandboxed process.
    pub fn start(&mut self) -> Result<(), SandboxError> {
        let pid = self.inner.start()?;
        self.pid = Some(pid);
        // Take captured stdio handles from the platform impl.
        self.stdout = self.inner.take_stdout();
        self.stderr = self.inner.take_stderr();
        self.stdin = self.inner.take_stdin();
        self.pty_read = self.inner.take_pty_read();
        self.status = SandboxStatus::Running;
        Ok(())
    }

    /// Wait for the sandboxed process to exit. Returns the exit code.
    pub async fn wait(&mut self) -> Result<i32, SandboxError> {
        let code = self.inner.wait().await?;
        self.status = SandboxStatus::Stopped;
        Ok(code)
    }

    /// Reap the sandboxed process if it has already exited.
    pub fn try_wait(&mut self) -> Result<Option<i32>, SandboxError> {
        if !matches!(self.status, SandboxStatus::Running) {
            return Ok(None);
        }
        let Some(code) = self.inner.try_wait()? else {
            return Ok(None);
        };
        self.status = SandboxStatus::Stopped;
        Ok(Some(code))
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

fn prepare_managed_agent_workspace(
    config: &mut SandboxConfig,
    manage_agent_workspace: bool,
) -> Result<Vec<(PathBuf, PathBuf)>, SandboxError> {
    if !manage_agent_workspace {
        let agent_symlinks = Vec::new();
        if let Err(err) = rewrite_read_write_paths_for_agent_targets(
            &config.policy.name,
            &mut config.policy.filesystem.read_write,
            &agent_symlinks,
        ) {
            return Err(SandboxError::CreationFailed(format!(
                "agent workspace preparation: {err}"
            )));
        }
        prepare_existing_scoped_ssh_for_exec(config)?;
        return Ok(agent_symlinks);
    }

    let mut agent_symlinks = crate::workspace::prepare_agent_workspace(
        &config.policy.name,
        &config.policy.filesystem.read_write,
    )
    .map_err(|e| SandboxError::CreationFailed(format!("agent workspace preparation: {e}")))?;

    if let Err(err) = rewrite_read_write_paths_for_agent_targets(
        &config.policy.name,
        &mut config.policy.filesystem.read_write,
        &agent_symlinks,
    ) {
        crate::workspace::cleanup_agent_symlinks(&agent_symlinks);
        return Err(SandboxError::CreationFailed(format!(
            "agent workspace preparation: {err}"
        )));
    }

    if !config.policy.ssh.allowed_keys.is_empty() {
        let ssh_dir = crate::workspace::ssh_workspace_path(&config.policy.name);
        match crate::workspace::link_scoped_ssh_workspace(&ssh_dir) {
            Ok(link) => agent_symlinks.push(link),
            Err(err) => {
                crate::workspace::cleanup_agent_symlinks(&agent_symlinks);
                return Err(SandboxError::CreationFailed(format!(
                    "scoped SSH workspace: {err}"
                )));
            }
        }

        match crate::workspace::prepare_ssh_workspace(&config.policy.name, &config.policy.ssh) {
            Ok(Some(prepared_ssh_dir)) => {
                if let Err(err) = push_unique_policy_path(
                    &mut config.policy.filesystem.read_write,
                    &prepared_ssh_dir,
                )
                .and_then(|()| {
                    remove_policy_path(
                        &mut config.policy.filesystem.deny,
                        &agent_symlinks
                            .last()
                            .expect("SSH symlink should have been recorded")
                            .0,
                    )
                }) {
                    crate::workspace::cleanup_agent_symlinks(&agent_symlinks);
                    return Err(SandboxError::CreationFailed(format!(
                        "scoped SSH workspace: {err}"
                    )));
                }
            }
            Ok(None) => {}
            Err(err) => {
                crate::workspace::cleanup_agent_symlinks(&agent_symlinks);
                return Err(SandboxError::CreationFailed(format!(
                    "scoped SSH workspace: {err}"
                )));
            }
        }
    }

    Ok(agent_symlinks)
}

fn prepare_existing_scoped_ssh_for_exec(config: &mut SandboxConfig) -> Result<(), SandboxError> {
    if config.policy.ssh.allowed_keys.is_empty() {
        return Ok(());
    }

    let ssh_dir = crate::workspace::ssh_workspace_path(&config.policy.name);
    match crate::workspace::scoped_ssh_link_points_to(&ssh_dir) {
        Ok(true) => {
            let ssh_link = crate::workspace::scoped_ssh_link_path().map_err(|err| {
                SandboxError::CreationFailed(format!("scoped SSH workspace: {err}"))
            })?;
            push_unique_policy_path(&mut config.policy.filesystem.read_write, &ssh_dir)
                .and_then(|()| remove_policy_path(&mut config.policy.filesystem.deny, &ssh_link))
                .map_err(|err| SandboxError::CreationFailed(format!("scoped SSH workspace: {err}")))
        }
        Ok(false) => Err(SandboxError::CreationFailed(
            "scoped SSH workspace is not prepared for exec".into(),
        )),
        Err(err) => Err(SandboxError::CreationFailed(format!(
            "scoped SSH workspace: {err}"
        ))),
    }
}

fn rewrite_read_write_paths_for_agent_targets(
    policy_name: &str,
    read_write_paths: &mut Vec<String>,
    symlinks: &[(PathBuf, PathBuf)],
) -> Result<(), String> {
    for path in read_write_paths.iter_mut() {
        let expanded = crate::workspace::expand_home_or_absolute_path(path)?;
        let mut target = expanded.as_ref().and_then(|expanded| {
            symlinks
                .iter()
                .find_map(|(link, target)| (expanded == link).then_some(target.clone()))
        });
        if target.is_none() {
            target = crate::workspace::agent_state_mapping_for_policy_path(policy_name, path)?
                .map(|(_, target)| target);
        }

        if let Some(target) = target {
            *path = policy_path_string(&target)?;
        }
    }

    for path in read_write_paths.clone() {
        if let Some((_, target)) =
            crate::workspace::agent_state_mapping_for_policy_path(policy_name, &path)?
        {
            push_unique_policy_path(read_write_paths, &target)?;
        }
    }

    Ok(())
}

fn remove_policy_path(paths: &mut Vec<String>, remove: &Path) -> Result<(), String> {
    let mut retained = Vec::with_capacity(paths.len());
    for path in paths.drain(..) {
        let should_remove = crate::workspace::expand_home_or_absolute_path(&path)?
            .is_some_and(|expanded| expanded == *remove);
        if !should_remove {
            retained.push(path);
        }
    }
    *paths = retained;
    Ok(())
}

fn push_unique_policy_path(paths: &mut Vec<String>, path: &Path) -> Result<(), String> {
    let path = policy_path_string(path)?;
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
    Ok(())
}

fn policy_path_string(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("policy path '{}' is not valid UTF-8", path.display()))
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlatformBackendSelection {
    Default,
    #[cfg(target_os = "linux")]
    LinuxMxc,
}

/// Platform-specific sandbox implementation trait.
pub(crate) trait SandboxImpl: Send {
    /// Start the isolated process. Returns the PID.
    fn start(&mut self) -> Result<u32, SandboxError>;

    /// Wait for the process to exit.
    fn wait(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<i32, SandboxError>> + Send + '_>>;

    /// Reap the child process if it has already exited without blocking.
    fn try_wait(&mut self) -> Result<Option<i32>, SandboxError>;

    /// Take captured stdout handle (if capture_output was enabled).
    fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        None
    }

    /// Take captured stderr handle (if capture_output was enabled).
    fn take_stderr(&mut self) -> Option<std::process::ChildStderr> {
        None
    }

    /// Take captured stdin handle for writing input to the child.
    fn take_stdin(&mut self) -> Option<std::process::ChildStdin> {
        None
    }

    /// Take ConPTY read handle (Windows only — provides merged TTY output).
    fn take_pty_read(&mut self) -> Option<std::fs::File> {
        None
    }

    /// Kill the process and clean up isolation resources.
    fn destroy(&mut self) -> Result<(), SandboxError>;
}

fn create_platform_sandbox_with_backend(
    config: &SandboxConfig,
    backend: PlatformBackendSelection,
) -> Result<Box<dyn SandboxImpl>, SandboxError> {
    #[cfg(target_os = "linux")]
    {
        match backend {
            PlatformBackendSelection::Default => {
                Ok(Box::new(crate::linux::LinuxSandbox::new(config)?))
            }
            PlatformBackendSelection::LinuxMxc => {
                Ok(Box::new(crate::linux::mxc::MxcLinuxSandbox::new(config)?))
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let _ = backend;
        Ok(Box::new(crate::macos::MacosSandbox::new(config)?))
    }

    #[cfg(target_os = "windows")]
    {
        let _ = backend;
        Ok(Box::new(crate::windows::WindowsSandbox::new(config)?))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = backend;
        let _ = config;
        Err(SandboxError::Unsupported(format!(
            "platform '{}' is not yet supported",
            std::env::consts::OS
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axis_core::policy::{
        FilesystemPolicy, GpuPolicy, InferencePolicy, NetworkMode, NetworkPolicy, ProcessPolicy,
        SshKeySpec, SshPolicy,
    };
    use std::ffi::OsString;
    use std::path::Path;
    use std::sync::{Mutex, OnceLock};

    fn test_config() -> SandboxConfig {
        SandboxConfig {
            id: SandboxId::new(),
            policy: Policy {
                version: 1,
                name: "test".into(),
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
            },
            command: "true".into(),
            args: Vec::new(),
            working_dir: None,
            workspace_dir: std::env::temp_dir().join("axis-sandbox-validation-test"),
            env: Vec::new(),
            proxy_port: 0,
            proxy_addr: None,
            connect_attribution: None,
            capture_output: false,
            timeout_sec: None,
        }
    }

    #[test]
    fn create_rejects_invalid_manual_resource_policy_before_platform_setup() {
        let mut config = test_config();
        config.policy.process.cpu_rate_percent = 101;

        let err = match Sandbox::create(config) {
            Ok(_) => panic!("invalid resource policy should be rejected"),
            Err(err) => err,
        };

        assert!(matches!(err, SandboxError::CreationFailed(_)));
        assert!(err.to_string().contains("cpu_rate_percent"));
    }

    #[test]
    fn create_for_exec_rejects_invalid_manual_resource_policy_before_platform_setup() {
        let mut config = test_config();
        config.policy.process.cpu_rate_percent = 101;

        let err = match Sandbox::create_for_exec(config) {
            Ok(_) => panic!("invalid resource policy should be rejected"),
            Err(err) => err,
        };

        assert!(matches!(err, SandboxError::CreationFailed(_)));
        assert!(err.to_string().contains("cpu_rate_percent"));
    }

    #[cfg(unix)]
    #[test]
    fn agent_workspace_preparation_rewrites_known_paths_and_ignores_unknown_home_paths() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let mut config = test_config();
            config.policy.name = "agent-codex".into();
            config.workspace_dir = workspace.path().join("workspace");
            config.policy.filesystem.read_write = vec![
                "~/.codex".into(),
                "~/Documents".into(),
                "~/.unknown-agent".into(),
                "{workspace}".into(),
            ];

            let symlinks = prepare_managed_agent_workspace(&mut config, true).unwrap();
            let codex_link = home.path().join(".codex");
            let codex_target = home.path().join(".axis/agents/agent-codex/codex");

            assert_eq!(symlinks, vec![(codex_link.clone(), codex_target.clone())]);
            assert!(codex_link.is_symlink());
            assert_eq!(std::fs::read_link(&codex_link).unwrap(), codex_target);
            assert!(
                config
                    .policy
                    .filesystem
                    .read_write
                    .contains(&codex_target.to_string_lossy().into_owned()),
                "backend policy should grant the contained target, not only the symlink alias"
            );
            assert!(
                !config
                    .policy
                    .filesystem
                    .read_write
                    .contains(&"~/.codex".into()),
                "backend policy should not rely on MXC representing symlink aliases"
            );
            assert!(
                !home.path().join("Documents").is_symlink(),
                "broad user directories must not be redirected"
            );
            assert!(
                !home.path().join(".unknown-agent").exists(),
                "unknown agent state paths must not be redirected"
            );

            crate::workspace::cleanup_agent_symlinks(&symlinks);
            assert!(!codex_link.exists());
        });
    }

    #[cfg(unix)]
    #[test]
    fn scoped_ssh_preparation_uses_generated_ssh_dir_and_removes_real_home_deny() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let key_dir = home.path().join("keys");
            std::fs::create_dir(&key_dir).unwrap();
            let key_path = key_dir.join("id_ed25519");
            std::fs::write(&key_path, "private-key").unwrap();

            let mut config = test_config();
            config.policy.name = "agent-ssh".into();
            config.workspace_dir = workspace.path().join("workspace");
            config.policy.filesystem.deny = vec!["~/.ssh".into(), "~/.aws".into()];
            config.policy.ssh = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: key_path.to_string_lossy().into_owned(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            let symlinks = prepare_managed_agent_workspace(&mut config, true).unwrap();
            let ssh_link = home.path().join(".ssh");
            let ssh_dir = home.path().join(".axis/agents/agent-ssh/ssh");

            assert!(ssh_link.is_symlink());
            assert_eq!(std::fs::read_link(&ssh_link).unwrap(), ssh_dir);
            assert_eq!(
                std::fs::read_to_string(ssh_dir.join("id_ed25519")).unwrap(),
                "private-key"
            );
            let generated_config = std::fs::read_to_string(ssh_dir.join("config")).unwrap();
            assert!(generated_config.contains("Host github.com"));
            assert!(generated_config.contains("IdentityFile ~/.ssh/id_ed25519"));
            assert!(
                config
                    .policy
                    .filesystem
                    .read_write
                    .contains(&ssh_dir.to_string_lossy().into_owned()),
                "scoped SSH target must be writable inside the backend sandbox"
            );
            assert!(
                !config.policy.filesystem.deny.contains(&"~/.ssh".into()),
                "the backend policy must not deny the generated ~/.ssh symlink target"
            );
            assert!(config.policy.filesystem.deny.contains(&"~/.aws".into()));

            crate::workspace::cleanup_agent_symlinks(&symlinks);
            assert!(!ssh_link.exists());
        });
    }

    #[cfg(unix)]
    #[test]
    fn scoped_ssh_preparation_refuses_to_replace_real_user_ssh() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let real_ssh = home.path().join(".ssh");
            std::fs::create_dir(&real_ssh).unwrap();
            let key_path = real_ssh.join("id_ed25519");
            std::fs::write(&key_path, "real-private-key").unwrap();

            let mut config = test_config();
            config.policy.name = "agent-ssh".into();
            config.workspace_dir = workspace.path().join("workspace");
            config.policy.ssh = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: "~/.ssh/id_ed25519".into(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            let err = prepare_managed_agent_workspace(&mut config, true).unwrap_err();

            assert!(matches!(err, SandboxError::CreationFailed(_)));
            assert!(
                err.to_string()
                    .contains("refusing to replace existing ~/.ssh")
            );
            assert!(real_ssh.is_dir());
            assert!(!real_ssh.is_symlink());
            assert_eq!(
                std::fs::read_to_string(real_ssh.join("id_ed25519")).unwrap(),
                "real-private-key"
            );
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn create_cleans_agent_symlink_when_mxc_backend_setup_fails() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let mut config = test_config();
            config.policy.name = "agent-codex".into();
            config.policy.network.mode = NetworkMode::Proxy;
            config.policy.filesystem.read_write = vec!["~/.codex".into()];
            config.workspace_dir = workspace.path().join("workspace");

            let err = match Sandbox::create_inner_with_backend(
                config,
                true,
                PlatformBackendSelection::LinuxMxc,
            ) {
                Ok(_) => panic!("MXC backend setup should fail for unsupported proxy mode"),
                Err(err) => err,
            };

            assert!(matches!(err, SandboxError::IsolationFailed(_)));
            assert!(err.to_string().contains("cooperative"));
            assert!(
                !home.path().join(".codex").exists(),
                "agent symlink should be cleaned when backend setup fails"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn exec_workspace_preparation_rewrites_known_paths_without_creating_symlinks() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let primary_symlinks =
                crate::workspace::prepare_agent_workspace("agent-codex", &["~/.codex".into()])
                    .unwrap();
            let codex_link = home.path().join(".codex");
            let codex_target = home.path().join(".axis/agents/agent-codex/codex");

            let mut config = test_config();
            config.policy.name = "agent-codex".into();
            config.workspace_dir = workspace.path().join("workspace");
            config.policy.filesystem.read_write = vec!["~/.codex".into()];

            let exec_symlinks = prepare_managed_agent_workspace(&mut config, false).unwrap();

            assert!(exec_symlinks.is_empty());
            assert!(codex_link.is_symlink());
            assert_eq!(
                config.policy.filesystem.read_write,
                vec![codex_target.to_string_lossy().into_owned()]
            );

            crate::workspace::cleanup_agent_symlinks(&primary_symlinks);
        });
    }

    #[cfg(unix)]
    #[test]
    fn exec_scoped_ssh_reuses_existing_generated_link_without_replacing_home_ssh() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let ssh_dir = crate::workspace::ssh_workspace_path("agent-ssh");
            let ssh_link_pair = crate::workspace::link_scoped_ssh_workspace(&ssh_dir).unwrap();

            let mut config = test_config();
            config.policy.name = "agent-ssh".into();
            config.workspace_dir = workspace.path().join("workspace");
            config.policy.filesystem.deny = vec!["~/.ssh".into()];
            config.policy.ssh = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: "/tmp/nonexistent-key-for-exec".into(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            let exec_symlinks = prepare_managed_agent_workspace(&mut config, false).unwrap();

            assert!(exec_symlinks.is_empty());
            assert!(home.path().join(".ssh").is_symlink());
            assert!(
                config
                    .policy
                    .filesystem
                    .read_write
                    .contains(&ssh_dir.to_string_lossy().into_owned())
            );
            assert!(!config.policy.filesystem.deny.contains(&"~/.ssh".into()));

            crate::workspace::cleanup_agent_symlinks(&[ssh_link_pair]);
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn public_create_for_exec_uses_default_linux_backend() {
        let workspace = tempfile::tempdir().unwrap();
        let mut config = test_config();
        config.workspace_dir = workspace.path().join("workspace");
        disable_resource_limits(&mut config);

        let sandbox = Sandbox::create_for_exec(config).unwrap();

        assert_eq!(sandbox.status, SandboxStatus::Creating);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn public_create_uses_default_linux_backend() {
        let workspace = tempfile::tempdir().unwrap();
        let mut config = test_config();
        config.workspace_dir = workspace.path().join("workspace");
        disable_resource_limits(&mut config);

        let sandbox = Sandbox::create(config).unwrap();

        assert_eq!(sandbox.status, SandboxStatus::Creating);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn explicit_linux_mxc_backend_fails_closed_before_spawn() {
        let workspace = tempfile::tempdir().unwrap();
        let mut config = test_config();
        config.workspace_dir = workspace.path().join("workspace");

        let err =
            match create_platform_sandbox_with_backend(&config, PlatformBackendSelection::LinuxMxc)
            {
                Ok(_) => panic!("MXC backend should reject unsupported filesystem semantics"),
                Err(err) => err,
            };

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("MXC Linux backend unsupported"));
        assert!(err.to_string().contains("default-deny"));
    }

    fn disable_resource_limits(config: &mut SandboxConfig) {
        config.policy.process.max_processes = 0;
        config.policy.process.max_memory_mb = 0;
        config.policy.process.cpu_rate_percent = 0;
    }

    fn with_home<T>(home: &Path, f: impl FnOnce() -> T) -> T {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();

        struct EnvGuard {
            home: Option<OsString>,
        }

        impl Drop for EnvGuard {
            fn drop(&mut self) {
                unsafe {
                    match &self.home {
                        Some(value) => std::env::set_var("HOME", value),
                        None => std::env::remove_var("HOME"),
                    }
                }
            }
        }

        let previous = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", home);
        }
        let _env_guard = EnvGuard { home: previous };

        f()
    }
}
