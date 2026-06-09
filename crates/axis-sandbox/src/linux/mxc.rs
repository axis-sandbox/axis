// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Linux MXC configuration translation.
//!
//! This module is the first MXC migration layer: it converts AXIS sandbox
//! policy into an AXIS-owned MXC JSON shape without changing runtime backend
//! selection. Unsupported AXIS guarantees fail before launch instead of being
//! mapped to weaker MXC behavior.

use crate::sandbox::{SandboxConfig, SandboxError, SandboxImpl};
use axis_core::policy::{Compatibility, FilesystemPolicy, NetworkMode, Policy};
use axis_core::types::SandboxId;
use serde::Serialize;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

const MXC_SCHEMA_VERSION: &str = "0.6.0-alpha";
const MXC_LINUX_PLATFORM: &str = "linux";
const MXC_BUBBLEWRAP_CONTAINMENT: &str = "bubblewrap";
const MXC_EXECUTOR_NAME: &str = "lxc-exec";
const MXC_EXECUTOR_DIRS: &[&str] = &["/usr/local/bin", "/usr/bin", "/bin"];
const AXIS_SECCOMP_LAUNCHER_NAME: &str = "axis-seccomp-launcher";
const AXIS_SECCOMP_LAUNCHER_DIRS: &[&str] = &[
    "/usr/libexec/axis",
    "/usr/local/libexec/axis",
    "/usr/lib/axis",
    "/usr/local/lib/axis",
];
const MXC_DRY_RUN_SUCCESS: &str = "Dry run completed. Result: validation passed";
const MAX_DRY_RUN_OUTPUT_BYTES: u64 = 64 * 1024;
const POST_TIMEOUT_REAP_GRACE_SEC: u64 = 5;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MxcTranslationError {
    #[error("MXC translation does not support AXIS proxy mode yet: {0}")]
    ProxyModeUnsupported(String),

    #[error("network endpoint policies are invalid in {mode} mode")]
    EndpointPoliciesInNonProxyMode { mode: &'static str },

    #[error("filesystem policy cannot be represented by MXC: {0}")]
    Filesystem(String),

    #[error(
        "MXC Bubblewrap filesystem isolation cannot preserve AXIS default-deny semantics: current MXC Bubblewrap mounts the host root read-only"
    )]
    FilesystemDefaultDenyUnsupported,

    #[error("process command must not be empty")]
    EmptyCommand,

    #[error("invalid environment variable: {0}")]
    InvalidEnv(String),

    #[error("path cannot be represented as UTF-8: {0}")]
    NonUtf8Path(String),

    #[error("timeout {seconds}s cannot be represented as MXC milliseconds")]
    TimeoutOverflow { seconds: u64 },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MxcExecutorError {
    #[error("no safe MXC executor found in stable install locations or PATH")]
    Unavailable,

    #[error("unsafe MXC executor candidate '{}': {reason}", path.display())]
    UnsafeCandidate { path: PathBuf, reason: String },

    #[error("MXC config contains environment entry filtered by AXIS sandbox policy: {key}")]
    FilteredEnv { key: String },

    #[error("MXC config contains malformed environment entry")]
    MalformedEnv,

    #[error("failed to serialize MXC dry-run config: {0}")]
    Serialize(String),

    #[error("failed to prepare MXC dry-run config: {0}")]
    ConfigIo(String),

    #[error("failed to spawn MXC executor: {0}")]
    Spawn(String),

    #[error("MXC dry-run timed out after {timeout_ms}ms")]
    Timeout { timeout_ms: u128 },

    #[error("MXC dry-run failed with exit code {code:?}")]
    DryRunFailed { code: Option<i32> },

    #[error("MXC dry-run exited successfully without reporting validation success")]
    MalformedDryRunOutput,
}

#[derive(Debug, Error, PartialEq, Eq)]
enum MxcSeccompLauncherError {
    #[error(
        "no safe axis-seccomp-launcher found in stable install locations or beside the current executable"
    )]
    Unavailable,

    #[error("unsafe axis-seccomp-launcher candidate '{}': {reason}", path.display())]
    UnsafeCandidate { path: PathBuf, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MxcExecutionSpec {
    pub version: String,
    pub platform: String,
    pub containment: String,
    pub process: MxcProcess,
    pub filesystem: MxcFilesystem,
    pub network: MxcNetwork,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxcExecutor {
    path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MxcSeccompLauncher {
    path: PathBuf,
}

impl MxcExecutor {
    pub fn resolve() -> Result<Self, MxcExecutorError> {
        Self::resolve_from_candidates(production_executor_candidates())
    }

    pub fn resolve_from_candidates<I, P>(candidates: I) -> Result<Self, MxcExecutorError>
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        for candidate in candidates {
            if let Ok(executor) = Self::from_path(candidate) {
                return Ok(executor);
            }
        }

        Err(MxcExecutorError::Unavailable)
    }

    pub fn from_path<P>(path: P) -> Result<Self, MxcExecutorError>
    where
        P: Into<PathBuf>,
    {
        let path = path.into();
        validate_executor_path(&path, ExecutorPathMode::Production)?;
        Ok(Self { path })
    }

    #[cfg(test)]
    fn from_injected_path<P>(path: P) -> Result<Self, MxcExecutorError>
    where
        P: Into<PathBuf>,
    {
        let path = path.into();
        validate_executor_path(&path, ExecutorPathMode::TestInjected)?;
        Ok(Self { path })
    }

    #[cfg(test)]
    fn resolve_from_injected_candidates<I, P>(candidates: I) -> Result<Self, MxcExecutorError>
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        for candidate in candidates {
            if let Ok(executor) = Self::from_injected_path(candidate) {
                return Ok(executor);
            }
        }

        Err(MxcExecutorError::Unavailable)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn dry_run(
        &self,
        spec: &MxcExecutionSpec,
        timeout: Duration,
    ) -> Result<MxcDryRunResult, MxcExecutorError> {
        self.dry_run_with_allowed_env(spec, timeout, &[])
    }

    fn dry_run_with_allowed_env(
        &self,
        spec: &MxcExecutionSpec,
        timeout: Duration,
        allowed_proxy_env: &[(String, String)],
    ) -> Result<MxcDryRunResult, MxcExecutorError> {
        let config = self.write_private_config_with_allowed_env(spec, allowed_proxy_env)?;

        let mut stdout_file =
            tempfile::tempfile().map_err(|err| MxcExecutorError::ConfigIo(err.to_string()))?;
        let mut stderr_file =
            tempfile::tempfile().map_err(|err| MxcExecutorError::ConfigIo(err.to_string()))?;
        let stdout = stdout_file
            .try_clone()
            .map_err(|err| MxcExecutorError::ConfigIo(err.to_string()))?;
        let stderr = stderr_file
            .try_clone()
            .map_err(|err| MxcExecutorError::ConfigIo(err.to_string()))?;

        let mut command = Command::new(&self.path);
        command
            .arg("--experimental")
            .arg("--dry-run")
            .arg("--config")
            .arg(config.path())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        // SAFETY: this pre_exec hook only calls async-signal-safe setpgid(2)
        // and returns the OS error directly when it fails.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }

        let child = command
            .spawn()
            .map_err(|err| MxcExecutorError::Spawn(err.to_string()))?;
        let status = wait_child_with_timeout(child, timeout)?;
        let stdout = read_limited_output(&mut stdout_file)?;
        let stderr = read_limited_output(&mut stderr_file)?;

        if !status.success() {
            return Err(MxcExecutorError::DryRunFailed {
                code: status.code(),
            });
        }
        if !stdout.contains(MXC_DRY_RUN_SUCCESS) {
            return Err(MxcExecutorError::MalformedDryRunOutput);
        }

        Ok(MxcDryRunResult { stdout, stderr })
    }

    fn write_private_config_with_allowed_env(
        &self,
        spec: &MxcExecutionSpec,
        allowed_proxy_env: &[(String, String)],
    ) -> Result<tempfile::NamedTempFile, MxcExecutorError> {
        validate_spec_env_for_launch(spec, allowed_proxy_env)?;

        let json =
            serde_json::to_vec(spec).map_err(|err| MxcExecutorError::Serialize(err.to_string()))?;
        let mut config = tempfile::Builder::new()
            .prefix("axis-mxc-")
            .suffix(".json")
            .tempfile()
            .map_err(|err| MxcExecutorError::ConfigIo(err.to_string()))?;
        config
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|err| MxcExecutorError::ConfigIo(err.to_string()))?;
        config
            .write_all(&json)
            .map_err(|err| MxcExecutorError::ConfigIo(err.to_string()))?;
        config
            .flush()
            .map_err(|err| MxcExecutorError::ConfigIo(err.to_string()))?;
        Ok(config)
    }
}

impl MxcSeccompLauncher {
    fn resolve() -> Result<Self, MxcSeccompLauncherError> {
        Self::resolve_from_candidates(production_seccomp_launcher_candidates())
    }

    fn resolve_from_candidates<I, P>(candidates: I) -> Result<Self, MxcSeccompLauncherError>
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        for candidate in candidates {
            if let Ok(launcher) = Self::from_path(candidate) {
                return Ok(launcher);
            }
        }

        Err(MxcSeccompLauncherError::Unavailable)
    }

    fn from_path<P>(path: P) -> Result<Self, MxcSeccompLauncherError>
    where
        P: Into<PathBuf>,
    {
        let path = path.into();
        validate_safe_executable_path(&path, ExecutorPathMode::Production).map_err(|reason| {
            MxcSeccompLauncherError::UnsafeCandidate {
                path: path.clone(),
                reason,
            }
        })?;
        Ok(Self { path })
    }

    #[cfg(test)]
    fn from_injected_path<P>(path: P) -> Result<Self, MxcSeccompLauncherError>
    where
        P: Into<PathBuf>,
    {
        let path = path.into();
        validate_safe_executable_path(&path, ExecutorPathMode::TestInjected).map_err(|reason| {
            MxcSeccompLauncherError::UnsafeCandidate {
                path: path.clone(),
                reason,
            }
        })?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxcDryRunResult {
    pub stdout: String,
    pub stderr: String,
}

pub(crate) struct MxcLinuxSandbox {
    id: SandboxId,
    spec: MxcExecutionSpec,
    executor: MxcExecutor,
    process_policy: axis_core::policy::ProcessPolicy,
    network_strategy: super::strategy::NetworkStrategy,
    proxy_strategy: super::strategy::ProxyStrategy,
    resource_strategy: super::strategy::ResourceStrategy,
    child: Option<Child>,
    exit_code: Option<i32>,
    config_file: Option<tempfile::NamedTempFile>,
    seccomp_filter_file: Option<tempfile::NamedTempFile>,
    netns_name: Option<String>,
    cgroup: Option<super::resources::CgroupHandle>,
    #[cfg(test)]
    cgroup_override: Option<super::resources::CgroupHandle>,
    #[cfg(test)]
    netns_override: Option<MxcNetnsOverride>,
    #[cfg(test)]
    netns_cleanup_result: Option<Result<(), String>>,
    workspace_dir: PathBuf,
    capture_output: bool,
    timeout_sec: Option<u64>,
    tmpdir_active: bool,
}

#[cfg(test)]
#[derive(Debug)]
struct MxcNetnsOverride {
    name: String,
    fd: i32,
    cleanup: Result<(), String>,
}

impl MxcLinuxSandbox {
    pub(crate) fn new(config: &SandboxConfig) -> Result<Self, SandboxError> {
        std::fs::create_dir_all(&config.workspace_dir)?;
        Self::new_with_resolvers(
            config,
            || {
                MxcExecutor::resolve().map_err(|err| {
                    SandboxError::IsolationFailed(format!("MXC Linux executor unavailable: {err}"))
                })
            },
            || {
                MxcSeccompLauncher::resolve().map_err(|err| {
                    SandboxError::IsolationFailed(format!(
                        "MXC Linux seccomp launcher unavailable: {err}"
                    ))
                })
            },
            || resolve_mxc_network_strategy(config),
            || resolve_mxc_resource_strategy(&config.policy.process),
        )
    }

    #[cfg(test)]
    fn new_with_executor(
        config: &SandboxConfig,
        executor: MxcExecutor,
        seccomp_launcher: MxcSeccompLauncher,
    ) -> Result<Self, SandboxError> {
        Self::new_with_resolvers(
            config,
            || Ok(executor),
            || Ok(seccomp_launcher),
            || Ok(no_proxy_network_strategy()),
            || Ok(no_resource_limits_strategy()),
        )
    }

    #[cfg(test)]
    fn new_with_executor_and_resource_strategy(
        config: &SandboxConfig,
        executor: MxcExecutor,
        seccomp_launcher: MxcSeccompLauncher,
        resource_strategy: super::strategy::ResourceStrategy,
    ) -> Result<Self, SandboxError> {
        Self::new_with_resolvers(
            config,
            || Ok(executor),
            || Ok(seccomp_launcher),
            || Ok(no_proxy_network_strategy()),
            || Ok(resource_strategy),
        )
    }

    #[cfg(test)]
    fn new_with_executor_and_strategies(
        config: &SandboxConfig,
        executor: MxcExecutor,
        seccomp_launcher: MxcSeccompLauncher,
        network_strategy: super::strategy::NetworkStrategy,
        proxy_strategy: super::strategy::ProxyStrategy,
        resource_strategy: super::strategy::ResourceStrategy,
    ) -> Result<Self, SandboxError> {
        Self::new_with_resolvers(
            config,
            || Ok(executor),
            || Ok(seccomp_launcher),
            || Ok((network_strategy, proxy_strategy)),
            || Ok(resource_strategy),
        )
    }

    fn new_with_resolvers<F, G, H, I>(
        config: &SandboxConfig,
        resolve_executor: F,
        resolve_seccomp_launcher: G,
        resolve_network: H,
        resolve_resources: I,
    ) -> Result<Self, SandboxError>
    where
        F: FnOnce() -> Result<MxcExecutor, SandboxError>,
        G: FnOnce() -> Result<MxcSeccompLauncher, SandboxError>,
        H: FnOnce() -> Result<
            (
                super::strategy::NetworkStrategy,
                super::strategy::ProxyStrategy,
            ),
            SandboxError,
        >,
        I: FnOnce() -> Result<super::strategy::ResourceStrategy, SandboxError>,
    {
        let (network_strategy, proxy_strategy) = resolve_network()?;
        let resource_strategy = resolve_resources()?;
        let mut tmpdir_active = false;
        if super::landlock::policy_uses_tmpdir(&config.policy.filesystem) {
            super::landlock::create_tmpdir(&config.workspace_dir)
                .map_err(|err| SandboxError::IsolationFailed(format!("MXC tmpdir: {err}")))?;
            tmpdir_active = true;
        }

        let network_translation = mxc_network_translation_mode(&network_strategy);
        let spec =
            MxcExecutionSpec::from_sandbox_config_with_network_mode(config, network_translation)
                .map_err(|err| {
                    let cleanup_error =
                        cleanup_tmpdir_on_setup_failure(&config.workspace_dir, tmpdir_active);
                    append_cleanup_failure(
                        SandboxError::IsolationFailed(format!(
                            "MXC Linux backend unsupported: {err}"
                        )),
                        cleanup_error,
                    )
                })?;
        let mut spec = spec;
        apply_proxy_env_to_spec(&mut spec, &proxy_strategy);
        let seccomp_filter_file =
            prepare_mxc_seccomp_launch(config, &mut spec, resolve_seccomp_launcher).map_err(
                |err| {
                    let cleanup_error =
                        cleanup_tmpdir_on_setup_failure(&config.workspace_dir, tmpdir_active);
                    append_cleanup_failure(err, cleanup_error)
                },
            )?;
        let executor = resolve_executor().map_err(|err| {
            let cleanup_error =
                cleanup_tmpdir_on_setup_failure(&config.workspace_dir, tmpdir_active);
            append_cleanup_failure(err, cleanup_error)
        })?;
        let allowed_proxy_env = allowed_proxy_env(&proxy_strategy);
        executor
            .dry_run_with_allowed_env(&spec, Duration::from_secs(5), &allowed_proxy_env)
            .map_err(|err| {
                let cleanup_error =
                    cleanup_tmpdir_on_setup_failure(&config.workspace_dir, tmpdir_active);
                append_cleanup_failure(
                    SandboxError::IsolationFailed(format!(
                        "MXC Linux dry-run validation failed: {err}"
                    )),
                    cleanup_error,
                )
            })?;

        Ok(Self {
            id: config.id,
            spec,
            executor,
            process_policy: config.policy.process.clone(),
            network_strategy,
            proxy_strategy,
            resource_strategy,
            child: None,
            exit_code: None,
            config_file: None,
            seccomp_filter_file: Some(seccomp_filter_file),
            netns_name: None,
            cgroup: None,
            #[cfg(test)]
            cgroup_override: None,
            #[cfg(test)]
            netns_override: None,
            #[cfg(test)]
            netns_cleanup_result: None,
            workspace_dir: config.workspace_dir.clone(),
            capture_output: config.capture_output,
            timeout_sec: config.timeout_sec,
            tmpdir_active,
        })
    }

    fn cleanup_after_stop(&mut self) -> Result<(), SandboxError> {
        self.config_file.take();
        self.seccomp_filter_file.take();
        let mut cleanup_errors = Vec::new();
        if let Some(error) = self.cleanup_netns() {
            cleanup_errors.push(format!("netns cleanup failed: {error}"));
        }
        if let Some(error) = self.cleanup_cgroup() {
            cleanup_errors.push(format!("cgroup cleanup failed: {error}"));
        }
        if let Err(error) = self.cleanup_tmpdir() {
            cleanup_errors.push(format!("tmpdir cleanup failed: {error}"));
        }
        if cleanup_errors.is_empty() {
            Ok(())
        } else {
            Err(SandboxError::IsolationFailed(cleanup_errors.join("; ")))
        }
    }

    fn cleanup_tmpdir(&mut self) -> Result<(), SandboxError> {
        if !self.tmpdir_active {
            return Ok(());
        }
        super::landlock::cleanup_tmpdir(&self.workspace_dir)
            .map_err(|err| SandboxError::IsolationFailed(format!("MXC tmpdir cleanup: {err}")))?;
        self.tmpdir_active = false;
        Ok(())
    }

    fn cleanup_netns(&mut self) -> Option<String> {
        let ns_name = self.netns_name.clone()?;

        #[cfg(test)]
        if let Some(result) = self.netns_cleanup_result.clone() {
            match result {
                Ok(()) => {
                    self.netns_cleanup_result = None;
                    self.netns_name = None;
                    return None;
                }
                Err(error) => {
                    tracing::warn!("failed to destroy MXC netns '{ns_name}': {error}");
                    return Some(format!("netns '{ns_name}': {error}"));
                }
            }
        }

        if let Err(error) = super::netns::destroy_netns(&ns_name) {
            tracing::warn!("failed to destroy MXC netns '{ns_name}': {error}");
            return Some(format!("netns '{ns_name}': {error}"));
        }
        self.netns_name = None;
        None
    }

    fn cleanup_cgroup(&mut self) -> Option<String> {
        let cgroup = self.cgroup.clone()?;
        let path = cgroup.path().to_path_buf();
        if let Err(err) = cgroup.cleanup() {
            tracing::warn!("failed to remove MXC cgroup '{}': {err}", path.display());
            return Some(format!("cgroup '{}': {err}", path.display()));
        }
        self.cgroup = None;
        None
    }

    fn cleanup_for_start_failure(&mut self, error: SandboxError) -> SandboxError {
        self.cleanup_for_start_failure_with_netns_fd(None, error)
    }

    fn cleanup_for_start_failure_with_netns_fd(
        &mut self,
        netns_fd: Option<i32>,
        error: SandboxError,
    ) -> SandboxError {
        super::close_fd(netns_fd);
        self.config_file.take();
        self.seccomp_filter_file.take();
        let mut cleanup_errors = Vec::new();
        if let Some(error) = self.cleanup_netns() {
            cleanup_errors.push(format!("netns cleanup failed: {error}"));
        }
        if let Some(error) = self.cleanup_cgroup() {
            cleanup_errors.push(format!("cgroup cleanup failed: {error}"));
        }
        if let Err(error) = self.cleanup_tmpdir() {
            cleanup_errors.push(format!("tmpdir cleanup failed: {error}"));
        }
        append_cleanup_failure(
            error,
            (!cleanup_errors.is_empty()).then(|| cleanup_errors.join("; ")),
        )
    }

    fn create_cgroup_for_start(&mut self) -> Result<super::resources::CgroupHandle, String> {
        #[cfg(test)]
        if let Some(cgroup) = self.cgroup_override.take() {
            return Ok(cgroup);
        }

        super::resources::create_cgroup(self.id, &self.process_policy)
    }

    fn create_netns_for_start(&mut self, proxy_port: u16) -> Result<i32, String> {
        #[cfg(test)]
        if let Some(netns) = self.netns_override.take() {
            self.netns_name = Some(netns.name);
            self.netns_cleanup_result = Some(netns.cleanup);
            return Ok(netns.fd);
        }

        let name = super::netns::create_netns(self.id, proxy_port)?;
        self.netns_name = Some(name.clone());
        super::netns::enter_netns(&name)
            .map_err(|error| format!("cannot open fd for '{name}': {error}"))
    }
}

fn resolve_mxc_resource_strategy(
    policy: &axis_core::policy::ProcessPolicy,
) -> Result<super::strategy::ResourceStrategy, SandboxError> {
    let (resources, fallbacks) = super::strategy::build_resource_strategy(policy)
        .map_err(|err| SandboxError::IsolationFailed(format!("MXC Linux resources: {err}")))?;
    for fallback in fallbacks {
        tracing::debug!(
            "MXC Linux resource fallback for {}: {}",
            fallback.area,
            fallback.reason
        );
    }
    validate_mxc_resource_strategy(&resources)?;
    Ok(resources)
}

fn resolve_mxc_network_strategy(
    config: &SandboxConfig,
) -> Result<
    (
        super::strategy::NetworkStrategy,
        super::strategy::ProxyStrategy,
    ),
    SandboxError,
> {
    let (network, proxy) = match config.policy.network.mode {
        NetworkMode::Allow => {
            reject_endpoint_policies(&config.policy, "allow").map_err(|err| {
                SandboxError::IsolationFailed(format!("MXC Linux network: {err}"))
            })?;
            (
                super::strategy::NetworkStrategy::AllowHost,
                super::strategy::ProxyStrategy::None,
            )
        }
        NetworkMode::Block => {
            reject_endpoint_policies(&config.policy, "block").map_err(|err| {
                SandboxError::IsolationFailed(format!("MXC Linux network: {err}"))
            })?;
            (
                super::strategy::NetworkStrategy::BlockedBySeccomp,
                super::strategy::ProxyStrategy::None,
            )
        }
        NetworkMode::Proxy => super::strategy::build_strict_proxy_strategy(
            &config.policy,
            config.id,
            config.proxy_port,
            config.proxy_addr,
        )
        .map_err(|err| SandboxError::IsolationFailed(format!("MXC Linux network: {err}")))?,
    };

    validate_mxc_network_strategy(&config.policy, &network)?;
    Ok((network, proxy))
}

fn validate_mxc_network_strategy(
    policy: &Policy,
    network: &super::strategy::NetworkStrategy,
) -> Result<(), SandboxError> {
    let super::strategy::NetworkStrategy::Proxy { setup, .. } = network else {
        return Ok(());
    };

    if axis_core::connect_attribution::policy_requires_connect_attribution(policy) {
        return Err(SandboxError::IsolationFailed(
            "MXC Linux proxy mode: binary-restricted endpoint policies require connect-time attribution, which is not implemented for the MXC backend yet"
                .into(),
        ));
    }

    match setup {
        super::strategy::ProxyNetworkSetup::IpNetnsWithCapNetAdmin => Ok(()),
        super::strategy::ProxyNetworkSetup::AxisNetnsHelperLaunch => {
            Err(SandboxError::IsolationFailed(
                "MXC Linux proxy mode: axis-netns-helper launch cannot safely execute MXC configs yet; native CAP_NET_ADMIN network namespace setup is required"
                    .into(),
            ))
        }
    }
}

fn validate_mxc_resource_strategy(
    resources: &super::strategy::ResourceStrategy,
) -> Result<(), SandboxError> {
    if let super::strategy::ResourceStrategy::RlimitFallback {
        process_limit: super::strategy::ProcessLimitFallback::RlimitNprocWithDedicatedUser,
        ..
    } = resources
    {
        return Err(SandboxError::IsolationFailed(
            "MXC Linux resources: process-count rlimit fallback requires a safe MXC run_as_user path; writable cgroups v2 are required for process limits on the current MXC backend"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn no_resource_limits_strategy() -> super::strategy::ResourceStrategy {
    super::strategy::ResourceStrategy::RlimitFallback {
        memory_limit: false,
        process_limit: super::strategy::ProcessLimitFallback::NotRequested,
        cpu_limit: super::strategy::CpuLimitFallback::NotRequested,
    }
}

#[cfg(test)]
fn no_proxy_network_strategy() -> (
    super::strategy::NetworkStrategy,
    super::strategy::ProxyStrategy,
) {
    (
        super::strategy::NetworkStrategy::AllowHost,
        super::strategy::ProxyStrategy::None,
    )
}

impl SandboxImpl for MxcLinuxSandbox {
    fn start(&mut self) -> Result<u32, SandboxError> {
        if self.child.is_some() {
            return Err(SandboxError::SpawnFailed(
                "MXC Linux backend is already running".into(),
            ));
        }

        let allowed_proxy_env = allowed_proxy_env(&self.proxy_strategy);
        let config = match self
            .executor
            .write_private_config_with_allowed_env(&self.spec, &allowed_proxy_env)
        {
            Ok(config) => config,
            Err(err) => {
                return Err(
                    self.cleanup_for_start_failure(SandboxError::IsolationFailed(format!(
                        "MXC config: {err}"
                    ))),
                );
            }
        };
        let prepared_rlimits =
            match super::prepare_rlimits_for_plan(&self.process_policy, &self.resource_strategy) {
                Ok(limits) => limits,
                Err(err) => {
                    return Err(
                        self.cleanup_for_start_failure(SandboxError::IsolationFailed(format!(
                            "MXC resource limits: {err}"
                        ))),
                    );
                }
            };

        if matches!(
            self.resource_strategy,
            super::strategy::ResourceStrategy::CgroupsV2 { .. }
        ) {
            match self.create_cgroup_for_start() {
                Ok(cgroup) => self.cgroup = Some(cgroup),
                Err(err) => {
                    return Err(
                        self.cleanup_for_start_failure(SandboxError::IsolationFailed(format!(
                            "MXC cgroup: creation failed: {err}"
                        ))),
                    );
                }
            }
        }

        let cgroup_procs_fd = match &self.cgroup {
            Some(cgroup) => match cgroup.open_procs_fd() {
                Ok(fd) => Some(fd),
                Err(err) => {
                    return Err(
                        self.cleanup_for_start_failure(SandboxError::IsolationFailed(format!(
                            "MXC cgroup: cannot open procs: {err}"
                        ))),
                    );
                }
            },
            None => None,
        };

        let netns_fd = match &self.network_strategy {
            super::strategy::NetworkStrategy::Proxy {
                setup: super::strategy::ProxyNetworkSetup::IpNetnsWithCapNetAdmin,
                proxy_port,
                ..
            } => match self.create_netns_for_start(*proxy_port) {
                Ok(fd) => Some(fd),
                Err(err) => {
                    super::close_fd(cgroup_procs_fd);
                    return Err(
                        self.cleanup_for_start_failure(SandboxError::IsolationFailed(format!(
                            "MXC netns: creation failed: {err}"
                        ))),
                    );
                }
            },
            super::strategy::NetworkStrategy::Proxy {
                setup: super::strategy::ProxyNetworkSetup::AxisNetnsHelperLaunch,
                ..
            } => {
                super::close_fd(cgroup_procs_fd);
                return Err(
                    self.cleanup_for_start_failure(SandboxError::IsolationFailed(
                        "MXC netns: axis-netns-helper launch is not implemented for MXC".into(),
                    )),
                );
            }
            _ => None,
        };

        let mut command = Command::new(self.executor.path());
        command
            .arg("--experimental")
            .arg("--config")
            .arg(config.path())
            .current_dir(&self.workspace_dir)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C");

        if self.capture_output {
            command.stdin(Stdio::null());
            let stdout = match File::create(self.workspace_dir.join("stdout.log")) {
                Ok(stdout) => stdout,
                Err(err) => {
                    super::close_fd(cgroup_procs_fd);
                    return Err(self.cleanup_for_start_failure_with_netns_fd(
                        netns_fd,
                        SandboxError::SpawnFailed(format!("stdout log: {err}")),
                    ));
                }
            };
            let stderr = match File::create(self.workspace_dir.join("stderr.log")) {
                Ok(stderr) => stderr,
                Err(err) => {
                    super::close_fd(cgroup_procs_fd);
                    return Err(self.cleanup_for_start_failure_with_netns_fd(
                        netns_fd,
                        SandboxError::SpawnFailed(format!("stderr log: {err}")),
                    ));
                }
            };
            command.stdout(Stdio::from(stdout));
            command.stderr(Stdio::from(stderr));
        }

        let mut child_error_pipe = match super::ChildSetupErrorPipe::new() {
            Ok(pipe) => pipe,
            Err(err) => {
                super::close_fd(cgroup_procs_fd);
                return Err(self.cleanup_for_start_failure_with_netns_fd(
                    netns_fd,
                    SandboxError::SpawnFailed(format!("child setup error pipe: {err}")),
                ));
            }
        };
        let child_error_write_fd = child_error_pipe.write_fd;
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, 0) < 0 {
                    return Err(super::child_setup_error(
                        child_error_write_fd,
                        super::ChildSetupErrorKind::SetProcessGroup,
                        super::current_errno(),
                    ));
                }

                if let Some(fd) = cgroup_procs_fd {
                    if let Err(errno) = super::enter_cgroup_from_child_fd(fd) {
                        libc::close(fd);
                        return Err(super::child_setup_error(
                            child_error_write_fd,
                            super::ChildSetupErrorKind::EnterCgroup,
                            errno,
                        ));
                    }
                    libc::close(fd);
                }

                if let Some(fd) = netns_fd {
                    let ret = libc::setns(fd, libc::CLONE_NEWNET);
                    libc::close(fd);
                    if ret < 0 {
                        return Err(super::child_setup_error(
                            child_error_write_fd,
                            super::ChildSetupErrorKind::EnterNetworkNamespace,
                            super::current_errno(),
                        ));
                    }
                }

                if let Some(limits) = prepared_rlimits
                    && let Err(errno) = super::apply_prepared_rlimits(limits)
                {
                    return Err(super::child_setup_error(
                        child_error_write_fd,
                        super::ChildSetupErrorKind::ApplyResourceLimits,
                        errno,
                    ));
                }

                Ok(())
            });
        }

        let child = match command.spawn() {
            Ok(child) => {
                super::close_fd(netns_fd);
                super::close_fd(cgroup_procs_fd);
                drop(child_error_pipe);
                child
            }
            Err(err) => {
                super::close_fd(cgroup_procs_fd);
                let err = match super::spawn_error(err, &mut child_error_pipe) {
                    SandboxError::IsolationFailed(message) => {
                        SandboxError::IsolationFailed(format!("MXC executor setup: {message}"))
                    }
                    SandboxError::SpawnFailed(message) => {
                        SandboxError::SpawnFailed(format!("MXC executor: {message}"))
                    }
                    other => other,
                };
                return Err(self.cleanup_for_start_failure_with_netns_fd(netns_fd, err));
            }
        };
        let pid = child.id();
        self.config_file = Some(config);
        self.child = Some(child);
        tracing::info!(
            "sandbox {} started via MXC Linux backend, pid={pid}",
            self.id
        );
        Ok(pid)
    }

    fn wait(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<i32, SandboxError>> + Send + '_>>
    {
        Box::pin(async {
            if let Some(code) = self.exit_code {
                self.cleanup_after_stop()?;
                return Ok(code);
            }

            let child = self
                .child
                .take()
                .ok_or_else(|| SandboxError::SpawnFailed("no MXC child process".into()))?;
            let pid = child.id() as i32;
            let status = match wait_runtime_child_with_timeout(child, self.timeout_sec).await {
                Ok(status) => status,
                Err(err) => {
                    self.exit_code = Some(-1);
                    kill_process_group(pid);
                    if let Err(cleanup_error) = self.cleanup_after_stop() {
                        return Err(SandboxError::IsolationFailed(format!(
                            "process cleanup failed after wait error {err}: {cleanup_error}"
                        )));
                    }
                    return Err(SandboxError::Io(err));
                }
            };
            let code = status.code().unwrap_or(-1);
            self.exit_code = Some(code);
            kill_process_group(pid);
            self.cleanup_after_stop()?;
            Ok(code)
        })
    }

    fn try_wait(&mut self) -> Result<Option<i32>, SandboxError> {
        if let Some(code) = self.exit_code {
            self.cleanup_after_stop()?;
            return Ok(Some(code));
        }

        let Some(child) = self.child.as_mut() else {
            return Err(SandboxError::SpawnFailed("no MXC child process".into()));
        };
        let Some(status) = child.try_wait()? else {
            return Ok(None);
        };

        let pid = child.id() as i32;
        self.child.take();
        let code = status.code().unwrap_or(-1);
        self.exit_code = Some(code);
        kill_process_group(pid);
        self.cleanup_after_stop()?;
        Ok(Some(code))
    }

    fn destroy(&mut self) -> Result<(), SandboxError> {
        if let Some(mut child) = self.child.take() {
            let pid = child.id() as i32;
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::kill(-pid, libc::SIGKILL);
            }
            self.exit_code = Some(wait_for_killed_child(&mut child, pid));
            kill_process_group(pid);
        }
        self.cleanup_after_stop()?;
        tracing::info!("sandbox {} destroyed via MXC Linux backend", self.id);
        Ok(())
    }
}

impl MxcExecutionSpec {
    pub fn from_sandbox_config(config: &SandboxConfig) -> Result<Self, MxcTranslationError> {
        Self::from_sandbox_config_with_network_mode(config, MxcNetworkTranslationMode::Standalone)
    }

    fn from_sandbox_config_with_network_mode(
        config: &SandboxConfig,
        network_mode: MxcNetworkTranslationMode,
    ) -> Result<Self, MxcTranslationError> {
        let translated = translate_sandbox_config_with_metadata(config, network_mode)?;
        validate_current_bubblewrap_filesystem_substrate(
            translated.root_read_substrate_acknowledged,
        )?;
        Ok(translated.spec)
    }
}

#[cfg(test)]
fn translate_sandbox_config(
    config: &SandboxConfig,
) -> Result<MxcExecutionSpec, MxcTranslationError> {
    Ok(translate_sandbox_config_with_metadata(config, MxcNetworkTranslationMode::Standalone)?.spec)
}

#[cfg(test)]
pub(crate) fn translate_sandbox_config_for_test(
    config: &SandboxConfig,
) -> Result<MxcExecutionSpec, MxcTranslationError> {
    translate_sandbox_config(config)
}

struct MxcTranslatedConfig {
    spec: MxcExecutionSpec,
    root_read_substrate_acknowledged: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MxcNetworkTranslationMode {
    Standalone,
    StrictProxyEnforcedByAxis,
}

struct MxcTranslatedFilesystem {
    filesystem: MxcFilesystem,
    root_read_substrate_acknowledged: bool,
}

fn translate_sandbox_config_with_metadata(
    config: &SandboxConfig,
    network_mode: MxcNetworkTranslationMode,
) -> Result<MxcTranslatedConfig, MxcTranslationError> {
    let process = translate_process(config)?;
    let network = translate_network(&config.policy, network_mode)?;
    let filesystem = translate_filesystem(&config.policy.filesystem, &config.workspace_dir)?;

    Ok(MxcTranslatedConfig {
        spec: MxcExecutionSpec {
            version: MXC_SCHEMA_VERSION.into(),
            platform: MXC_LINUX_PLATFORM.into(),
            containment: MXC_BUBBLEWRAP_CONTAINMENT.into(),
            process,
            filesystem: filesystem.filesystem,
            network,
        },
        root_read_substrate_acknowledged: filesystem.root_read_substrate_acknowledged,
    })
}

fn validate_current_bubblewrap_filesystem_substrate(
    root_read_substrate_acknowledged: bool,
) -> Result<(), MxcTranslationError> {
    if root_read_substrate_acknowledged {
        Ok(())
    } else {
        Err(MxcTranslationError::FilesystemDefaultDenyUnsupported)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MxcProcess {
    #[serde(rename = "commandLine")]
    pub command_line: String,
    pub cwd: String,
    pub env: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MxcFilesystem {
    #[serde(rename = "readwritePaths")]
    pub readwrite_paths: Vec<String>,
    #[serde(rename = "readonlyPaths")]
    pub readonly_paths: Vec<String>,
    #[serde(rename = "deniedPaths")]
    pub denied_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MxcNetwork {
    #[serde(rename = "defaultPolicy")]
    pub default_policy: MxcNetworkDefaultPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MxcNetworkDefaultPolicy {
    Allow,
    Block,
}

fn translate_process(config: &SandboxConfig) -> Result<MxcProcess, MxcTranslationError> {
    if config.command.is_empty() {
        return Err(MxcTranslationError::EmptyCommand);
    }

    let cwd = config
        .working_dir
        .as_deref()
        .unwrap_or(&config.workspace_dir)
        .to_path_buf();

    Ok(MxcProcess {
        command_line: shell_command_line(&config.command, &config.args),
        cwd: path_to_string(&cwd)?,
        env: translate_env(&config.env)?,
        timeout: translate_timeout(config.timeout_sec.or(config.policy.process.timeout_sec))?,
    })
}

fn translate_filesystem(
    policy: &FilesystemPolicy,
    workspace: &Path,
) -> Result<MxcTranslatedFilesystem, MxcTranslationError> {
    let expanded = super::landlock::expand_filesystem_policy(policy, workspace)
        .map_err(MxcTranslationError::Filesystem)?;
    let workspace = std::fs::canonicalize(workspace).map_err(|e| {
        MxcTranslationError::Filesystem(format!(
            "workspace '{}' cannot be canonicalized: {e}",
            workspace.display()
        ))
    })?;
    validate_mxc_filesystem_overlays(&expanded, &workspace)
        .map_err(MxcTranslationError::Filesystem)?;
    let root_read_substrate_acknowledged =
        expanded_paths_grant_root_read(&expanded.read_only, &expanded.read_write);
    let mut readwrite_paths = represented_paths(policy, &expanded.read_write)?;
    push_unique(&mut readwrite_paths, path_to_string(&workspace)?);
    let mut readonly_paths = represented_paths(policy, &expanded.read_only)?;
    readonly_paths.retain(|path| Path::new(path) != Path::new("/"));

    Ok(MxcTranslatedFilesystem {
        filesystem: MxcFilesystem {
            readwrite_paths,
            readonly_paths,
            denied_paths: represented_paths(policy, &expanded.deny)?,
        },
        root_read_substrate_acknowledged,
    })
}

fn represented_paths(
    policy: &FilesystemPolicy,
    paths: &[super::landlock::ExpandedPath],
) -> Result<Vec<String>, MxcTranslationError> {
    let mut represented = Vec::new();

    for path in paths {
        let required =
            path.required || matches!(policy.compatibility, Compatibility::HardRequirement);

        if path.mount_path != path.path {
            if required {
                return Err(MxcTranslationError::Filesystem(format!(
                    "required path '{}' resolves to '{}' but MXC config cannot represent a distinct mount alias '{}'",
                    path.original,
                    path.path.display(),
                    path.mount_path.display()
                )));
            }
            continue;
        }

        if !path.path.exists() && !required {
            continue;
        }

        if !path.path.exists() {
            return Err(MxcTranslationError::Filesystem(format!(
                "required path '{}' does not exist after expansion to '{}'",
                path.original,
                path.path.display()
            )));
        }

        represented.push(path_to_string(&path.path)?);
    }

    Ok(represented)
}

fn push_unique(paths: &mut Vec<String>, path: String) {
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

fn validate_mxc_filesystem_overlays(
    policy: &super::landlock::ExpandedFilesystemPolicy,
    workspace: &Path,
) -> Result<(), String> {
    for read_only in &policy.read_only {
        for read_write in &policy.read_write {
            if read_only.path == read_write.path {
                return Err(format!(
                    "read-only path '{}' expanded to '{}' also appears as read-write path '{}' expanded to '{}'; this filesystem policy is ambiguous under MXC Bubblewrap overlays",
                    read_only.original,
                    read_only.path.display(),
                    read_write.original,
                    read_write.path.display()
                ));
            }

            if read_only.path != Path::new("/")
                && path_contains_or_equal(&read_only.path, &read_write.path)
            {
                return Err(format!(
                    "read-only path '{}' expanded to '{}' contains read-write path '{}' expanded to '{}'; current MXC Bubblewrap overlay order would shadow the read-write grant",
                    read_only.original,
                    read_only.path.display(),
                    read_write.original,
                    read_write.path.display()
                ));
            }
        }
    }

    for deny in &policy.deny {
        if path_contains_or_equal(workspace, &deny.path)
            || path_contains_or_equal(&deny.path, workspace)
        {
            return Err(format!(
                "deny path '{}' expanded to '{}' conflicts with the sandbox workspace '{}'",
                deny.original,
                deny.path.display(),
                workspace.display()
            ));
        }

        for allowed in policy.read_only.iter().chain(policy.read_write.iter()) {
            if path_contains_or_equal(&deny.path, &allowed.path) {
                return Err(format!(
                    "deny path '{}' expanded to '{}' contains allowed path '{}' expanded to '{}'; this filesystem policy is ambiguous under MXC Bubblewrap overlays",
                    deny.original,
                    deny.path.display(),
                    allowed.original,
                    allowed.path.display()
                ));
            }
        }
    }
    Ok(())
}

fn expanded_paths_grant_root_read(
    read_only: &[super::landlock::ExpandedPath],
    read_write: &[super::landlock::ExpandedPath],
) -> bool {
    read_only
        .iter()
        .chain(read_write.iter())
        .any(|path| path.path == Path::new("/"))
}

fn path_contains_or_equal(parent: &Path, child: &Path) -> bool {
    child == parent || child.starts_with(parent)
}

fn prepare_mxc_seccomp_launch<F>(
    config: &SandboxConfig,
    spec: &mut MxcExecutionSpec,
    resolve_seccomp_launcher: F,
) -> Result<tempfile::NamedTempFile, SandboxError>
where
    F: FnOnce() -> Result<MxcSeccompLauncher, SandboxError>,
{
    let filter = super::seccomp::prepare_seccomp_with_options(
        &config.policy.process,
        mxc_seccomp_options_for_policy(&config.policy),
    )
    .map_err(SandboxError::IsolationFailed)?;
    let seccomp_launcher = resolve_seccomp_launcher()?;
    let filter_file = write_private_seccomp_filter(&filter)?;
    let filter_path = path_to_string(filter_file.path())
        .map_err(|err| SandboxError::IsolationFailed(format!("MXC seccomp filter path: {err}")))?;
    let launcher_path = path_to_string(seccomp_launcher.path()).map_err(|err| {
        SandboxError::IsolationFailed(format!("MXC seccomp launcher path: {err}"))
    })?;

    ensure_seccomp_support_path_not_denied(&spec.filesystem, "launcher", &launcher_path)?;
    ensure_seccomp_support_path_not_denied(&spec.filesystem, "filter", &filter_path)?;
    push_unique(&mut spec.filesystem.readonly_paths, launcher_path.clone());
    push_unique(&mut spec.filesystem.readonly_paths, filter_path.clone());
    spec.process.command_line =
        seccomp_launcher_command_line(&launcher_path, &filter_path, &config.command, &config.args);

    Ok(filter_file)
}

fn ensure_seccomp_support_path_not_denied(
    filesystem: &MxcFilesystem,
    label: &str,
    path: &str,
) -> Result<(), SandboxError> {
    let path = Path::new(path);
    for denied in &filesystem.denied_paths {
        let denied = Path::new(denied);
        if path_contains_or_equal(denied, path) {
            return Err(SandboxError::IsolationFailed(format!(
                "MXC seccomp {label} path '{}' is covered by denied path '{}'",
                path.display(),
                denied.display()
            )));
        }
    }
    Ok(())
}

fn mxc_seccomp_options_for_policy(policy: &Policy) -> super::seccomp::SeccompOptions {
    match policy.network.mode {
        NetworkMode::Block => super::seccomp::SeccompOptions::deny_network_socket_domains(),
        NetworkMode::Allow | NetworkMode::Proxy => super::seccomp::SeccompOptions::default(),
    }
}

fn write_private_seccomp_filter(
    filter: &super::seccomp::PreparedSeccompFilter,
) -> Result<tempfile::NamedTempFile, SandboxError> {
    let mut file = tempfile::Builder::new()
        .prefix("axis-mxc-seccomp-")
        .suffix(".bpf")
        .tempfile()
        .map_err(|err| SandboxError::IsolationFailed(format!("MXC seccomp filter: {err}")))?;
    file.write_all(&filter.export_bpf_bytes())
        .map_err(|err| SandboxError::IsolationFailed(format!("MXC seccomp filter: {err}")))?;
    file.flush()
        .map_err(|err| SandboxError::IsolationFailed(format!("MXC seccomp filter: {err}")))?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))
        .map_err(|err| SandboxError::IsolationFailed(format!("MXC seccomp filter: {err}")))?;
    Ok(file)
}

fn seccomp_launcher_command_line(
    launcher_path: &str,
    filter_path: &str,
    command: &str,
    args: &[String],
) -> String {
    [
        shell_quote_arg(launcher_path),
        "--filter".into(),
        shell_quote_arg(filter_path),
        "--".into(),
    ]
    .into_iter()
    .chain(std::iter::once(shell_quote_arg(command)))
    .chain(args.iter().map(|arg| shell_quote_arg(arg)))
    .collect::<Vec<_>>()
    .join(" ")
}

fn mxc_network_translation_mode(
    network: &super::strategy::NetworkStrategy,
) -> MxcNetworkTranslationMode {
    if matches!(network, super::strategy::NetworkStrategy::Proxy { .. }) {
        MxcNetworkTranslationMode::StrictProxyEnforcedByAxis
    } else {
        MxcNetworkTranslationMode::Standalone
    }
}

fn translate_network(
    policy: &Policy,
    mode: MxcNetworkTranslationMode,
) -> Result<MxcNetwork, MxcTranslationError> {
    let default_policy = match policy.network.mode {
        NetworkMode::Allow => {
            reject_endpoint_policies(policy, "allow")?;
            MxcNetworkDefaultPolicy::Allow
        }
        NetworkMode::Block => {
            reject_endpoint_policies(policy, "block")?;
            MxcNetworkDefaultPolicy::Block
        }
        NetworkMode::Proxy if mode == MxcNetworkTranslationMode::Standalone => {
            return Err(MxcTranslationError::ProxyModeUnsupported(
                "MXC Bubblewrap proxy mode is cooperative env-var routing and does not preserve AXIS strict proxy isolation".into(),
            ));
        }
        NetworkMode::Proxy => MxcNetworkDefaultPolicy::Allow,
    };

    Ok(MxcNetwork { default_policy })
}

fn reject_endpoint_policies(
    policy: &Policy,
    mode: &'static str,
) -> Result<(), MxcTranslationError> {
    if policy.network.policies.is_empty() {
        Ok(())
    } else {
        Err(MxcTranslationError::EndpointPoliciesInNonProxyMode { mode })
    }
}

fn translate_env(env: &[(String, String)]) -> Result<Vec<String>, MxcTranslationError> {
    let mut filtered = env.to_vec();
    axis_core::sandbox_env::retain_linux_sandbox_env(&mut filtered);

    filtered
        .into_iter()
        .map(|(key, value)| {
            if key.is_empty() || key.contains('=') || key.contains('\0') {
                return Err(MxcTranslationError::InvalidEnv(key));
            }
            if value.contains('\0') {
                return Err(MxcTranslationError::InvalidEnv(key));
            }
            Ok(format!("{key}={value}"))
        })
        .collect()
}

fn apply_proxy_env_to_spec(spec: &mut MxcExecutionSpec, proxy: &super::strategy::ProxyStrategy) {
    let super::strategy::ProxyStrategy::Required {
        sandbox_addr, port, ..
    } = proxy
    else {
        return;
    };

    spec.process.env.retain(|entry| {
        entry
            .split_once('=')
            .map(|(key, _)| !axis_core::sandbox_env::is_proxy_env_key(key))
            .unwrap_or(true)
    });
    spec.process.env.extend(
        super::proxy_env_vars(sandbox_addr, *port)
            .into_iter()
            .map(|(key, value)| format!("{key}={value}")),
    );
}

fn allowed_proxy_env(proxy: &super::strategy::ProxyStrategy) -> Vec<(String, String)> {
    let super::strategy::ProxyStrategy::Required {
        sandbox_addr, port, ..
    } = proxy
    else {
        return Vec::new();
    };

    super::proxy_env_vars(sandbox_addr, *port)
}

fn translate_timeout(timeout_sec: Option<u64>) -> Result<Option<u32>, MxcTranslationError> {
    let Some(seconds) = timeout_sec else {
        return Ok(None);
    };
    let millis = seconds
        .checked_mul(1000)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(MxcTranslationError::TimeoutOverflow { seconds })?;
    Ok(Some(millis))
}

fn shell_command_line(command: &str, args: &[String]) -> String {
    std::iter::once(command)
        .chain(args.iter().map(String::as_str))
        .map(shell_quote_arg)
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote_arg(arg: &str) -> String {
    if !arg.is_empty()
        && arg.bytes().all(|byte| {
            matches!(
                byte,
                b'a'..=b'z'
                    | b'A'..=b'Z'
                    | b'0'..=b'9'
                    | b'_'
                    | b'-'
                    | b'.'
                    | b'/'
                    | b':'
                    | b','
                    | b'='
                    | b'+'
                    | b'@'
                    | b'%'
            )
        })
    {
        return arg.to_string();
    }

    let mut quoted = String::from("'");
    for ch in arg.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

fn path_to_string(path: &Path) -> Result<String, MxcTranslationError> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| MxcTranslationError::NonUtf8Path(path.display().to_string()))
}

fn production_executor_candidates() -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();

    for dir in MXC_EXECUTOR_DIRS {
        push_candidate(
            &mut candidates,
            &mut seen,
            Path::new(dir).join(MXC_EXECUTOR_NAME),
        );
    }

    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            if dir.as_os_str().is_empty() || !dir.is_absolute() {
                continue;
            }
            push_candidate(&mut candidates, &mut seen, dir.join(MXC_EXECUTOR_NAME));
        }
    }

    candidates
}

fn production_seccomp_launcher_candidates() -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();

    for dir in AXIS_SECCOMP_LAUNCHER_DIRS {
        push_candidate(
            &mut candidates,
            &mut seen,
            Path::new(dir).join(AXIS_SECCOMP_LAUNCHER_NAME),
        );
    }

    if let Ok(current_exe) = std::env::current_exe()
        && let Some(dir) = current_exe.parent()
    {
        push_candidate(
            &mut candidates,
            &mut seen,
            dir.join(AXIS_SECCOMP_LAUNCHER_NAME),
        );
        if dir.file_name().is_some_and(|name| name == "deps")
            && let Some(parent) = dir.parent()
        {
            push_candidate(
                &mut candidates,
                &mut seen,
                parent.join(AXIS_SECCOMP_LAUNCHER_NAME),
            );
        }
    }

    candidates
}

fn push_candidate(candidates: &mut Vec<PathBuf>, seen: &mut HashSet<PathBuf>, candidate: PathBuf) {
    if seen.insert(candidate.clone()) {
        candidates.push(candidate);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutorPathMode {
    Production,
    #[allow(dead_code)]
    TestInjected,
}

fn validate_executor_path(
    path: &Path,
    validation_mode: ExecutorPathMode,
) -> Result<(), MxcExecutorError> {
    validate_safe_executable_path(path, validation_mode)
        .map_err(|reason| unsafe_candidate(path, reason))
}

fn validate_safe_executable_path(
    path: &Path,
    validation_mode: ExecutorPathMode,
) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("path must be absolute".into());
    }

    // SAFETY: geteuid(2) has no preconditions and only reads process state.
    let trusted_uid = unsafe { libc::geteuid() };
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|err| {
            if current == path && err.kind() == std::io::ErrorKind::NotFound {
                "candidate does not exist".to_string()
            } else {
                format!("could not inspect '{}': {err}", current.display())
            }
        })?;

        if metadata.file_type().is_symlink() {
            return Err(format!(
                "path component '{}' is a symlink",
                current.display()
            ));
        }
        let mode_bits = metadata.permissions().mode();
        let uid = metadata.uid();
        let injected_sticky_ancestor = current != path
            && metadata.is_dir()
            && allows_sticky_writable_ancestor(mode_bits, validation_mode);
        if current != Path::new("/") && uid != 0 && uid != trusted_uid && !injected_sticky_ancestor
        {
            return Err(format!(
                "path component '{}' is not owned by root or the current user",
                current.display()
            ));
        }

        if current == path {
            if !metadata.is_file() {
                return Err("candidate is not a regular file".into());
            }
            if mode_bits & 0o111 == 0 {
                return Err("candidate is not executable".into());
            }
            if mode_bits & 0o022 != 0 {
                return Err(format!(
                    "path component '{}' is group- or world-writable",
                    current.display()
                ));
            }
        } else if !metadata.is_dir() {
            return Err(format!(
                "path component '{}' is not a directory",
                current.display()
            ));
        } else if mode_bits & 0o022 != 0
            && !allows_sticky_writable_ancestor(mode_bits, validation_mode)
        {
            return Err(format!(
                "path component '{}' is group- or world-writable",
                current.display()
            ));
        }
    }

    Ok(())
}

fn allows_sticky_writable_ancestor(mode_bits: u32, validation_mode: ExecutorPathMode) -> bool {
    matches!(validation_mode, ExecutorPathMode::TestInjected) && mode_bits & 0o1000 != 0
}

fn unsafe_candidate(path: &Path, reason: impl Into<String>) -> MxcExecutorError {
    MxcExecutorError::UnsafeCandidate {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

fn validate_spec_env_for_launch(
    spec: &MxcExecutionSpec,
    allowed_proxy_env: &[(String, String)],
) -> Result<(), MxcExecutorError> {
    let mut parsed = Vec::with_capacity(spec.process.env.len());
    for entry in &spec.process.env {
        let Some((key, value)) = entry.split_once('=') else {
            return Err(MxcExecutorError::MalformedEnv);
        };
        parsed.push((key.to_string(), value.to_string()));
    }

    let original = parsed.clone();
    let mut retained = parsed;
    axis_core::sandbox_env::retain_linux_sandbox_env(&mut retained);
    let mut allowed_proxy_env = allowed_proxy_env.to_vec();

    for (key, value) in &original {
        if take_env_match(&mut retained, key, value)
            || take_env_match(&mut allowed_proxy_env, key, value)
        {
            continue;
        }
        return Err(MxcExecutorError::FilteredEnv { key: key.clone() });
    }

    Ok(())
}

fn take_env_match(entries: &mut Vec<(String, String)>, key: &str, value: &str) -> bool {
    let Some(index) = entries
        .iter()
        .position(|(entry_key, entry_value)| entry_key == key && entry_value == value)
    else {
        return false;
    };
    entries.remove(index);
    true
}

fn wait_child_with_timeout(
    mut child: Child,
    timeout: Duration,
) -> Result<ExitStatus, MxcExecutorError> {
    let started = Instant::now();
    let process_group = child.id() as i32;

    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| MxcExecutorError::Spawn(err.to_string()))?
        {
            return Ok(status);
        }

        if started.elapsed() >= timeout {
            if process_group > 0 {
                kill_process_group_until_stopped(process_group, Duration::from_millis(500));
            }
            let _ = child.kill();
            let _ = child.wait();
            if process_group > 0 {
                kill_process_group_until_stopped(process_group, Duration::from_millis(500));
            }
            return Err(MxcExecutorError::Timeout {
                timeout_ms: timeout.as_millis(),
            });
        }

        thread::sleep(Duration::from_millis(10));
    }
}

fn read_limited_output(file: &mut File) -> Result<String, MxcExecutorError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|err| MxcExecutorError::ConfigIo(err.to_string()))?;
    let mut bytes = Vec::new();
    file.take(MAX_DRY_RUN_OUTPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| MxcExecutorError::ConfigIo(err.to_string()))?;

    if bytes.len() > MAX_DRY_RUN_OUTPUT_BYTES as usize {
        bytes.truncate(MAX_DRY_RUN_OUTPUT_BYTES as usize);
    }

    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn cleanup_tmpdir_on_setup_failure(workspace: &Path, tmpdir_active: bool) -> Option<String> {
    if !tmpdir_active {
        return None;
    }
    super::landlock::cleanup_tmpdir(workspace).err()
}

fn append_cleanup_failure(error: SandboxError, cleanup_error: Option<String>) -> SandboxError {
    let Some(cleanup_error) = cleanup_error else {
        return error;
    };
    match error {
        SandboxError::IsolationFailed(message) => {
            SandboxError::IsolationFailed(format!("{message}; cleanup failed: {cleanup_error}"))
        }
        SandboxError::SpawnFailed(message) => {
            SandboxError::SpawnFailed(format!("{message}; cleanup failed: {cleanup_error}"))
        }
        other => other,
    }
}

async fn wait_runtime_child_with_timeout(
    mut child: Child,
    timeout_sec: Option<u64>,
) -> Result<ExitStatus, io::Error> {
    let pid = child.id() as i32;
    let mut wait_task = tokio::task::spawn_blocking(move || child.wait());

    let Some(timeout_sec) = timeout_sec else {
        return join_child_wait(wait_task.await);
    };

    let timeout = tokio::time::sleep(Duration::from_secs(timeout_sec));
    tokio::pin!(timeout);
    tokio::select! {
        result = &mut wait_task => join_child_wait(result),
        _ = &mut timeout => {
            tracing::warn!("MXC sandbox child pid={pid} exceeded timeout of {timeout_sec}s");
            kill_process_group_until_stopped(pid, Duration::from_millis(500));
            let reap_grace = Duration::from_secs(POST_TIMEOUT_REAP_GRACE_SEC);
            match tokio::time::timeout(reap_grace, &mut wait_task).await {
                Ok(result) => {
                    kill_process_group_until_stopped(pid, Duration::from_millis(500));
                    join_child_wait(result)
                }
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "MXC child pid={pid} did not exit within {POST_TIMEOUT_REAP_GRACE_SEC}s after SIGKILL"
                    ),
                )),
            }
        }
    }
}

fn join_child_wait(
    result: Result<Result<ExitStatus, io::Error>, tokio::task::JoinError>,
) -> Result<ExitStatus, io::Error> {
    result.map_err(|err| io::Error::other(format!("wait task: {err}")))?
}

fn wait_for_killed_child(child: &mut Child, pid: i32) -> i32 {
    let deadline = Instant::now() + Duration::from_secs(POST_TIMEOUT_REAP_GRACE_SEC);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.code().unwrap_or(-1),
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                tracing::warn!(
                    "MXC sandbox child pid={pid} did not exit within {POST_TIMEOUT_REAP_GRACE_SEC}s after destroy SIGKILL"
                );
                return -1;
            }
            Err(err) => {
                tracing::warn!("MXC sandbox child pid={pid}: wait after destroy failed: {err}");
                return -1;
            }
        }
    }
}

fn kill_process_group(pid: i32) {
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
        while libc::waitpid(-pid, std::ptr::null_mut(), libc::WNOHANG) > 0 {}
    }
}

fn kill_process_group_until_stopped(pid: i32, grace: Duration) {
    let deadline = Instant::now() + grace;
    loop {
        kill_process_group(pid);
        if !process_group_exists(pid) || Instant::now() >= deadline {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn process_group_exists(pid: i32) -> bool {
    let ret = unsafe { libc::kill(-pid, 0) };
    ret == 0 || io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::{resources, strategy};
    use axis_core::policy::{
        Access, BinaryMatch, Endpoint, EndpointPolicy, FilesystemPolicy, GpuPolicy,
        InferencePolicy, NetworkPolicy, ProcessPolicy, SshPolicy,
    };
    use axis_core::types::SandboxId;
    use std::ffi::OsString;
    use std::net::{Ipv4Addr, TcpListener};
    use std::os::fd::IntoRawFd;
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};

    fn policy(network_mode: NetworkMode) -> Policy {
        Policy {
            version: 1,
            name: "test".into(),
            filesystem: FilesystemPolicy::default(),
            process: ProcessPolicy::default(),
            network: NetworkPolicy {
                mode: network_mode,
                policies: Vec::new(),
            },
            inference: InferencePolicy::default(),
            gpu: GpuPolicy::default(),
            ssh: SshPolicy::default(),
            amd: None,
        }
    }

    fn config(policy: Policy, workspace: PathBuf) -> SandboxConfig {
        SandboxConfig {
            id: SandboxId::new(),
            policy,
            command: "/usr/bin/python3".into(),
            args: vec!["-c".into(), "print('hello world')".into()],
            working_dir: None,
            workspace_dir: workspace,
            env: vec![
                ("PATH".into(), "/usr/bin".into()),
                ("CUSTOM".into(), "kept".into()),
                ("ANTHROPIC_API_KEY".into(), "secret".into()),
                ("HTTPS_PROXY".into(), "http://proxy-with-creds".into()),
            ],
            proxy_port: 0,
            proxy_addr: None,
            connect_attribution: None,
            capture_output: true,
            timeout_sec: None,
        }
    }

    #[test]
    fn allow_mode_maps_to_mxc_allow_policy() {
        let workspace = tempfile::tempdir().unwrap();
        let spec = translate_sandbox_config(&config(
            policy(NetworkMode::Allow),
            workspace.path().to_path_buf(),
        ))
        .unwrap();

        assert_eq!(spec.version, MXC_SCHEMA_VERSION);
        assert_eq!(spec.platform, MXC_LINUX_PLATFORM);
        assert_eq!(spec.containment, MXC_BUBBLEWRAP_CONTAINMENT);
        assert_eq!(spec.network.default_policy, MxcNetworkDefaultPolicy::Allow);
    }

    #[test]
    fn block_mode_maps_to_mxc_block_policy() {
        let workspace = tempfile::tempdir().unwrap();
        let spec = translate_sandbox_config(&config(
            policy(NetworkMode::Block),
            workspace.path().to_path_buf(),
        ))
        .unwrap();

        assert_eq!(spec.network.default_policy, MxcNetworkDefaultPolicy::Block);
    }

    #[test]
    fn full_bubblewrap_spec_fails_closed_until_filesystem_default_deny_is_supported() {
        let workspace = tempfile::tempdir().unwrap();

        let err = MxcExecutionSpec::from_sandbox_config(&config(
            policy(NetworkMode::Block),
            workspace.path().into(),
        ))
        .unwrap_err();

        assert_eq!(err, MxcTranslationError::FilesystemDefaultDenyUnsupported);
        assert!(err.to_string().contains("host root read-only"));
    }

    #[test]
    fn endpoint_policies_are_rejected_in_non_proxy_modes() {
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = policy(NetworkMode::Allow);
        policy.network.policies.push(endpoint_policy());

        let err = MxcExecutionSpec::from_sandbox_config(&config(policy, workspace.path().into()))
            .unwrap_err();

        assert_eq!(
            err,
            MxcTranslationError::EndpointPoliciesInNonProxyMode { mode: "allow" }
        );
    }

    #[test]
    fn endpoint_policies_are_rejected_in_block_mode() {
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = policy(NetworkMode::Block);
        policy.network.policies.push(endpoint_policy());

        let err = MxcExecutionSpec::from_sandbox_config(&config(policy, workspace.path().into()))
            .unwrap_err();

        assert_eq!(
            err,
            MxcTranslationError::EndpointPoliciesInNonProxyMode { mode: "block" }
        );
    }

    #[test]
    fn proxy_mode_fails_closed_in_initial_translator() {
        let workspace = tempfile::tempdir().unwrap();
        let err = MxcExecutionSpec::from_sandbox_config(&config(
            policy(NetworkMode::Proxy),
            workspace.path().into(),
        ))
        .unwrap_err();

        assert!(matches!(err, MxcTranslationError::ProxyModeUnsupported(_)));
        assert!(err.to_string().contains("cooperative"));
    }

    #[test]
    fn proxy_mode_maps_to_allow_when_strict_axis_proxy_is_preplanned() {
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Proxy),
            workspace.path().into(),
        );

        let spec = MxcExecutionSpec::from_sandbox_config_with_network_mode(
            &config,
            MxcNetworkTranslationMode::StrictProxyEnforcedByAxis,
        )
        .unwrap();

        assert_eq!(spec.network.default_policy, MxcNetworkDefaultPolicy::Allow);
    }

    #[test]
    fn proxy_mode_rejects_helper_launch_for_mxc() {
        let id = SandboxId::new();
        let policy = mxc_representable_policy(NetworkMode::Proxy);
        let (network, _) = helper_mxc_proxy_strategies(id, 31_280);

        let err = validate_mxc_network_strategy(&policy, &network).unwrap_err();

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("axis-netns-helper launch"));
        assert!(err.to_string().contains("CAP_NET_ADMIN"));
    }

    #[test]
    fn proxy_mode_rejects_binary_restricted_endpoint_policies_for_mxc() {
        let id = SandboxId::new();
        let mut policy = mxc_representable_policy(NetworkMode::Proxy);
        let mut endpoint = endpoint_policy();
        endpoint.binaries = vec![BinaryMatch {
            path: "/usr/bin/curl".into(),
        }];
        policy.network.policies.push(endpoint);
        let (network, _) = native_mxc_proxy_strategies(id, 31_280);

        let err = validate_mxc_network_strategy(&policy, &network).unwrap_err();

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("connect-time attribution"));
        assert!(err.to_string().contains("MXC backend"));
    }

    #[test]
    fn empty_command_fails_closed() {
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(policy(NetworkMode::Block), workspace.path().into());
        config.command.clear();

        let err = MxcExecutionSpec::from_sandbox_config(&config).unwrap_err();

        assert_eq!(err, MxcTranslationError::EmptyCommand);
    }

    #[test]
    fn process_command_line_is_shell_quoted_and_cwd_defaults_to_workspace() {
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(policy(NetworkMode::Block), workspace.path().into());
        config.command = "python3".into();
        config.args = vec![
            "-c".into(),
            "print('hello world')".into(),
            String::new(),
            "a'b".into(),
        ];

        let spec = translate_sandbox_config(&config).unwrap();

        assert_eq!(
            spec.process.command_line,
            "python3 -c 'print('\\''hello world'\\'')' '' 'a'\\''b'"
        );
        assert_eq!(spec.process.cwd, workspace.path().to_string_lossy());
    }

    #[test]
    fn explicit_working_directory_is_used() {
        let workspace = tempfile::tempdir().unwrap();
        let cwd = workspace.path().join("cwd");
        std::fs::create_dir(&cwd).unwrap();
        let mut config = config(policy(NetworkMode::Block), workspace.path().into());
        config.working_dir = Some(cwd.clone());

        let spec = translate_sandbox_config(&config).unwrap();

        assert_eq!(spec.process.cwd, cwd.to_string_lossy());
    }

    #[test]
    fn non_utf8_working_directory_fails_closed() {
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(policy(NetworkMode::Block), workspace.path().into());
        config.working_dir = Some(PathBuf::from(OsString::from_vec(vec![0xff])));

        let err = MxcExecutionSpec::from_sandbox_config(&config).unwrap_err();

        assert!(matches!(err, MxcTranslationError::NonUtf8Path(_)));
    }

    #[test]
    fn env_translation_strips_secrets_and_proxy_vars_but_keeps_custom_values() {
        let workspace = tempfile::tempdir().unwrap();
        let spec =
            translate_sandbox_config(&config(policy(NetworkMode::Block), workspace.path().into()))
                .unwrap();

        assert_eq!(spec.process.env, vec!["PATH=/usr/bin", "CUSTOM=kept"]);
    }

    #[test]
    fn invalid_environment_keys_and_values_are_rejected() {
        let workspace = tempfile::tempdir().unwrap();
        for (key, value) in [
            (String::new(), "value".into()),
            ("BAD=KEY".into(), "value".into()),
            ("BAD\0KEY".into(), "value".into()),
            ("BAD_VALUE".into(), "value\0".into()),
        ] {
            let mut config = config(policy(NetworkMode::Block), workspace.path().into());
            config.env = vec![(key.clone(), value)];

            let err = MxcExecutionSpec::from_sandbox_config(&config).unwrap_err();

            assert!(matches!(err, MxcTranslationError::InvalidEnv(_)));
        }
    }

    #[test]
    fn filesystem_policy_maps_existing_paths_and_skips_missing_best_effort_paths() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        let ro = root.path().join("ro");
        let rw = root.path().join("rw");
        let denied = root.path().join("denied");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::create_dir(&ro).unwrap();
        std::fs::create_dir(&rw).unwrap();
        std::fs::create_dir(&denied).unwrap();

        let mut policy = policy(NetworkMode::Block);
        policy.filesystem = FilesystemPolicy {
            read_only: vec![
                ro.to_string_lossy().into_owned(),
                root.path()
                    .join("missing-ro")
                    .to_string_lossy()
                    .into_owned(),
            ],
            read_write: vec![
                "{workspace}".into(),
                rw.to_string_lossy().into_owned(),
                root.path()
                    .join("missing-rw")
                    .to_string_lossy()
                    .into_owned(),
            ],
            deny: vec![
                denied.to_string_lossy().into_owned(),
                root.path()
                    .join("missing-denied")
                    .to_string_lossy()
                    .into_owned(),
            ],
            compatibility: Compatibility::BestEffort,
        };

        let spec = translate_sandbox_config(&config(policy, workspace.clone())).unwrap();

        assert_eq!(spec.filesystem.readonly_paths, vec![path_string(&ro)]);
        assert_eq!(
            spec.filesystem.readwrite_paths,
            vec![path_string(&workspace), path_string(&rw)]
        );
        assert_eq!(spec.filesystem.denied_paths, vec![path_string(&denied)]);
    }

    #[test]
    fn default_filesystem_adds_implicit_workspace_readwrite_path() {
        let workspace = tempfile::tempdir().unwrap();

        let spec =
            translate_sandbox_config(&config(policy(NetworkMode::Block), workspace.path().into()))
                .unwrap();

        assert_eq!(
            spec.filesystem.readwrite_paths,
            vec![path_string(workspace.path())]
        );
    }

    #[test]
    fn full_spec_allows_explicit_root_read_grant_for_mxc_bubblewrap() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        let denied = root.path().join("outside-denied");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::create_dir(&denied).unwrap();
        let mut policy = policy(NetworkMode::Block);
        policy.filesystem = FilesystemPolicy {
            read_only: vec!["/".into()],
            read_write: vec!["{workspace}".into()],
            deny: vec![denied.to_string_lossy().into_owned()],
            compatibility: Compatibility::HardRequirement,
        };

        let spec =
            MxcExecutionSpec::from_sandbox_config(&config(policy, workspace.clone())).unwrap();

        assert!(
            !spec
                .filesystem
                .readonly_paths
                .iter()
                .any(|path| path == "/"),
            "root read acknowledgement must not become a late MXC readonly bind"
        );
        assert!(
            spec.filesystem
                .readwrite_paths
                .iter()
                .any(|path| path == &path_string(&workspace))
        );
        assert_eq!(spec.filesystem.denied_paths, vec![path_string(&denied)]);
    }

    #[test]
    fn readonly_parent_containing_readwrite_child_fails_closed_for_mxc_bubblewrap_order() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        let readonly_parent = root.path().join("readonly-parent");
        let readwrite_child = readonly_parent.join("readwrite-child");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::create_dir(&readonly_parent).unwrap();
        std::fs::create_dir(&readwrite_child).unwrap();
        let mut policy = policy(NetworkMode::Block);
        policy.filesystem = FilesystemPolicy {
            read_only: vec!["/".into(), readonly_parent.to_string_lossy().into_owned()],
            read_write: vec![
                "{workspace}".into(),
                readwrite_child.to_string_lossy().into_owned(),
            ],
            compatibility: Compatibility::HardRequirement,
            ..FilesystemPolicy::default()
        };

        let err = MxcExecutionSpec::from_sandbox_config(&config(policy, workspace)).unwrap_err();

        assert!(
            err.to_string()
                .contains("would shadow the read-write grant")
        );
    }

    #[test]
    fn deny_path_containing_allowed_path_fails_closed_for_mxc_bubblewrap() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        let denied = root.path().join("denied-parent");
        let allowed = denied.join("allowed-child");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::create_dir(&denied).unwrap();
        std::fs::create_dir(&allowed).unwrap();
        let mut policy = policy(NetworkMode::Allow);
        policy.filesystem = FilesystemPolicy {
            read_only: vec!["/".into(), allowed.to_string_lossy().into_owned()],
            read_write: vec!["{workspace}".into()],
            deny: vec![denied.to_string_lossy().into_owned()],
            compatibility: Compatibility::HardRequirement,
        };

        let err = MxcExecutionSpec::from_sandbox_config(&config(policy, workspace)).unwrap_err();

        assert!(matches!(err, MxcTranslationError::Filesystem(_)));
        assert!(err.to_string().contains("contains allowed path"));
    }

    #[test]
    fn explicit_workspace_policy_does_not_duplicate_implicit_workspace() {
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = policy(NetworkMode::Block);
        policy.filesystem.read_write.push("{workspace}".into());

        let spec = translate_sandbox_config(&config(policy, workspace.path().into())).unwrap();

        assert_eq!(
            spec.filesystem.readwrite_paths,
            vec![path_string(workspace.path())]
        );
    }

    #[test]
    fn best_effort_symlink_alias_is_skipped_until_mxc_can_represent_mount_aliases() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        let target = root.path().join("target");
        let alias = root.path().join("alias");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, &alias).unwrap();

        let mut policy = policy(NetworkMode::Block);
        policy
            .filesystem
            .read_only
            .push(alias.to_string_lossy().into_owned());

        let spec = translate_sandbox_config(&config(policy, workspace)).unwrap();

        assert!(spec.filesystem.readonly_paths.is_empty());
    }

    #[test]
    fn hard_requirement_missing_path_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let mut policy = policy(NetworkMode::Block);
        policy.filesystem = FilesystemPolicy {
            read_only: vec![root.path().join("missing").to_string_lossy().into_owned()],
            compatibility: Compatibility::HardRequirement,
            ..FilesystemPolicy::default()
        };

        let err = MxcExecutionSpec::from_sandbox_config(&config(policy, workspace)).unwrap_err();

        assert!(matches!(err, MxcTranslationError::Filesystem(_)));
    }

    #[test]
    fn hard_requirement_symlink_alias_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        let target = root.path().join("target");
        let alias = root.path().join("alias");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, &alias).unwrap();

        let mut policy = policy(NetworkMode::Block);
        policy.filesystem = FilesystemPolicy {
            read_only: vec![alias.to_string_lossy().into_owned()],
            compatibility: Compatibility::HardRequirement,
            ..FilesystemPolicy::default()
        };

        let err = MxcExecutionSpec::from_sandbox_config(&config(policy, workspace)).unwrap_err();

        assert!(matches!(err, MxcTranslationError::Filesystem(_)));
        assert!(err.to_string().contains("mount alias"));
    }

    #[test]
    fn timeout_maps_seconds_to_milliseconds() {
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(policy(NetworkMode::Block), workspace.path().into());
        config.timeout_sec = Some(2);

        let spec = translate_sandbox_config(&config).unwrap();

        assert_eq!(spec.process.timeout, Some(2000));
    }

    #[test]
    fn policy_timeout_is_used_when_config_timeout_is_absent() {
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = policy(NetworkMode::Block);
        policy.process.timeout_sec = Some(3);

        let spec = translate_sandbox_config(&config(policy, workspace.path().into())).unwrap();

        assert_eq!(spec.process.timeout, Some(3000));
    }

    #[test]
    fn config_timeout_overrides_policy_timeout() {
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = policy(NetworkMode::Block);
        policy.process.timeout_sec = Some(3);
        let mut config = config(policy, workspace.path().into());
        config.timeout_sec = Some(2);

        let spec = translate_sandbox_config(&config).unwrap();

        assert_eq!(spec.process.timeout, Some(2000));
    }

    #[test]
    fn timeout_overflow_fails_closed() {
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(policy(NetworkMode::Block), workspace.path().into());
        config.timeout_sec = Some(u64::MAX);

        let err = MxcExecutionSpec::from_sandbox_config(&config).unwrap_err();

        assert!(matches!(err, MxcTranslationError::TimeoutOverflow { .. }));
    }

    #[test]
    fn serialized_json_uses_mxc_field_names() {
        let workspace = tempfile::tempdir().unwrap();
        let spec =
            translate_sandbox_config(&config(policy(NetworkMode::Block), workspace.path().into()))
                .unwrap();

        let json = serde_json::to_value(&spec).unwrap();

        assert_eq!(json["process"]["commandLine"], spec.process.command_line);
        assert_eq!(json["network"]["defaultPolicy"], "block");
        assert!(json["filesystem"]["readwritePaths"].is_array());
        assert!(json["filesystem"]["readonlyPaths"].is_array());
        assert!(json["filesystem"]["deniedPaths"].is_array());
    }

    #[test]
    fn executor_from_path_accepts_safe_executable() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(&executable, "#!/bin/sh\nexit 0\n", 0o700);

        let executor = MxcExecutor::from_injected_path(&executable).unwrap();

        assert_eq!(executor.path(), executable);
    }

    #[test]
    fn executor_from_path_rejects_unsafe_candidates() {
        let root = secure_tempdir();

        let missing = root.path().join("missing");
        assert_unsafe_candidate(&missing, "does not exist");

        let directory = root.path().join("directory");
        fs::create_dir(&directory).unwrap();
        assert_unsafe_candidate(&directory, "regular file");

        let non_executable = root.path().join("non-executable");
        write_executable(&non_executable, "#!/bin/sh\nexit 0\n", 0o600);
        assert_unsafe_candidate(&non_executable, "not executable");

        let group_writable = root.path().join("group-writable");
        write_executable(&group_writable, "#!/bin/sh\nexit 0\n", 0o720);
        assert_unsafe_candidate(&group_writable, "group- or world-writable");

        let world_writable = root.path().join("world-writable");
        write_executable(&world_writable, "#!/bin/sh\nexit 0\n", 0o702);
        assert_unsafe_candidate(&world_writable, "group- or world-writable");
    }

    #[test]
    fn executor_from_path_rejects_writable_ancestor() {
        let root = secure_tempdir();
        let writable_dir = root.path().join("writable");
        fs::create_dir(&writable_dir).unwrap();
        fs::set_permissions(&writable_dir, fs::Permissions::from_mode(0o777)).unwrap();
        let executable = writable_dir.join("lxc-exec");
        write_executable(&executable, "#!/bin/sh\nexit 0\n", 0o700);

        assert_unsafe_candidate(&executable, "group- or world-writable");
    }

    #[test]
    fn executor_resolver_uses_first_safe_candidate_and_reports_unavailable() {
        let root = secure_tempdir();
        let unsafe_candidate = root.path().join("unsafe-lxc-exec");
        write_executable(&unsafe_candidate, "#!/bin/sh\nexit 0\n", 0o777);
        let safe_candidate = root.path().join("safe-lxc-exec");
        write_executable(&safe_candidate, "#!/bin/sh\nexit 0\n", 0o700);

        let executor = MxcExecutor::resolve_from_injected_candidates([
            unsafe_candidate,
            safe_candidate.clone(),
        ])
        .unwrap();

        assert_eq!(executor.path(), safe_candidate);
        assert_eq!(
            MxcExecutor::resolve_from_candidates([root.path().join("missing")]).unwrap_err(),
            MxcExecutorError::Unavailable
        );
    }

    #[test]
    fn production_resolver_rejects_sticky_tmp_candidates() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(&executable, "#!/bin/sh\nexit 0\n", 0o700);

        let err = MxcExecutor::resolve_from_candidates([executable]).unwrap_err();

        assert_eq!(err, MxcExecutorError::Unavailable);
    }

    #[test]
    fn dry_run_success_uses_private_config_path_without_secret_leakage() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        let argv_path = root.path().join("argv");
        let config_copy = root.path().join("config-copy");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 set -eu\n\
                 printf '%s\\n' \"$@\" > {}\n\
                 config=''\n\
                 previous=''\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$previous\" = '--config' ]; then config=\"$arg\"; fi\n\
                   previous=\"$arg\"\n\
                 done\n\
                 test -n \"$config\"\n\
                 cat \"$config\" > {}\n\
                 echo '{}'\n",
                shell_quote_path(&argv_path),
                shell_quote_path(&config_copy),
                MXC_DRY_RUN_SUCCESS
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let spec =
            translate_sandbox_config(&config(policy(NetworkMode::Block), workspace.path().into()))
                .unwrap();

        let result = executor
            .dry_run(&spec, Duration::from_secs(1))
            .expect("fake executor should report dry-run success");

        let argv = fs::read_to_string(argv_path).unwrap();
        let config_json = fs::read_to_string(config_copy).unwrap();
        assert!(argv.contains("--experimental"));
        assert!(argv.contains("--dry-run"));
        assert!(argv.contains("--config"));
        for captured in [&argv, &config_json, &result.stdout, &result.stderr] {
            assert!(!captured.contains("ANTHROPIC_API_KEY"));
            assert!(!captured.contains("proxy-with-creds"));
            assert!(!captured.contains("secret"));
        }
    }

    #[test]
    fn dry_run_clears_inherited_parent_environment() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 if [ \"${{ANTHROPIC_API_KEY+x}}\" = x ]; then\n\
                   echo inherited-secret-leaked >&2\n\
                   exit 9\n\
                 fi\n\
                 echo '{}'\n",
                MXC_DRY_RUN_SUCCESS
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let spec =
            translate_sandbox_config(&config(policy(NetworkMode::Block), workspace.path().into()))
                .unwrap();

        let result = with_parent_secret_env(|| {
            executor
                .dry_run(&spec, Duration::from_secs(1))
                .expect("dry-run should not inherit provider secrets")
        });

        assert!(!result.stderr.contains("inherited-secret-leaked"));
    }

    #[test]
    fn dry_run_failure_reports_status_without_reflecting_output() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(
            &executable,
            "#!/bin/sh\necho super-secret-token\nexit 7\n",
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let spec =
            translate_sandbox_config(&config(policy(NetworkMode::Block), workspace.path().into()))
                .unwrap();

        let err = executor.dry_run(&spec, Duration::from_secs(1)).unwrap_err();

        assert_eq!(err, MxcExecutorError::DryRunFailed { code: Some(7) });
        assert!(!err.to_string().contains("super-secret-token"));
    }

    #[test]
    fn dry_run_malformed_success_output_is_rejected() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(&executable, "#!/bin/sh\necho unexpected\nexit 0\n", 0o700);
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let spec =
            translate_sandbox_config(&config(policy(NetworkMode::Block), workspace.path().into()))
                .unwrap();

        let err = executor.dry_run(&spec, Duration::from_secs(1)).unwrap_err();

        assert_eq!(err, MxcExecutorError::MalformedDryRunOutput);
    }

    #[test]
    fn dry_run_timeout_kills_executor() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        let descendant_pid = root.path().join("descendant.pid");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\nsleep 5 &\necho $! > {}\nwait\n",
                shell_quote_path(&descendant_pid)
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let spec =
            translate_sandbox_config(&config(policy(NetworkMode::Block), workspace.path().into()))
                .unwrap();

        let err = executor
            .dry_run(&spec, Duration::from_millis(200))
            .unwrap_err();

        assert_eq!(err, MxcExecutorError::Timeout { timeout_ms: 200 });
        let pid = fs::read_to_string(descendant_pid)
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap();
        assert_process_stopped(pid);
    }

    #[test]
    fn dry_run_rejects_manual_specs_with_filtered_or_malformed_env() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(
            &executable,
            &format!("#!/bin/sh\necho '{}'\n", MXC_DRY_RUN_SUCCESS),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let mut spec =
            translate_sandbox_config(&config(policy(NetworkMode::Block), workspace.path().into()))
                .unwrap();

        spec.process
            .env
            .push("ANTHROPIC_API_KEY=super-secret".into());
        let err = executor.dry_run(&spec, Duration::from_secs(1)).unwrap_err();
        assert_eq!(
            err,
            MxcExecutorError::FilteredEnv {
                key: "ANTHROPIC_API_KEY".into()
            }
        );

        spec.process.env = vec!["ANTHROPIC_API_KEY-super-secret".into()];
        let err = executor.dry_run(&spec, Duration::from_secs(1)).unwrap_err();
        assert_eq!(err, MxcExecutorError::MalformedEnv);
        assert!(!err.to_string().contains("super-secret"));
    }

    #[test]
    fn dry_run_allows_only_axis_generated_proxy_env_when_authorized() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(
            &executable,
            &format!("#!/bin/sh\necho '{}'\n", MXC_DRY_RUN_SUCCESS),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let proxy_port = 31_280;
        let (_network, proxy) = native_mxc_proxy_strategies(id, proxy_port);
        let allowed_proxy_env = allowed_proxy_env(&proxy);
        let mut config = config(
            mxc_representable_policy(NetworkMode::Proxy),
            workspace.path().into(),
        );
        config.id = id;
        let mut spec = MxcExecutionSpec::from_sandbox_config_with_network_mode(
            &config,
            MxcNetworkTranslationMode::StrictProxyEnforcedByAxis,
        )
        .unwrap();
        apply_proxy_env_to_spec(&mut spec, &proxy);
        let expected_proxy = format!(
            "HTTP_PROXY=http://{}:{proxy_port}",
            super::super::netns::proxy_netns_allocation(id, proxy_port).host_addr
        );

        assert!(spec.process.env.contains(&expected_proxy));
        assert!(
            !spec
                .process
                .env
                .iter()
                .any(|entry| entry.contains("proxy-with-creds"))
        );

        executor
            .dry_run_with_allowed_env(&spec, Duration::from_secs(1), &allowed_proxy_env)
            .unwrap();
        assert_eq!(
            executor.dry_run(&spec, Duration::from_secs(1)).unwrap_err(),
            MxcExecutorError::FilteredEnv {
                key: "HTTP_PROXY".into()
            }
        );
    }

    #[test]
    fn seccomp_launch_rewrites_command_and_mounts_private_filter_readonly() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        let config_copy = root.path().join("config-copy");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 set -eu\n\
                 config=''\n\
                 previous=''\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$previous\" = '--config' ]; then config=\"$arg\"; fi\n\
                   previous=\"$arg\"\n\
                 done\n\
                 test -n \"$config\"\n\
                 cat \"$config\" > {}\n\
                 echo '{}'\n",
                shell_quote_path(&config_copy),
                MXC_DRY_RUN_SUCCESS
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let launcher = fake_seccomp_launcher(&root);
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(
            mxc_representable_policy(NetworkMode::Block),
            workspace.path().into(),
        );
        config.command = "/bin/sh".into();
        config.args = vec!["-c".into(), "echo '$PATH'".into()];

        let sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher.clone())
            .expect("fake MXC dry-run should accept rewritten command");

        let config_json = fs::read_to_string(config_copy).unwrap();
        let json: serde_json::Value = serde_json::from_str(&config_json).unwrap();
        let command_line = json["process"]["commandLine"].as_str().unwrap();
        assert!(command_line.contains("axis-seccomp-launcher"));
        assert!(command_line.contains("--filter"));
        assert!(command_line.contains("-- /bin/sh -c 'echo '\\''$PATH'\\'''"));
        assert!(!command_line.contains("ANTHROPIC_API_KEY"));
        assert!(!command_line.contains("proxy-with-creds"));

        let readonly_paths = json["filesystem"]["readonlyPaths"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(readonly_paths.contains(&launcher.path().to_str().unwrap()));
        let filter_path = readonly_paths
            .iter()
            .copied()
            .find(|path| path.contains("axis-mxc-seccomp-") && path.ends_with(".bpf"))
            .expect("MXC config should mount the private seccomp filter readonly");
        assert!(
            Path::new(filter_path).exists(),
            "filter file must stay alive while sandbox is alive"
        );

        drop(sandbox);
        assert!(
            !Path::new(filter_path).exists(),
            "filter file should be removed when sandbox state is dropped"
        );
    }

    #[test]
    fn invalid_seccomp_policy_fails_before_executor_resolution() {
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = mxc_representable_policy(NetworkMode::Allow);
        policy.process.blocked_syscalls = vec!["not_a_real_syscall".into()];
        let config = config(policy, workspace.path().into());

        let result = MxcLinuxSandbox::new_with_resolvers(
            &config,
            || panic!("executor must not be resolved after seccomp preparation failure"),
            || panic!("launcher must not be resolved after seccomp preparation failure"),
            || Ok(no_proxy_network_strategy()),
            || Ok(no_resource_limits_strategy()),
        );
        let Err(err) = result else {
            panic!("expected seccomp preparation failure");
        };

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("unknown syscall"));
    }

    #[test]
    fn denied_seccomp_launcher_path_fails_before_executor_resolution() {
        let root = secure_tempdir();
        let workspace = root.path().join("workspace");
        let denied = root.path().join("denied");
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(&denied).unwrap();
        fs::set_permissions(&denied, fs::Permissions::from_mode(0o700)).unwrap();
        let launcher_path = denied.join("axis-seccomp-launcher");
        write_executable(&launcher_path, "#!/bin/sh\nexit 127\n", 0o700);
        let launcher = MxcSeccompLauncher::from_injected_path(&launcher_path).unwrap();
        let mut policy = mxc_representable_policy(NetworkMode::Allow);
        policy
            .filesystem
            .deny
            .push(denied.to_string_lossy().into_owned());
        let config = config(policy, workspace);

        let result = MxcLinuxSandbox::new_with_resolvers(
            &config,
            || panic!("executor must not be resolved when seccomp support path is denied"),
            || Ok(launcher),
            || Ok(no_proxy_network_strategy()),
            || Ok(no_resource_limits_strategy()),
        );
        let Err(err) = result else {
            panic!("expected denied seccomp launcher path failure");
        };

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("seccomp launcher path"));
        assert!(err.to_string().contains("covered by denied path"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_captures_output_exit_code_and_removes_private_config() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        let config_path_record = root.path().join("config-path");
        let config_copy = root.path().join("config-copy");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 set -eu\n\
                 mode=run\n\
                 config=''\n\
                 previous=''\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$arg\" = '--dry-run' ]; then mode=dry; fi\n\
                   if [ \"$previous\" = '--config' ]; then config=\"$arg\"; fi\n\
                   previous=\"$arg\"\n\
                 done\n\
                 test -n \"$config\"\n\
                 printf '%s\\n' \"$config\" > {}\n\
                 cat \"$config\" > {}\n\
                 if [ \"$mode\" = dry ]; then\n\
                   echo '{}'\n\
                   exit 0\n\
                 fi\n\
                 if IFS= read -r _line; then\n\
                   echo stdin was not closed >&2\n\
                   exit 8\n\
                 fi\n\
                 echo mxc-stdout\n\
                 echo mxc-stderr >&2\n\
                 exit 7\n",
                shell_quote_path(&config_path_record),
                shell_quote_path(&config_copy),
                MXC_DRY_RUN_SUCCESS
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        config.capture_output = true;

        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();
        SandboxImpl::start(&mut sandbox).unwrap();
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();

        assert_eq!(code, 7);
        assert_eq!(
            fs::read_to_string(workspace.path().join("stdout.log")).unwrap(),
            "mxc-stdout\n"
        );
        assert_eq!(
            fs::read_to_string(workspace.path().join("stderr.log")).unwrap(),
            "mxc-stderr\n"
        );
        let config_path = fs::read_to_string(config_path_record).unwrap();
        assert!(
            !Path::new(config_path.trim()).exists(),
            "private MXC config file should be removed after wait"
        );
        let config_json = fs::read_to_string(config_copy).unwrap();
        assert!(!config_json.contains("ANTHROPIC_API_KEY"));
        assert!(!config_json.contains("proxy-with-creds"));
        assert!(!config_json.contains("secret"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_non_capture_mode_does_not_create_daemon_logs() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        let marker = root.path().join("ran");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 mode=run\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$arg\" = '--dry-run' ]; then mode=dry; fi\n\
                 done\n\
                 if [ \"$mode\" = dry ]; then\n\
                   echo '{}'\n\
                   exit 0\n\
                 fi\n\
                 echo ran > {}\n",
                MXC_DRY_RUN_SUCCESS,
                shell_quote_path(&marker)
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        config.capture_output = false;

        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();
        SandboxImpl::start(&mut sandbox).unwrap();
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();

        assert_eq!(code, 0);
        assert!(marker.exists());
        assert!(!workspace.path().join("stdout.log").exists());
        assert!(!workspace.path().join("stderr.log").exists());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_timeout_kills_executor_process_group_and_cleans_tmpdir() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        let descendant_pid = root.path().join("descendant.pid");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 set -eu\n\
                 mode=run\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$arg\" = '--dry-run' ]; then mode=dry; fi\n\
                 done\n\
                 if [ \"$mode\" = dry ]; then\n\
                   echo '{}'\n\
                   exit 0\n\
                 fi\n\
                 sleep 30 &\n\
                 echo $! > {}\n\
                 wait\n",
                MXC_DRY_RUN_SUCCESS,
                shell_quote_path(&descendant_pid)
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = mxc_representable_policy(NetworkMode::Block);
        policy.filesystem.read_write.push("{tmpdir}".into());
        let tmpdir = crate::linux::landlock::sandbox_tmpdir(workspace.path());
        let mut config = config(policy, workspace.path().into());
        config.timeout_sec = Some(1);

        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();
        assert!(tmpdir.exists(), "MXC setup should create AXIS tmpdir");
        SandboxImpl::start(&mut sandbox).unwrap();
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();

        assert_eq!(code, -1);
        let pid = fs::read_to_string(descendant_pid)
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap();
        assert_process_stopped(pid);
        assert!(!tmpdir.exists(), "MXC wait should clean AXIS tmpdir");
    }

    #[test]
    fn runtime_start_failure_cleans_native_proxy_netns() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "exit 0");
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let proxy_port = 31_280;
        let (network, proxy) = native_mxc_proxy_strategies(id, proxy_port);
        let mut config = config(
            mxc_representable_policy(NetworkMode::Proxy),
            workspace.path().into(),
        );
        config.id = id;
        config.proxy_port = proxy_port;
        config.proxy_addr = Some(super::super::netns::proxy_bind_addr(id, proxy_port));
        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor_and_strategies(
            &config,
            executor,
            launcher,
            network,
            proxy,
            no_resource_limits_strategy(),
        )
        .unwrap();
        sandbox.netns_override = Some(MxcNetnsOverride {
            name: "axis-test-netns".into(),
            fd: tempfile::tempfile().unwrap().into_raw_fd(),
            cleanup: Ok(()),
        });
        fs::create_dir(workspace.path().join("stdout.log")).unwrap();

        let err = SandboxImpl::start(&mut sandbox).unwrap_err();

        assert!(matches!(err, SandboxError::SpawnFailed(_)));
        assert!(sandbox.netns_name.is_none());
    }

    #[test]
    fn runtime_spawn_failure_cleans_native_proxy_netns_after_setns_error() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "exit 0");
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let proxy_port = 31_281;
        let (network, proxy) = native_mxc_proxy_strategies(id, proxy_port);
        let mut config = config(
            mxc_representable_policy(NetworkMode::Proxy),
            workspace.path().into(),
        );
        config.id = id;
        config.proxy_port = proxy_port;
        config.proxy_addr = Some(super::super::netns::proxy_bind_addr(id, proxy_port));
        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor_and_strategies(
            &config,
            executor,
            launcher,
            network,
            proxy,
            no_resource_limits_strategy(),
        )
        .unwrap();
        sandbox.netns_override = Some(MxcNetnsOverride {
            name: "axis-test-netns".into(),
            fd: tempfile::tempfile().unwrap().into_raw_fd(),
            cleanup: Ok(()),
        });

        let err = SandboxImpl::start(&mut sandbox).unwrap_err();

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("enter network namespace"));
        assert!(sandbox.netns_name.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_wait_reports_netns_cleanup_failure() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "exit 0");
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();

        SandboxImpl::start(&mut sandbox).unwrap();
        inject_failing_netns_cleanup(&mut sandbox);

        let err = SandboxImpl::wait(&mut sandbox).await.unwrap_err();

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("netns cleanup failed"));
        assert!(
            sandbox.netns_name.is_some(),
            "failed cleanup should leave netns name inspectable"
        );
    }

    #[test]
    fn runtime_try_wait_reports_netns_cleanup_failure() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "exit 0");
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();

        SandboxImpl::start(&mut sandbox).unwrap();
        inject_failing_netns_cleanup(&mut sandbox);

        let deadline = Instant::now() + Duration::from_secs(5);
        let err = loop {
            match SandboxImpl::try_wait(&mut sandbox) {
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => panic!("MXC executor did not exit before try_wait deadline"),
                Ok(Some(code)) => {
                    panic!("try_wait should report netns cleanup failure, got code {code}")
                }
                Err(err) => break err,
            }
        };

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("netns cleanup failed"));
        assert!(
            sandbox.netns_name.is_some(),
            "failed cleanup should leave netns name inspectable"
        );
    }

    #[test]
    fn runtime_destroy_reports_netns_cleanup_failure() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "sleep 30");
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();

        SandboxImpl::start(&mut sandbox).unwrap();
        inject_failing_netns_cleanup(&mut sandbox);

        let err = SandboxImpl::destroy(&mut sandbox).unwrap_err();

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("netns cleanup failed"));
        assert!(
            sandbox.netns_name.is_some(),
            "failed cleanup should leave netns name inspectable"
        );
    }

    #[test]
    fn runtime_start_failure_cleans_tmpdir() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(
            &executable,
            &format!("#!/bin/sh\necho '{}'\n", MXC_DRY_RUN_SUCCESS),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = mxc_representable_policy(NetworkMode::Allow);
        policy.filesystem.read_write.push("{tmpdir}".into());
        let tmpdir = crate::linux::landlock::sandbox_tmpdir(workspace.path());
        let config = config(policy, workspace.path().into());
        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();
        assert!(tmpdir.exists(), "MXC setup should create AXIS tmpdir");
        let filter_path = sandbox
            .seccomp_filter_file
            .as_ref()
            .map(|file| file.path().to_path_buf())
            .expect("MXC setup should create private seccomp filter");
        assert!(
            filter_path.exists(),
            "private seccomp filter should exist before start"
        );
        std::fs::remove_file(&executable).unwrap();

        let err = SandboxImpl::start(&mut sandbox).unwrap_err();

        assert!(matches!(err, SandboxError::SpawnFailed(_)));
        assert!(!tmpdir.exists(), "start failure should clean AXIS tmpdir");
        assert!(
            !filter_path.exists(),
            "start failure should remove private seccomp filter"
        );
    }

    #[test]
    fn resource_strategy_rejects_process_rlimit_fallback_for_mxc() {
        let process_fallback = strategy::ResourceStrategy::RlimitFallback {
            memory_limit: true,
            process_limit: strategy::ProcessLimitFallback::RlimitNprocWithDedicatedUser,
            cpu_limit: strategy::CpuLimitFallback::NotRequested,
        };

        let err = validate_mxc_resource_strategy(&process_fallback).unwrap_err();

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("process-count rlimit fallback"));
        assert!(err.to_string().contains("writable cgroups v2"));

        let memory_only = strategy::ResourceStrategy::RlimitFallback {
            memory_limit: true,
            process_limit: strategy::ProcessLimitFallback::NotRequested,
            cpu_limit: strategy::CpuLimitFallback::NotRequested,
        };
        validate_mxc_resource_strategy(&memory_only).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_enters_cgroup_before_mxc_executor_runs() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 mode=run\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$arg\" = '--dry-run' ]; then mode=dry; fi\n\
                 done\n\
                 if [ \"$mode\" = dry ]; then\n\
                   echo '{}'\n\
                   exit 0\n\
                 fi\n\
                 exit 0\n",
                MXC_DRY_RUN_SUCCESS
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launcher = fake_seccomp_launcher(&root);
        let cgroup_root = tempfile::tempdir().unwrap();
        let cgroup = temp_cgroup(cgroup_root.path(), &config);
        let cgroup_path = cgroup.path().to_path_buf();
        let mut sandbox = MxcLinuxSandbox::new_with_executor_and_resource_strategy(
            &config,
            executor,
            launcher,
            strategy::ResourceStrategy::CgroupsV2 {
                support: strategy::CgroupV2Support::Writable,
            },
        )
        .unwrap();
        sandbox.cgroup_override = Some(cgroup);

        let pid = SandboxImpl::start(&mut sandbox).unwrap();

        assert_eq!(
            fs::read_to_string(cgroup_path.join("cgroup.procs"))
                .unwrap()
                .trim(),
            pid.to_string()
        );
        fs::write(cgroup_path.join("cgroup.procs"), "").unwrap();
        assert_eq!(SandboxImpl::wait(&mut sandbox).await.unwrap(), 0);
        assert!(!cgroup_path.exists(), "MXC cgroup should be cleaned");
    }

    #[test]
    fn runtime_start_failure_cleans_cgroup() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(
            &executable,
            &format!("#!/bin/sh\necho '{}'\n", MXC_DRY_RUN_SUCCESS),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launcher = fake_seccomp_launcher(&root);
        let cgroup_root = tempfile::tempdir().unwrap();
        let cgroup = temp_cgroup(cgroup_root.path(), &config);
        let cgroup_path = cgroup.path().to_path_buf();
        let mut sandbox = MxcLinuxSandbox::new_with_executor_and_resource_strategy(
            &config,
            executor,
            launcher,
            strategy::ResourceStrategy::CgroupsV2 {
                support: strategy::CgroupV2Support::Writable,
            },
        )
        .unwrap();
        sandbox.cgroup_override = Some(cgroup);
        fs::create_dir(workspace.path().join("stdout.log")).unwrap();

        let err = SandboxImpl::start(&mut sandbox).unwrap_err();

        assert!(matches!(err, SandboxError::SpawnFailed(_)));
        assert!(
            !cgroup_path.exists(),
            "start failure should clean cgroup; error={err}; remaining={:?}",
            remaining_dir_entries(&cgroup_path)
        );
    }

    #[test]
    fn runtime_start_failure_reports_cgroup_cleanup_failure() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(
            &executable,
            &format!("#!/bin/sh\necho '{}'\n", MXC_DRY_RUN_SUCCESS),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launcher = fake_seccomp_launcher(&root);
        let cgroup_root = tempfile::tempdir().unwrap();
        let cgroup = temp_cgroup(cgroup_root.path(), &config);
        let cgroup_path = cgroup.path().to_path_buf();
        fs::write(cgroup_path.join("cgroup.procs"), "1234\n").unwrap();
        let mut sandbox = MxcLinuxSandbox::new_with_executor_and_resource_strategy(
            &config,
            executor,
            launcher,
            strategy::ResourceStrategy::CgroupsV2 {
                support: strategy::CgroupV2Support::Writable,
            },
        )
        .unwrap();
        sandbox.cgroup_override = Some(cgroup);
        fs::remove_file(&executable).unwrap();

        let err = SandboxImpl::start(&mut sandbox).unwrap_err();

        assert!(err.to_string().contains("cleanup failed"));
        assert!(err.to_string().contains("cgroup cleanup failed"));
        assert!(
            cgroup_path.exists(),
            "failed cleanup should leave cgroup inspectable"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_wait_reports_cgroup_cleanup_failure() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "exit 0");
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launcher = fake_seccomp_launcher(&root);
        let cgroup_root = tempfile::tempdir().unwrap();
        let cgroup = temp_cgroup(cgroup_root.path(), &config);
        let cgroup_path = cgroup.path().to_path_buf();
        let mut sandbox = MxcLinuxSandbox::new_with_executor_and_resource_strategy(
            &config,
            executor,
            launcher,
            cgroup_resource_strategy(),
        )
        .unwrap();
        sandbox.cgroup_override = Some(cgroup);

        SandboxImpl::start(&mut sandbox).unwrap();

        let err = SandboxImpl::wait(&mut sandbox).await.unwrap_err();

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("cgroup cleanup failed"));
        assert!(
            cgroup_path.exists(),
            "failed cleanup should leave cgroup inspectable"
        );
    }

    #[test]
    fn runtime_try_wait_reports_cgroup_cleanup_failure() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "exit 0");
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launcher = fake_seccomp_launcher(&root);
        let cgroup_root = tempfile::tempdir().unwrap();
        let cgroup = temp_cgroup(cgroup_root.path(), &config);
        let cgroup_path = cgroup.path().to_path_buf();
        let mut sandbox = MxcLinuxSandbox::new_with_executor_and_resource_strategy(
            &config,
            executor,
            launcher,
            cgroup_resource_strategy(),
        )
        .unwrap();
        sandbox.cgroup_override = Some(cgroup);

        SandboxImpl::start(&mut sandbox).unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        let err = loop {
            match SandboxImpl::try_wait(&mut sandbox) {
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => panic!("MXC executor did not exit before try_wait deadline"),
                Ok(Some(code)) => {
                    panic!("try_wait should report cgroup cleanup failure, got code {code}")
                }
                Err(err) => break err,
            }
        };

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("cgroup cleanup failed"));
        assert!(
            cgroup_path.exists(),
            "failed cleanup should leave cgroup inspectable"
        );
    }

    #[test]
    fn runtime_destroy_reports_cgroup_cleanup_failure() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "sleep 30");
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launcher = fake_seccomp_launcher(&root);
        let cgroup_root = tempfile::tempdir().unwrap();
        let cgroup = temp_cgroup(cgroup_root.path(), &config);
        let cgroup_path = cgroup.path().to_path_buf();
        let mut sandbox = MxcLinuxSandbox::new_with_executor_and_resource_strategy(
            &config,
            executor,
            launcher,
            cgroup_resource_strategy(),
        )
        .unwrap();
        sandbox.cgroup_override = Some(cgroup);

        SandboxImpl::start(&mut sandbox).unwrap();

        let err = SandboxImpl::destroy(&mut sandbox).unwrap_err();

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("cgroup cleanup failed"));
        assert!(
            cgroup_path.exists(),
            "failed cleanup should leave cgroup inspectable"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_wait_error_preserves_cgroup_cleanup_failure() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "exit 0");
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launcher = fake_seccomp_launcher(&root);
        let cgroup_root = tempfile::tempdir().unwrap();
        let cgroup = temp_cgroup(cgroup_root.path(), &config);
        let cgroup_path = cgroup.path().to_path_buf();
        let mut sandbox = MxcLinuxSandbox::new_with_executor_and_resource_strategy(
            &config,
            executor,
            launcher,
            cgroup_resource_strategy(),
        )
        .unwrap();
        sandbox.cgroup_override = Some(cgroup);

        let pid = SandboxImpl::start(&mut sandbox).unwrap();
        reap_child(pid);

        let err = SandboxImpl::wait(&mut sandbox).await.unwrap_err();
        let message = err.to_string();
        let expected_wait_error = std::io::Error::from_raw_os_error(libc::ECHILD).to_string();

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(message.contains("process cleanup failed after wait error"));
        assert!(
            message.contains(&expected_wait_error),
            "wait error was not preserved in '{message}'"
        );
        assert!(message.contains("cgroup cleanup failed"));
        assert!(
            cgroup_path.exists(),
            "failed cleanup should leave cgroup inspectable"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gated_real_mxc_allow_and_block_runtime_parity() {
        if MxcExecutor::resolve().is_err() {
            eprintln!("safe lxc-exec unavailable (test skipped)");
            return;
        }
        if MxcSeccompLauncher::resolve().is_err() {
            eprintln!("axis-seccomp-launcher unavailable for MXC backend (test skipped)");
            return;
        }
        if find_on_path("bwrap").is_none() {
            eprintln!("bubblewrap unavailable for MXC backend (test skipped)");
            return;
        }
        if fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
            .map(|value| value.trim() != "1")
            .unwrap_or(true)
        {
            eprintln!("unprivileged user namespaces unavailable (test skipped)");
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

        let root = tempfile::tempdir().unwrap();
        let ro_dir = root.path().join("ro");
        let rw_dir = root.path().join("rw");
        let denied_dir = root.path().join("denied");
        let allow_workspace = root.path().join("allow-workspace");
        let block_workspace = root.path().join("block-workspace");
        for dir in [
            &ro_dir,
            &rw_dir,
            &denied_dir,
            &allow_workspace,
            &block_workspace,
        ] {
            std::fs::create_dir(dir).unwrap();
        }
        let ro_file = ro_dir.join("ro.txt");
        let denied_file = denied_dir.join("secret.txt");
        std::fs::write(&ro_file, "read-only").unwrap();
        std::fs::write(&denied_file, "denied").unwrap();

        let allow_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        allow_listener.set_nonblocking(true).unwrap();
        let allow_port = allow_listener.local_addr().unwrap().port();
        let mut allow_config = config(
            mxc_filesystem_policy(NetworkMode::Allow, &rw_dir, &denied_dir),
            allow_workspace.clone(),
        );
        allow_config.command = python.to_string_lossy().into_owned();
        allow_config.args = vec!["-c".into(), real_mxc_allow_probe().into()];
        allow_config.working_dir = Some(allow_workspace.clone());
        allow_config.capture_output = true;
        allow_config.timeout_sec = Some(10);
        allow_config.env = vec![
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("CUSTOM".into(), "kept".into()),
            ("RO_FILE".into(), ro_file.to_string_lossy().into_owned()),
            ("RW_DIR".into(), rw_dir.to_string_lossy().into_owned()),
            (
                "DENIED_FILE".into(),
                denied_file.to_string_lossy().into_owned(),
            ),
            (
                "DENIED_DIR".into(),
                denied_dir.to_string_lossy().into_owned(),
            ),
            ("ALLOW_PORT".into(), allow_port.to_string()),
            ("ANTHROPIC_API_KEY".into(), "secret".into()),
            ("HTTPS_PROXY".into(), "http://proxy-with-creds".into()),
        ];

        let mut allow_sandbox = MxcLinuxSandbox::new(&allow_config).unwrap();
        SandboxImpl::start(&mut allow_sandbox).unwrap();
        let allow_code = SandboxImpl::wait(&mut allow_sandbox).await.unwrap();
        let allow_stderr =
            fs::read_to_string(allow_workspace.join("stderr.log")).unwrap_or_default();
        assert_eq!(
            allow_code, 0,
            "MXC allow-mode probe failed:\n{allow_stderr}"
        );
        assert!(
            listener_observed_probe(&allow_listener),
            "MXC allow-mode sandbox did not reach host loopback listener"
        );
        assert_eq!(
            fs::read_to_string(allow_workspace.join("stdout.log")).unwrap(),
            "allow-stdout\n"
        );
        assert_eq!(fs::read_to_string(rw_dir.join("rw.txt")).unwrap(), "rw");
        assert_eq!(
            fs::read_to_string(allow_workspace.join("workspace.txt")).unwrap(),
            "workspace"
        );
        allow_sandbox.destroy().unwrap();

        let block_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let block_port = block_listener.local_addr().unwrap().port();
        let mut block_config = config(
            mxc_filesystem_policy(NetworkMode::Block, &rw_dir, &denied_dir),
            block_workspace.clone(),
        );
        block_config.command = python.to_string_lossy().into_owned();
        block_config.args = vec!["-c".into(), real_mxc_block_probe().into()];
        block_config.working_dir = Some(block_workspace.clone());
        block_config.capture_output = true;
        block_config.timeout_sec = Some(10);
        block_config.env = vec![
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("BLOCK_PORT".into(), block_port.to_string()),
            ("HTTP_PROXY".into(), "http://proxy-with-creds".into()),
        ];

        let mut block_sandbox = MxcLinuxSandbox::new(&block_config).unwrap();
        SandboxImpl::start(&mut block_sandbox).unwrap();
        let block_code = SandboxImpl::wait(&mut block_sandbox).await.unwrap();
        let block_stderr =
            fs::read_to_string(block_workspace.join("stderr.log")).unwrap_or_default();
        assert_eq!(
            block_code, 0,
            "MXC block-mode probe failed:\n{block_stderr}"
        );
        assert_eq!(
            fs::read_to_string(block_workspace.join("stdout.log")).unwrap(),
            "block-stdout\n"
        );
        assert!(block_workspace.join("block-ok").exists());
        block_sandbox.destroy().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gated_real_mxc_native_proxy_reaches_only_axis_proxy_address() {
        if std::env::var("AXIS_REAL_MXC_PROXY_TESTS").as_deref() != Ok("1") {
            eprintln!("AXIS_REAL_MXC_PROXY_TESTS=1 not set (test skipped)");
            return;
        }
        if MxcExecutor::resolve().is_err() {
            panic!("AXIS_REAL_MXC_PROXY_TESTS=1 requires a safe lxc-exec");
        }
        if MxcSeccompLauncher::resolve().is_err() {
            panic!("AXIS_REAL_MXC_PROXY_TESTS=1 requires axis-seccomp-launcher");
        }

        let Some(python) =
            find_on_path("python3").and_then(|path| std::fs::canonicalize(path).ok())
        else {
            panic!("AXIS_REAL_MXC_PROXY_TESTS=1 requires python3 on PATH");
        };

        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let proxy_port = free_tcp_port_with_adjacent_port();
        let denied_port = proxy_port + 1;
        let allocation = super::super::netns::proxy_netns_allocation(id, proxy_port);
        let mut config = config(
            mxc_representable_policy(NetworkMode::Proxy),
            workspace.path().into(),
        );
        config.id = id;
        config.command = python.to_string_lossy().into_owned();
        config.args = vec!["-c".into(), real_mxc_proxy_probe().into()];
        config.working_dir = Some(workspace.path().into());
        config.capture_output = true;
        config.timeout_sec = Some(10);
        config.proxy_port = proxy_port;
        config.proxy_addr = Some(allocation.proxy_addr);
        config.policy.process.max_processes = 0;
        config.policy.process.max_memory_mb = 0;
        config.policy.process.cpu_rate_percent = 0;
        config.env = vec![
            ("PATH".into(), "/usr/bin:/bin".into()),
            (
                "AXIS_EXPECT_PROXY_HOST".into(),
                allocation.host_addr.to_string(),
            ),
            ("AXIS_EXPECT_PROXY_PORT".into(), proxy_port.to_string()),
            ("AXIS_DENIED_HOST_PORT".into(), denied_port.to_string()),
            ("HTTP_PROXY".into(), "http://proxy-with-creds".into()),
        ];

        let mut sandbox = MxcLinuxSandbox::new(&config).unwrap();
        SandboxImpl::start(&mut sandbox).unwrap();
        let listener = TcpListener::bind((allocation.host_addr, proxy_port)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let denied_listener = TcpListener::bind((allocation.host_addr, denied_port)).unwrap();
        denied_listener.set_nonblocking(true).unwrap();
        assert!(
            listener_observed_probe(&listener),
            "MXC proxy sandbox did not reach host-veth proxy listener"
        );
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();
        let stderr = fs::read_to_string(workspace.path().join("stderr.log")).unwrap_or_default();

        assert_eq!(code, 0, "MXC proxy probe failed:\n{stderr}");
        assert!(
            !listener_observed_probe_with_timeout(&denied_listener, Duration::from_millis(500)),
            "MXC proxy sandbox reached non-proxy host-veth port"
        );
        assert!(workspace.path().join("mxc-proxy-ok").exists());
        sandbox.destroy().unwrap();
    }

    fn endpoint_policy() -> EndpointPolicy {
        EndpointPolicy {
            name: "github".into(),
            endpoints: vec![Endpoint {
                host: "github.com".into(),
                port: 443,
                access: Access::ReadOnly,
                protocol: None,
                rules: Vec::new(),
            }],
            binaries: Vec::new(),
        }
    }

    fn mxc_representable_policy(network_mode: NetworkMode) -> Policy {
        let mut policy = policy(network_mode);
        policy.filesystem = FilesystemPolicy {
            read_only: vec!["/".into()],
            read_write: vec!["{workspace}".into()],
            compatibility: Compatibility::HardRequirement,
            ..FilesystemPolicy::default()
        };
        policy
    }

    fn mxc_filesystem_policy(
        network_mode: NetworkMode,
        rw_dir: &Path,
        denied_dir: &Path,
    ) -> Policy {
        let mut policy = mxc_representable_policy(network_mode);
        policy
            .filesystem
            .read_write
            .push(rw_dir.to_string_lossy().into_owned());
        policy
            .filesystem
            .deny
            .push(denied_dir.to_string_lossy().into_owned());
        policy
    }

    fn native_mxc_proxy_strategies(
        id: SandboxId,
        proxy_port: u16,
    ) -> (strategy::NetworkStrategy, strategy::ProxyStrategy) {
        mxc_proxy_strategies(
            id,
            proxy_port,
            strategy::ProxyNetworkSetup::IpNetnsWithCapNetAdmin,
        )
    }

    fn helper_mxc_proxy_strategies(
        id: SandboxId,
        proxy_port: u16,
    ) -> (strategy::NetworkStrategy, strategy::ProxyStrategy) {
        mxc_proxy_strategies(
            id,
            proxy_port,
            strategy::ProxyNetworkSetup::AxisNetnsHelperLaunch,
        )
    }

    fn mxc_proxy_strategies(
        id: SandboxId,
        proxy_port: u16,
        setup: strategy::ProxyNetworkSetup,
    ) -> (strategy::NetworkStrategy, strategy::ProxyStrategy) {
        let allocation = super::super::netns::proxy_netns_allocation(id, proxy_port);
        (
            strategy::NetworkStrategy::Proxy {
                setup,
                firewall: Some(strategy::FirewallTool::Iptables),
                host_addr: allocation.host_addr,
                sandbox_addr: allocation.sandbox_addr,
                proxy_port,
            },
            strategy::ProxyStrategy::Required {
                bind_addr: allocation.host_addr,
                sandbox_addr: allocation.host_addr,
                port: proxy_port,
            },
        )
    }

    fn temp_cgroup(root: &Path, config: &SandboxConfig) -> resources::CgroupHandle {
        let cgroup = resources::create_cgroup_at(root, config.id, &config.policy.process)
            .expect("temp cgroup should be created");
        fs::write(cgroup.path().join("cgroup.procs"), "").unwrap();
        cgroup
    }

    fn cgroup_resource_strategy() -> strategy::ResourceStrategy {
        strategy::ResourceStrategy::CgroupsV2 {
            support: strategy::CgroupV2Support::Writable,
        }
    }

    fn inject_failing_netns_cleanup(sandbox: &mut MxcLinuxSandbox) {
        sandbox.netns_name = Some("axis-test-netns".into());
        sandbox.netns_cleanup_result = Some(Err("destroy failed".into()));
    }

    fn fake_mxc_runtime_executor(root: &tempfile::TempDir, run_script: &str) -> MxcExecutor {
        let executable = root.path().join("lxc-exec");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 mode=run\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$arg\" = '--dry-run' ]; then mode=dry; fi\n\
                 done\n\
                 if [ \"$mode\" = dry ]; then\n\
                   echo '{}'\n\
                   exit 0\n\
                 fi\n\
                 {run_script}\n",
                MXC_DRY_RUN_SUCCESS
            ),
            0o700,
        );
        MxcExecutor::from_injected_path(&executable).unwrap()
    }

    fn reap_child(pid: u32) {
        loop {
            let ret = unsafe { libc::waitpid(pid as libc::pid_t, std::ptr::null_mut(), 0) };
            if ret == pid as libc::pid_t {
                return;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            panic!("waitpid({pid}) failed: {err}");
        }
    }

    fn remaining_dir_entries(path: &Path) -> Vec<String> {
        match fs::read_dir(path) {
            Ok(entries) => entries
                .map(|entry| {
                    entry
                        .map(|entry| entry.file_name().to_string_lossy().into_owned())
                        .unwrap_or_else(|err| format!("<error: {err}>"))
                })
                .collect(),
            Err(err) => vec![format!("<read_dir: {err}>")],
        }
    }

    fn path_string(path: &Path) -> String {
        path.to_string_lossy().into_owned()
    }

    fn write_executable(path: &Path, script: &str, mode: u32) {
        let parent = path.parent().expect("test executable should have a parent");
        let mut file = tempfile::NamedTempFile::new_in(parent).unwrap();
        file.write_all(script.as_bytes()).unwrap();
        file.flush().unwrap();
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(mode))
            .unwrap();
        file.persist(path).unwrap();
    }

    fn fake_seccomp_launcher(root: &tempfile::TempDir) -> MxcSeccompLauncher {
        let executable = root.path().join("axis-seccomp-launcher");
        write_executable(&executable, "#!/bin/sh\nexit 127\n", 0o700);
        MxcSeccompLauncher::from_injected_path(&executable).unwrap()
    }

    fn secure_tempdir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn assert_unsafe_candidate(path: &Path, expected_reason: &str) {
        let err = MxcExecutor::from_injected_path(path).unwrap_err();
        let MxcExecutorError::UnsafeCandidate { reason, .. } = err else {
            panic!("expected unsafe candidate error, got {err:?}");
        };
        assert!(
            reason.contains(expected_reason),
            "expected reason containing '{expected_reason}', got '{reason}'"
        );
    }

    fn shell_quote_path(path: &Path) -> String {
        shell_quote_arg(&path.to_string_lossy())
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

    fn free_tcp_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn free_tcp_port_with_adjacent_port() -> u16 {
        loop {
            let port = free_tcp_port();
            if port < u16::MAX {
                return port;
            }
        }
    }

    fn listener_observed_probe(listener: &TcpListener) -> bool {
        listener_observed_probe_with_timeout(listener, Duration::from_secs(3))
    }

    fn listener_observed_probe_with_timeout(listener: &TcpListener, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            match listener.accept() {
                Ok((_stream, _addr)) => return true,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Err(err) => panic!("listener accept failed: {err}"),
            }
        }
    }

    fn real_mxc_allow_probe() -> &'static str {
        r#"
import os
import pathlib
import socket
import sys

assert os.environ["CUSTOM"] == "kept"
for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    if key in os.environ:
        print(f"unexpected proxy env: {key}", file=sys.stderr)
        sys.exit(10)
assert sys.stdin.read() == ""

ro_file = pathlib.Path(os.environ["RO_FILE"])
rw_dir = pathlib.Path(os.environ["RW_DIR"])
denied_file = pathlib.Path(os.environ["DENIED_FILE"])
denied_dir = pathlib.Path(os.environ["DENIED_DIR"])
assert ro_file.read_text() == "read-only"
try:
    ro_file.write_text("mutated")
except OSError:
    pass
else:
    print("read-only file was writable", file=sys.stderr)
    sys.exit(11)
rw_dir.joinpath("rw.txt").write_text("rw")
pathlib.Path("workspace.txt").write_text("workspace")
try:
    denied_file.read_text()
except OSError:
    pass
else:
    print("denied file was readable", file=sys.stderr)
    sys.exit(12)
try:
    denied_dir.joinpath("new.txt").write_text("denied-write")
except OSError:
    pass
else:
    print("denied directory was writable", file=sys.stderr)
    sys.exit(13)

sock = socket.create_connection(("127.0.0.1", int(os.environ["ALLOW_PORT"])), 3)
sock.sendall(b"allow-probe")
sock.close()
print("allow-stdout")
"#
    }

    fn real_mxc_block_probe() -> &'static str {
        r#"
import os
import pathlib
import socket
import sys

for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy"):
    if key in os.environ:
        print(f"unexpected proxy env: {key}", file=sys.stderr)
        sys.exit(20)

port = int(os.environ["BLOCK_PORT"])
for address in (("127.0.0.1", port), ("::1", port)):
    try:
        sock = socket.create_connection(address, 1)
    except OSError:
        pass
    else:
        sock.close()
        print(f"network connection unexpectedly succeeded: {address}", file=sys.stderr)
        sys.exit(21)

left, right = socket.socketpair()
left.close()
right.close()
pathlib.Path("block-ok").write_text("ok")
print("block-stdout")
"#
    }

    fn real_mxc_proxy_probe() -> &'static str {
        r#"
import os
import pathlib
import socket
import sys
import time

host = os.environ["AXIS_EXPECT_PROXY_HOST"]
port = int(os.environ["AXIS_EXPECT_PROXY_PORT"])
denied_port = int(os.environ["AXIS_DENIED_HOST_PORT"])
expected_proxy = f"http://{host}:{port}"
for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    assert os.environ.get(key) == expected_proxy, (key, os.environ.get(key), expected_proxy)
for key in ("NO_PROXY", "no_proxy"):
    assert os.environ.get(key) == "localhost,127.0.0.1,::1", (key, os.environ.get(key))

deadline = time.time() + 3
while True:
    try:
        sock = socket.create_connection((host, port), 0.25)
    except OSError:
        if time.time() >= deadline:
            raise
        time.sleep(0.05)
    else:
        break
sock.sendall(b"mxc-proxy-probe")
sock.close()

try:
    denied = socket.create_connection((host, denied_port), 1)
except OSError:
    pass
else:
    denied.close()
    print("direct non-proxy host-veth port was reachable", file=sys.stderr)
    sys.exit(30)

pathlib.Path("mxc-proxy-ok").write_text("ok")
"#
    }

    fn with_parent_secret_env<T>(f: impl FnOnce() -> T) -> T {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        struct EnvGuard(Option<OsString>);
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                // SAFETY: guarded by ENV_LOCK for the duration of the test.
                unsafe {
                    if let Some(value) = &self.0 {
                        std::env::set_var("ANTHROPIC_API_KEY", value);
                    } else {
                        std::env::remove_var("ANTHROPIC_API_KEY");
                    }
                }
            }
        }

        let previous = std::env::var_os("ANTHROPIC_API_KEY");
        // SAFETY: this test serializes process-environment mutation with a
        // module-local mutex and restores the variable before releasing it.
        unsafe {
            std::env::set_var("ANTHROPIC_API_KEY", "inherited-secret");
        }
        let _env_guard = EnvGuard(previous);
        f()
    }

    fn assert_process_stopped(pid: i32) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while process_is_running(pid) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!process_is_running(pid), "process {pid} is still running");
    }

    fn process_is_running(pid: i32) -> bool {
        if let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat"))
            && let Some((_, rest)) = stat.rsplit_once(") ")
            && let Some(state) = rest.split_whitespace().next()
        {
            return state != "Z";
        }

        // SAFETY: kill(pid, 0) performs existence/permission probing only and
        // does not deliver a signal.
        unsafe { libc::kill(pid, 0) == 0 }
    }
}
