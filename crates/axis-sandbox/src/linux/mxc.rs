// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Linux MXC configuration translation.
//!
//! This module is the first MXC migration layer: it converts AXIS sandbox
//! policy into an AXIS-owned MXC JSON shape without changing runtime backend
//! selection. Unsupported AXIS guarantees fail before launch instead of being
//! mapped to weaker MXC behavior.

use crate::sandbox::SandboxConfig;
use axis_core::policy::{Compatibility, FilesystemPolicy, NetworkMode, Policy};
use serde::Serialize;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
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
const MXC_DRY_RUN_SUCCESS: &str = "Dry run completed. Result: validation passed";
const MAX_DRY_RUN_OUTPUT_BYTES: u64 = 64 * 1024;

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

    #[error("MXC dry-run config contains environment entry filtered by AXIS sandbox policy: {key}")]
    FilteredEnv { key: String },

    #[error("MXC dry-run config contains malformed environment entry")]
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
        validate_spec_env_for_dry_run(spec)?;

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxcDryRunResult {
    pub stdout: String,
    pub stderr: String,
}

impl MxcExecutionSpec {
    pub fn from_sandbox_config(config: &SandboxConfig) -> Result<Self, MxcTranslationError> {
        let spec = translate_sandbox_config(config)?;
        reject_current_bubblewrap_filesystem_substrate(&spec.filesystem)?;
        Ok(spec)
    }
}

fn translate_sandbox_config(
    config: &SandboxConfig,
) -> Result<MxcExecutionSpec, MxcTranslationError> {
    let process = translate_process(config)?;
    let network = translate_network(&config.policy)?;
    let filesystem = translate_filesystem(&config.policy.filesystem, &config.workspace_dir)?;

    Ok(MxcExecutionSpec {
        version: MXC_SCHEMA_VERSION.into(),
        platform: MXC_LINUX_PLATFORM.into(),
        containment: MXC_BUBBLEWRAP_CONTAINMENT.into(),
        process,
        filesystem,
        network,
    })
}

fn reject_current_bubblewrap_filesystem_substrate(
    _filesystem: &MxcFilesystem,
) -> Result<(), MxcTranslationError> {
    Err(MxcTranslationError::FilesystemDefaultDenyUnsupported)
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
) -> Result<MxcFilesystem, MxcTranslationError> {
    let expanded = super::landlock::expand_and_validate_filesystem_policy(policy, workspace)
        .map_err(MxcTranslationError::Filesystem)?;
    let workspace = std::fs::canonicalize(workspace).map_err(|e| {
        MxcTranslationError::Filesystem(format!(
            "workspace '{}' cannot be canonicalized: {e}",
            workspace.display()
        ))
    })?;
    let mut readwrite_paths = represented_paths(policy, &expanded.read_write)?;
    push_unique(&mut readwrite_paths, path_to_string(&workspace)?);

    Ok(MxcFilesystem {
        readwrite_paths,
        readonly_paths: represented_paths(policy, &expanded.read_only)?,
        denied_paths: represented_paths(policy, &expanded.deny)?,
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

fn translate_network(policy: &Policy) -> Result<MxcNetwork, MxcTranslationError> {
    let default_policy = match policy.network.mode {
        NetworkMode::Allow => {
            reject_endpoint_policies(policy, "allow")?;
            MxcNetworkDefaultPolicy::Allow
        }
        NetworkMode::Block => {
            reject_endpoint_policies(policy, "block")?;
            MxcNetworkDefaultPolicy::Block
        }
        NetworkMode::Proxy => {
            return Err(MxcTranslationError::ProxyModeUnsupported(
                "MXC Bubblewrap proxy mode is cooperative env-var routing and does not preserve AXIS strict proxy isolation".into(),
            ));
        }
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
    if !path.is_absolute() {
        return Err(unsafe_candidate(path, "path must be absolute"));
    }

    // SAFETY: geteuid(2) has no preconditions and only reads process state.
    let trusted_uid = unsafe { libc::geteuid() };
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|err| {
            if current == path && err.kind() == std::io::ErrorKind::NotFound {
                unsafe_candidate(path, "candidate does not exist")
            } else {
                unsafe_candidate(
                    path,
                    format!("could not inspect '{}': {err}", current.display()),
                )
            }
        })?;

        if metadata.file_type().is_symlink() {
            return Err(unsafe_candidate(
                path,
                format!("path component '{}' is a symlink", current.display()),
            ));
        }
        let mode_bits = metadata.permissions().mode();
        let uid = metadata.uid();
        let injected_sticky_ancestor = current != path
            && metadata.is_dir()
            && allows_sticky_writable_ancestor(mode_bits, validation_mode);
        if current != Path::new("/") && uid != 0 && uid != trusted_uid && !injected_sticky_ancestor
        {
            return Err(unsafe_candidate(
                path,
                format!(
                    "path component '{}' is not owned by root or the current user",
                    current.display()
                ),
            ));
        }

        if current == path {
            if !metadata.is_file() {
                return Err(unsafe_candidate(path, "candidate is not a regular file"));
            }
            if mode_bits & 0o111 == 0 {
                return Err(unsafe_candidate(path, "candidate is not executable"));
            }
            if mode_bits & 0o022 != 0 {
                return Err(unsafe_candidate(
                    path,
                    format!(
                        "path component '{}' is group- or world-writable",
                        current.display()
                    ),
                ));
            }
        } else if !metadata.is_dir() {
            return Err(unsafe_candidate(
                path,
                format!("path component '{}' is not a directory", current.display()),
            ));
        } else if mode_bits & 0o022 != 0
            && !allows_sticky_writable_ancestor(mode_bits, validation_mode)
        {
            return Err(unsafe_candidate(
                path,
                format!(
                    "path component '{}' is group- or world-writable",
                    current.display()
                ),
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

fn validate_spec_env_for_dry_run(spec: &MxcExecutionSpec) -> Result<(), MxcExecutorError> {
    let mut parsed = Vec::with_capacity(spec.process.env.len());
    for entry in &spec.process.env {
        let Some((key, value)) = entry.split_once('=') else {
            return Err(MxcExecutorError::MalformedEnv);
        };
        parsed.push((key.to_string(), value.to_string()));
    }

    let original = parsed.clone();
    axis_core::sandbox_env::retain_linux_sandbox_env(&mut parsed);
    if parsed == original {
        return Ok(());
    }

    let filtered_key = original
        .iter()
        .find(|candidate| !parsed.iter().any(|retained| retained.0 == candidate.0))
        .map(|(key, _)| key.clone())
        .unwrap_or_else(|| "<unknown>".into());
    Err(MxcExecutorError::FilteredEnv { key: filtered_key })
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
                // SAFETY: kill(2) is called with a negative process-group id
                // derived from the child pid after the child was placed into
                // its own group by the pre_exec setpgid hook.
                unsafe {
                    libc::kill(-process_group, libc::SIGKILL);
                }
            }
            let _ = child.kill();
            let _ = child.wait();
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

#[cfg(test)]
mod tests {
    use super::*;
    use axis_core::policy::{
        Access, Endpoint, EndpointPolicy, FilesystemPolicy, GpuPolicy, InferencePolicy,
        NetworkPolicy, ProcessPolicy, SshPolicy,
    };
    use axis_core::types::SandboxId;
    use std::ffi::OsString;
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

    fn path_string(path: &Path) -> String {
        path.to_string_lossy().into_owned()
    }

    fn write_executable(path: &Path, script: &str, mode: u32) {
        fs::write(path, script).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
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
