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
use std::path::Path;
use thiserror::Error;

const MXC_SCHEMA_VERSION: &str = "0.6.0-alpha";
const MXC_LINUX_PLATFORM: &str = "linux";
const MXC_BUBBLEWRAP_CONTAINMENT: &str = "bubblewrap";

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MxcExecutionSpec {
    pub version: String,
    pub platform: String,
    pub containment: String,
    pub process: MxcProcess,
    pub filesystem: MxcFilesystem,
    pub network: MxcNetwork,
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
}
