// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! MXC wire configuration shapes.
//!
//! This module keeps MXC JSON generation platform-neutral where the shared
//! backend planner has already approved the AXIS policy and launch inputs.
//! Platform adapters remain responsible for spawning executors and for any
//! AXIS-owned layers around the MXC process.

use crate::container_backend::{
    ContainerBackendConfigFormat, ContainerBackendExecutionSpec, ContainerBackendNetworkMode,
    ContainerMountAccess, ContainerRootfsSource,
};
use crate::process_backend::{
    ProcessBackendConfigFormat, ProcessBackendExecutionSpec, ProcessBackendNetworkMode,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

pub const MXC_CONFIG_VERSION: &str = "0.6.0-alpha";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MxcConfigError {
    #[error("MXC process command line must not be empty")]
    EmptyCommandLine,

    #[error("MXC process environment entry must be KEY=VALUE with a non-empty key")]
    InvalidEnvironmentEntry,

    #[error(
        "AXIS strict proxy must be enforced outside MXC before emitting allow-mode MXC network config"
    )]
    StrictProxyRequiresAxisLayer,

    #[error("MXC config cannot represent endpoint policies outside AXIS strict proxy mode")]
    EndpointPolicyRequiresStrictProxy,

    #[error("MXC process config cannot use native AXIS backend '{backend}'")]
    NativeProcessBackendUnsupported { backend: String },

    #[error("MXC process timeout {timeout_ms}ms exceeds the MXC wire limit")]
    ProcessTimeoutOverflow { timeout_ms: u64 },

    #[error("MXC LXC config requires a distribution/release rootfs source")]
    LxcRootfsRequired,

    #[error("MXC WSLC config requires a WSL image or image tar rootfs source")]
    WslcImageRequired,

    #[error("MXC WSLC config cannot represent AXIS container bind mounts")]
    WslcBindMountsUnsupported,

    #[error(
        "MXC container config cannot represent bind mount aliases: {host_path} -> {container_path}"
    )]
    BindMountAliasUnsupported {
        host_path: String,
        container_path: String,
    },

    #[error(
        "MXC container config bind mount '{host_path}' is not granted by AXIS filesystem policy"
    )]
    BindMountNotGranted { host_path: String },

    #[error("MXC WSLC config cannot represent AXIS per-sandbox resource limits exactly")]
    WslcResourceLimitsUnsupported,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MxcContainerConfigOptions {
    pub container_id: Option<String>,
    pub strict_proxy_enforced_by_axis: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MxcProcessConfigOptions {
    pub container_id: Option<String>,
    pub strict_proxy_enforced_by_axis: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcProcessConfig {
    #[serde(rename = "commandLine")]
    pub command_line: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcContainerWireConfig {
    pub version: String,
    #[serde(rename = "containerId", skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    pub containment: MxcContainment,
    pub platform: MxcPlatform,
    pub process: MxcProcessConfig,
    pub filesystem: MxcFilesystemConfig,
    pub network: MxcNetworkConfig,
    pub lifecycle: MxcLifecycleConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lxc: Option<MxcLxcConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<MxcExperimentalConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcProcessWireConfig {
    pub version: String,
    #[serde(rename = "containerId", skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    pub containment: MxcContainment,
    pub platform: MxcPlatform,
    pub process: MxcProcessConfig,
    pub filesystem: MxcFilesystemConfig,
    pub network: MxcNetworkConfig,
    pub lifecycle: MxcLifecycleConfig,
    #[serde(rename = "processContainer", skip_serializing_if = "Option::is_none")]
    pub process_container: Option<MxcProcessContainerConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback: Option<MxcFallbackConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<MxcExperimentalConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MxcContainment {
    Bubblewrap,
    Lxc,
    #[serde(rename = "processcontainer")]
    ProcessContainer,
    Seatbelt,
    Wslc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MxcPlatform {
    Linux,
    Macos,
    Windows,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcFilesystemConfig {
    #[serde(rename = "readwritePaths", default)]
    pub readwrite_paths: Vec<String>,
    #[serde(rename = "readonlyPaths", default)]
    pub readonly_paths: Vec<String>,
    #[serde(rename = "deniedPaths", default)]
    pub denied_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcNetworkConfig {
    #[serde(rename = "defaultPolicy")]
    pub default_policy: MxcNetworkDefaultPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MxcNetworkDefaultPolicy {
    Allow,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcLifecycleConfig {
    #[serde(rename = "destroyOnExit")]
    pub destroy_on_exit: bool,
    #[serde(rename = "preservePolicy")]
    pub preserve_policy: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcProcessContainerConfig {
    #[serde(rename = "leastPrivilege")]
    pub least_privilege: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcFallbackConfig {
    #[serde(rename = "allowDaclMutation")]
    pub allow_dacl_mutation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcLxcConfig {
    pub distribution: String,
    pub release: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcExperimentalConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wslc: Option<MxcWslcConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seatbelt: Option<MxcSeatbeltConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcWslcConfig {
    #[serde(rename = "targetOs")]
    pub target_os: String,
    pub image: String,
    #[serde(rename = "imageTarPath", skip_serializing_if = "Option::is_none")]
    pub image_tar_path: Option<String>,
    #[serde(rename = "storagePath", skip_serializing_if = "Option::is_none")]
    pub storage_path: Option<String>,
    pub gpu: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcSeatbeltConfig {
    #[serde(rename = "profileOverride", skip_serializing_if = "Option::is_none")]
    pub profile_override: Option<String>,
    #[serde(rename = "guiAccess")]
    pub gui_access: bool,
    #[serde(rename = "launchMethod")]
    pub launch_method: MxcSeatbeltLaunchMethod,
    #[serde(rename = "nestedPty")]
    pub nested_pty: bool,
    #[serde(rename = "keychainAccess")]
    pub keychain_access: bool,
    #[serde(
        rename = "extraMachLookups",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub extra_mach_lookups: Vec<String>,
}

impl Default for MxcSeatbeltConfig {
    fn default() -> Self {
        Self {
            profile_override: None,
            gui_access: false,
            launch_method: MxcSeatbeltLaunchMethod::Exec,
            nested_pty: false,
            keychain_access: false,
            extra_mach_lookups: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MxcSeatbeltLaunchMethod {
    Exec,
    Open,
}

pub fn build_mxc_container_config(
    process: MxcProcessConfig,
    spec: &ContainerBackendExecutionSpec,
    options: MxcContainerConfigOptions,
) -> Result<MxcContainerWireConfig, MxcConfigError> {
    validate_process_config(&process)?;
    validate_container_network(spec, &options)?;
    validate_bind_mounts(spec)?;

    let filesystem = MxcFilesystemConfig {
        readwrite_paths: spec.filesystem.read_write.clone(),
        readonly_paths: spec.filesystem.read_only.clone(),
        denied_paths: spec.filesystem.deny.clone(),
    };
    let network = MxcNetworkConfig {
        default_policy: mxc_network_policy(spec, &options)?,
    };
    let lifecycle = MxcLifecycleConfig {
        destroy_on_exit: spec.destroy_on_exit,
        preserve_policy: false,
    };

    match spec.config_format {
        ContainerBackendConfigFormat::MxcLinuxLxcJson => {
            let (distribution, release) = lxc_distribution_release(spec)?;
            Ok(MxcContainerWireConfig {
                version: MXC_CONFIG_VERSION.into(),
                container_id: options.container_id,
                containment: MxcContainment::Lxc,
                platform: MxcPlatform::Linux,
                process,
                filesystem,
                network,
                lifecycle,
                lxc: Some(MxcLxcConfig {
                    distribution: distribution.into(),
                    release: release.into(),
                }),
                experimental: None,
            })
        }
        ContainerBackendConfigFormat::MxcWindowsWslcJson => {
            let wslc = wslc_config(spec)?;
            Ok(MxcContainerWireConfig {
                version: MXC_CONFIG_VERSION.into(),
                container_id: options.container_id,
                containment: MxcContainment::Wslc,
                platform: MxcPlatform::Windows,
                process,
                filesystem,
                network,
                lifecycle,
                lxc: None,
                experimental: Some(MxcExperimentalConfig {
                    wslc: Some(wslc),
                    ..Default::default()
                }),
            })
        }
    }
}

pub fn build_mxc_process_config(
    command_line: impl Into<String>,
    spec: &ProcessBackendExecutionSpec,
    options: MxcProcessConfigOptions,
) -> Result<MxcProcessWireConfig, MxcConfigError> {
    validate_process_network(spec, &options)?;
    let process = process_config_for_process_spec(command_line.into(), spec)?;
    let filesystem = MxcFilesystemConfig {
        readwrite_paths: spec.filesystem.read_write.clone(),
        readonly_paths: spec.filesystem.read_only.clone(),
        denied_paths: spec.filesystem.deny.clone(),
    };
    let network = MxcNetworkConfig {
        default_policy: mxc_process_network_policy(spec, &options)?,
    };
    let lifecycle = MxcLifecycleConfig {
        destroy_on_exit: true,
        preserve_policy: false,
    };

    match spec.config_format {
        ProcessBackendConfigFormat::MxcLinuxJson => Ok(MxcProcessWireConfig {
            version: MXC_CONFIG_VERSION.into(),
            container_id: options.container_id,
            containment: MxcContainment::Bubblewrap,
            platform: MxcPlatform::Linux,
            process,
            filesystem,
            network,
            lifecycle,
            process_container: None,
            fallback: None,
            experimental: None,
        }),
        ProcessBackendConfigFormat::MxcWindowsProcessContainer => Ok(MxcProcessWireConfig {
            version: MXC_CONFIG_VERSION.into(),
            container_id: options.container_id,
            containment: MxcContainment::ProcessContainer,
            platform: MxcPlatform::Windows,
            process,
            filesystem,
            network,
            lifecycle,
            process_container: Some(MxcProcessContainerConfig::default()),
            fallback: Some(MxcFallbackConfig {
                allow_dacl_mutation: false,
            }),
            experimental: None,
        }),
        ProcessBackendConfigFormat::MxcMacosSeatbeltProfile => Ok(MxcProcessWireConfig {
            version: MXC_CONFIG_VERSION.into(),
            container_id: options.container_id,
            containment: MxcContainment::Seatbelt,
            platform: MxcPlatform::Macos,
            process,
            filesystem,
            network,
            lifecycle,
            process_container: None,
            fallback: None,
            experimental: Some(MxcExperimentalConfig {
                seatbelt: Some(MxcSeatbeltConfig::default()),
                ..Default::default()
            }),
        }),
        ProcessBackendConfigFormat::AxisNativeLinux
        | ProcessBackendConfigFormat::AxisNativeMacosSeatbeltProfile
        | ProcessBackendConfigFormat::AxisNativeWindowsProcess => {
            Err(MxcConfigError::NativeProcessBackendUnsupported {
                backend: spec.backend.clone(),
            })
        }
    }
}

fn process_config_for_process_spec(
    command_line: String,
    spec: &ProcessBackendExecutionSpec,
) -> Result<MxcProcessConfig, MxcConfigError> {
    let timeout = match spec.timeout_ms {
        Some(timeout_ms) if timeout_ms > u32::MAX.into() => {
            return Err(MxcConfigError::ProcessTimeoutOverflow { timeout_ms });
        }
        Some(timeout_ms) => Some(timeout_ms as u32),
        None => None,
    };
    let process = MxcProcessConfig {
        command_line,
        cwd: spec.working_dir.clone(),
        env: spec
            .environment
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect(),
        timeout,
    };

    validate_process_config(&process)?;
    Ok(process)
}

fn validate_process_config(process: &MxcProcessConfig) -> Result<(), MxcConfigError> {
    if process.command_line.trim().is_empty() {
        return Err(MxcConfigError::EmptyCommandLine);
    }

    if process.env.iter().any(|entry| {
        let Some((key, _value)) = entry.split_once('=') else {
            return true;
        };
        key.trim().is_empty()
    }) {
        return Err(MxcConfigError::InvalidEnvironmentEntry);
    }

    Ok(())
}

fn validate_process_network(
    spec: &ProcessBackendExecutionSpec,
    options: &MxcProcessConfigOptions,
) -> Result<(), MxcConfigError> {
    let has_endpoint_policy =
        !spec.network.endpoint_policy_names.is_empty() || spec.network.binary_attribution_required;
    if has_endpoint_policy && spec.network.mode != ProcessBackendNetworkMode::StrictProxy {
        return Err(MxcConfigError::EndpointPolicyRequiresStrictProxy);
    }
    if spec.network.mode == ProcessBackendNetworkMode::StrictProxy
        && !options.strict_proxy_enforced_by_axis
    {
        return Err(MxcConfigError::StrictProxyRequiresAxisLayer);
    }
    Ok(())
}

fn validate_container_network(
    spec: &ContainerBackendExecutionSpec,
    options: &MxcContainerConfigOptions,
) -> Result<(), MxcConfigError> {
    let has_endpoint_policy =
        !spec.network.endpoint_policy_names.is_empty() || spec.network.binary_attribution_required;
    if has_endpoint_policy && spec.network.mode != ContainerBackendNetworkMode::StrictProxy {
        return Err(MxcConfigError::EndpointPolicyRequiresStrictProxy);
    }
    if spec.network.mode == ContainerBackendNetworkMode::StrictProxy
        && !options.strict_proxy_enforced_by_axis
    {
        return Err(MxcConfigError::StrictProxyRequiresAxisLayer);
    }
    Ok(())
}

fn validate_bind_mounts(spec: &ContainerBackendExecutionSpec) -> Result<(), MxcConfigError> {
    if spec.config_format == ContainerBackendConfigFormat::MxcWindowsWslcJson
        && !spec.bind_mounts.is_empty()
    {
        return Err(MxcConfigError::WslcBindMountsUnsupported);
    }

    for mount in &spec.bind_mounts {
        if Path::new(&mount.host_path) != Path::new(&mount.container_path) {
            return Err(MxcConfigError::BindMountAliasUnsupported {
                host_path: mount.host_path.clone(),
                container_path: mount.container_path.clone(),
            });
        }

        let granted = match mount.access {
            ContainerMountAccess::ReadOnly => spec
                .filesystem
                .read_only
                .iter()
                .any(|path| Path::new(path) == Path::new(&mount.host_path)),
            ContainerMountAccess::ReadWrite => spec
                .filesystem
                .read_write
                .iter()
                .any(|path| Path::new(path) == Path::new(&mount.host_path)),
        };
        if !granted {
            return Err(MxcConfigError::BindMountNotGranted {
                host_path: mount.host_path.clone(),
            });
        }
    }

    Ok(())
}

fn mxc_process_network_policy(
    spec: &ProcessBackendExecutionSpec,
    options: &MxcProcessConfigOptions,
) -> Result<MxcNetworkDefaultPolicy, MxcConfigError> {
    match spec.network.mode {
        ProcessBackendNetworkMode::Allow => Ok(MxcNetworkDefaultPolicy::Allow),
        ProcessBackendNetworkMode::Block => Ok(MxcNetworkDefaultPolicy::Block),
        ProcessBackendNetworkMode::StrictProxy if options.strict_proxy_enforced_by_axis => {
            Ok(MxcNetworkDefaultPolicy::Allow)
        }
        ProcessBackendNetworkMode::StrictProxy => Err(MxcConfigError::StrictProxyRequiresAxisLayer),
    }
}

fn mxc_network_policy(
    spec: &ContainerBackendExecutionSpec,
    options: &MxcContainerConfigOptions,
) -> Result<MxcNetworkDefaultPolicy, MxcConfigError> {
    match spec.network.mode {
        ContainerBackendNetworkMode::Allow => Ok(MxcNetworkDefaultPolicy::Allow),
        ContainerBackendNetworkMode::Block => Ok(MxcNetworkDefaultPolicy::Block),
        ContainerBackendNetworkMode::StrictProxy if options.strict_proxy_enforced_by_axis => {
            Ok(MxcNetworkDefaultPolicy::Allow)
        }
        ContainerBackendNetworkMode::StrictProxy => {
            Err(MxcConfigError::StrictProxyRequiresAxisLayer)
        }
    }
}

fn lxc_distribution_release(
    spec: &ContainerBackendExecutionSpec,
) -> Result<(&str, &str), MxcConfigError> {
    let ContainerRootfsSource::LxcDistributionRelease {
        distribution,
        release,
    } = &spec.rootfs
    else {
        return Err(MxcConfigError::LxcRootfsRequired);
    };
    Ok((distribution, release))
}

fn wslc_config(spec: &ContainerBackendExecutionSpec) -> Result<MxcWslcConfig, MxcConfigError> {
    if spec.resources.max_processes != 0
        || spec.resources.max_memory_mb != 0
        || spec.resources.cpu_rate_percent != 0
    {
        return Err(MxcConfigError::WslcResourceLimitsUnsupported);
    }

    match &spec.rootfs {
        ContainerRootfsSource::WslImage { image } => Ok(MxcWslcConfig {
            target_os: "linux".into(),
            image: image.clone(),
            image_tar_path: None,
            storage_path: spec.storage_path.clone(),
            gpu: false,
        }),
        ContainerRootfsSource::WslImageTar {
            image,
            image_tar_path,
        } => Ok(MxcWslcConfig {
            target_os: "linux".into(),
            image: image.clone(),
            image_tar_path: Some(image_tar_path.clone()),
            storage_path: spec.storage_path.clone(),
            gpu: false,
        }),
        _ => Err(MxcConfigError::WslcImageRequired),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{DependencyState, PlannerOptions, RuntimeProbeSnapshot};
    use crate::capability_map::{BackendCapabilityMapId, backend_capability_map};
    use crate::container_backend::{
        ContainerBackendSpecError, ContainerBindMount, ContainerLaunchOptions,
        ContainerMountAccess, build_container_backend_execution_spec,
    };
    use crate::policy::{
        Access, BinaryMatch, Endpoint, EndpointPolicy, FilesystemPolicy, GpuPolicy,
        InferencePolicy, NetworkMode, NetworkPolicy, Policy, ProcessPolicy, SshPolicy,
    };
    use crate::process_backend::{
        ProcessBackendSpecError, ProcessLaunchOptions, build_process_backend_execution_spec,
    };
    use std::collections::BTreeMap;

    #[test]
    fn lxc_container_config_serializes_mxc_wire_shape() {
        let spec = lxc_execution_spec(NetworkMode::Block).unwrap();
        let config = build_mxc_container_config(process(), &spec, options("axis-lxc")).unwrap();
        let json = serde_json::to_value(&config).unwrap();

        assert_eq!(json["version"], MXC_CONFIG_VERSION);
        assert_eq!(json["containerId"], "axis-lxc");
        assert_eq!(json["containment"], "lxc");
        assert_eq!(json["platform"], "linux");
        assert_eq!(json["process"]["commandLine"], "echo container");
        assert_eq!(json["process"]["cwd"], "/workspace");
        assert_eq!(json["process"]["env"][0], "PATH=/usr/bin");
        assert_eq!(json["filesystem"]["readwritePaths"][0], "/workspace");
        assert_eq!(json["network"]["defaultPolicy"], "block");
        assert_eq!(json["lifecycle"]["destroyOnExit"], true);
        assert_eq!(json["lxc"]["distribution"], "alpine");
        assert_eq!(json["lxc"]["release"], "3.23");
        assert!(json.get("experimental").is_none());
    }

    #[test]
    fn wslc_container_config_serializes_experimental_wslc_shape() {
        let launch = ContainerLaunchOptions {
            rootfs: ContainerRootfsSource::WslImageTar {
                image: "alpine:latest".into(),
                image_tar_path: "C:\\images\\alpine.tar".into(),
            },
            storage_path: Some("C:\\axis\\wslc".into()),
            working_dir: None,
            bind_mounts: Vec::new(),
            destroy_on_exit: true,
        };
        let spec = build_container_backend_execution_spec(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcWindowsWslc,
            launch,
            &present_runtime_for_backend(BackendCapabilityMapId::MxcWindowsWslc),
            &PlannerOptions::new(),
        )
        .unwrap();

        let config = build_mxc_container_config(process(), &spec, options("axis-wslc")).unwrap();
        let json = serde_json::to_value(&config).unwrap();

        assert_eq!(json["containment"], "wslc");
        assert_eq!(json["platform"], "windows");
        assert!(json.get("lxc").is_none());
        assert_eq!(json["network"]["defaultPolicy"], "allow");
        assert_eq!(json["experimental"]["wslc"]["targetOs"], "linux");
        assert_eq!(json["experimental"]["wslc"]["image"], "alpine:latest");
        assert_eq!(
            json["experimental"]["wslc"]["imageTarPath"],
            "C:\\images\\alpine.tar"
        );
        assert_eq!(
            json["experimental"]["wslc"]["storagePath"],
            "C:\\axis\\wslc"
        );
        assert_eq!(json["experimental"]["wslc"]["gpu"], false);
    }

    #[test]
    fn bubblewrap_process_config_serializes_mxc_wire_shape() {
        let spec = process_execution_spec(
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            NetworkMode::Block,
        )
        .unwrap();
        let config =
            build_mxc_process_config("agent --version", &spec, process_options("axis-bwrap"))
                .unwrap();
        let json = serde_json::to_value(&config).unwrap();

        assert_eq!(json["version"], MXC_CONFIG_VERSION);
        assert_eq!(json["containerId"], "axis-bwrap");
        assert_eq!(json["containment"], "bubblewrap");
        assert_eq!(json["platform"], "linux");
        assert_eq!(json["process"]["commandLine"], "agent --version");
        assert_eq!(json["process"]["cwd"], "/workspace");
        assert_eq!(json["process"]["env"][0], "AXIS_TEST=1");
        assert_eq!(json["process"]["timeout"], 3000);
        assert_eq!(json["filesystem"]["readonlyPaths"][0], "/usr");
        assert_eq!(json["filesystem"]["readwritePaths"][0], "/workspace");
        assert_eq!(json["filesystem"]["deniedPaths"][0], "/home/user/.ssh");
        assert_eq!(json["network"]["defaultPolicy"], "block");
        assert_eq!(json["lifecycle"]["destroyOnExit"], true);
        assert_eq!(json["lifecycle"]["preservePolicy"], false);
        assert!(json.get("processContainer").is_none());
        assert!(json.get("fallback").is_none());
        assert!(json.get("experimental").is_none());
    }

    #[test]
    fn windows_processcontainer_config_serializes_mxc_wire_shape() {
        let spec = process_execution_spec(
            BackendCapabilityMapId::MxcWindowsProcessContainer,
            NetworkMode::Allow,
        )
        .unwrap();
        let config =
            build_mxc_process_config("agent --version", &spec, process_options("axis-windows"))
                .unwrap();
        let json = serde_json::to_value(&config).unwrap();

        assert_eq!(json["containment"], "processcontainer");
        assert_eq!(json["platform"], "windows");
        assert_eq!(json["network"]["defaultPolicy"], "allow");
        assert_eq!(json["processContainer"]["leastPrivilege"], false);
        assert!(json["processContainer"].get("capabilities").is_none());
        assert_eq!(json["fallback"]["allowDaclMutation"], false);
        assert!(json.get("experimental").is_none());
    }

    #[test]
    fn macos_seatbelt_config_serializes_experimental_mxc_wire_shape() {
        let spec =
            process_execution_spec(BackendCapabilityMapId::MxcMacosSeatbelt, NetworkMode::Block)
                .unwrap();
        let config =
            build_mxc_process_config("agent --version", &spec, process_options("axis-seatbelt"))
                .unwrap();
        let json = serde_json::to_value(&config).unwrap();

        assert_eq!(json["containment"], "seatbelt");
        assert_eq!(json["platform"], "macos");
        assert_eq!(json["network"]["defaultPolicy"], "block");
        assert!(json.get("processContainer").is_none());
        assert_eq!(json["experimental"]["seatbelt"]["guiAccess"], false);
        assert_eq!(json["experimental"]["seatbelt"]["launchMethod"], "exec");
        assert_eq!(json["experimental"]["seatbelt"]["nestedPty"], false);
        assert_eq!(json["experimental"]["seatbelt"]["keychainAccess"], false);
        assert!(
            json["experimental"]["seatbelt"]
                .get("extraMachLookups")
                .is_none()
        );
    }

    #[test]
    fn native_process_backends_are_rejected_before_mxc_config() {
        let spec =
            process_execution_spec(BackendCapabilityMapId::AxisNativeLinux, NetworkMode::Allow)
                .unwrap();

        let err =
            build_mxc_process_config("agent --version", &spec, MxcProcessConfigOptions::default())
                .unwrap_err();

        assert_eq!(
            err,
            MxcConfigError::NativeProcessBackendUnsupported {
                backend: "axis-native-linux".into()
            }
        );
    }

    #[test]
    fn process_strict_proxy_requires_axis_owned_network_layer_before_mxc_config() {
        let spec = process_execution_spec(
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            NetworkMode::Proxy,
        )
        .unwrap();

        let err = build_mxc_process_config("agent --version", &spec, process_options("axis-bwrap"))
            .unwrap_err();
        assert_eq!(err, MxcConfigError::StrictProxyRequiresAxisLayer);

        let config = build_mxc_process_config(
            "agent --version",
            &spec,
            MxcProcessConfigOptions {
                container_id: Some("axis-bwrap".into()),
                strict_proxy_enforced_by_axis: true,
            },
        )
        .unwrap();
        assert_eq!(
            config.network.default_policy,
            MxcNetworkDefaultPolicy::Allow
        );
    }

    #[test]
    fn process_endpoint_policies_are_rejected_outside_strict_proxy_mode() {
        let mut policy = process_policy(NetworkMode::Allow);
        policy.network.policies.push(endpoint_policy_with_binary());
        let spec = build_process_backend_execution_spec(
            &policy,
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            process_launch(),
            &present_runtime_for_backend(BackendCapabilityMapId::MxcLinuxBubblewrap),
            &PlannerOptions::new(),
        )
        .unwrap();

        let err = build_mxc_process_config("agent --version", &spec, process_options("axis-bwrap"))
            .unwrap_err();

        assert_eq!(err, MxcConfigError::EndpointPolicyRequiresStrictProxy);
    }

    #[test]
    fn process_inputs_are_validated_before_mxc_process_config() {
        let mut spec = process_execution_spec(
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            NetworkMode::Allow,
        )
        .unwrap();

        assert_eq!(
            build_mxc_process_config(" ", &spec, process_options("axis-bwrap")).unwrap_err(),
            MxcConfigError::EmptyCommandLine
        );

        spec.environment.insert(" ".into(), "bad".into());
        assert_eq!(
            build_mxc_process_config("agent --version", &spec, process_options("axis-bwrap"))
                .unwrap_err(),
            MxcConfigError::InvalidEnvironmentEntry
        );
    }

    #[test]
    fn process_timeout_overflow_is_rejected_before_mxc_process_config() {
        let mut spec = process_execution_spec(
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            NetworkMode::Allow,
        )
        .unwrap();
        spec.timeout_ms = Some(u64::from(u32::MAX) + 1);

        let err = build_mxc_process_config("agent --version", &spec, process_options("axis-bwrap"))
            .unwrap_err();

        assert_eq!(
            err,
            MxcConfigError::ProcessTimeoutOverflow {
                timeout_ms: u64::from(u32::MAX) + 1
            }
        );
    }

    #[test]
    fn strict_proxy_requires_axis_owned_network_layer_before_mxc_config() {
        let spec = lxc_execution_spec(NetworkMode::Proxy).unwrap();

        let err = build_mxc_container_config(process(), &spec, options("axis-lxc")).unwrap_err();
        assert_eq!(err, MxcConfigError::StrictProxyRequiresAxisLayer);

        let config = build_mxc_container_config(
            process(),
            &spec,
            MxcContainerConfigOptions {
                container_id: Some("axis-lxc".into()),
                strict_proxy_enforced_by_axis: true,
            },
        )
        .unwrap();
        assert_eq!(
            config.network.default_policy,
            MxcNetworkDefaultPolicy::Allow
        );
    }

    #[test]
    fn endpoint_policies_are_rejected_outside_strict_proxy_mode() {
        let mut policy = policy(NetworkMode::Allow);
        policy.network.policies.push(endpoint_policy_with_binary());
        let spec = build_container_backend_execution_spec(
            &policy,
            BackendCapabilityMapId::MxcLinuxLxc,
            lxc_launch(),
            &present_runtime_for_backend(BackendCapabilityMapId::MxcLinuxLxc),
            &PlannerOptions::new(),
        )
        .unwrap();

        let err = build_mxc_container_config(process(), &spec, options("axis-lxc")).unwrap_err();

        assert_eq!(err, MxcConfigError::EndpointPolicyRequiresStrictProxy);
    }

    #[test]
    fn bind_mount_aliases_are_rejected_before_mxc_config() {
        let mut spec = lxc_execution_spec(NetworkMode::Allow).unwrap();
        spec.bind_mounts[0].container_path = "/container-workspace".into();

        let err = build_mxc_container_config(process(), &spec, options("axis-lxc")).unwrap_err();

        assert_eq!(
            err,
            MxcConfigError::BindMountAliasUnsupported {
                host_path: "/workspace".into(),
                container_path: "/container-workspace".into()
            }
        );
    }

    #[test]
    fn wslc_bind_mounts_are_rejected_before_mxc_config() {
        let mut launch = wslc_launch_without_bind_mounts();
        launch.bind_mounts.push(ContainerBindMount {
            host_path: "C:\\workspace".into(),
            container_path: "C:\\workspace".into(),
            access: ContainerMountAccess::ReadWrite,
        });
        let spec = build_container_backend_execution_spec(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcWindowsWslc,
            launch,
            &present_runtime_for_backend(BackendCapabilityMapId::MxcWindowsWslc),
            &PlannerOptions::new(),
        )
        .unwrap();

        let err = build_mxc_container_config(process(), &spec, options("axis-wslc")).unwrap_err();

        assert_eq!(err, MxcConfigError::WslcBindMountsUnsupported);
    }

    #[test]
    fn bind_mounts_must_be_granted_by_axis_filesystem_policy() {
        let mut spec = lxc_execution_spec(NetworkMode::Allow).unwrap();
        spec.filesystem.read_write.clear();

        let err = build_mxc_container_config(process(), &spec, options("axis-lxc")).unwrap_err();

        assert_eq!(
            err,
            MxcConfigError::BindMountNotGranted {
                host_path: "/workspace".into()
            }
        );
    }

    #[test]
    fn wslc_resource_limits_are_not_emitted_as_exact_axis_limits() {
        let mut policy = policy(NetworkMode::Allow);
        policy.process.max_memory_mb = 1024;
        let spec = build_container_backend_execution_spec(
            &policy,
            BackendCapabilityMapId::MxcWindowsWslc,
            wslc_launch_without_bind_mounts(),
            &present_runtime_for_backend(BackendCapabilityMapId::MxcWindowsWslc),
            &PlannerOptions::new()
                .accept_weaker_surface(crate::capability::PolicySurface::Resources)
                .accept_weaker_surface(crate::capability::PolicySurface::Cleanup),
        )
        .unwrap();

        let err = build_mxc_container_config(process(), &spec, options("axis-wslc")).unwrap_err();

        assert_eq!(err, MxcConfigError::WslcResourceLimitsUnsupported);
    }

    #[test]
    fn process_inputs_are_validated_before_mxc_config() {
        let spec = lxc_execution_spec(NetworkMode::Allow).unwrap();
        let mut process_config = process();
        process_config.command_line = " ".into();
        assert_eq!(
            build_mxc_container_config(process_config, &spec, options("axis-lxc")).unwrap_err(),
            MxcConfigError::EmptyCommandLine
        );

        let mut process_config = process();
        process_config.env.push("BAD_ENV".into());
        assert_eq!(
            build_mxc_container_config(process_config, &spec, options("axis-lxc")).unwrap_err(),
            MxcConfigError::InvalidEnvironmentEntry
        );
    }

    fn lxc_execution_spec(
        mode: NetworkMode,
    ) -> Result<ContainerBackendExecutionSpec, ContainerBackendSpecError> {
        let proxy_mode = matches!(mode, NetworkMode::Proxy);
        let mut policy = policy(mode);
        if proxy_mode {
            policy.network.policies.push(endpoint_policy_with_binary());
        }
        build_container_backend_execution_spec(
            &policy,
            BackendCapabilityMapId::MxcLinuxLxc,
            lxc_launch(),
            &present_runtime_for_backend(BackendCapabilityMapId::MxcLinuxLxc),
            &PlannerOptions::new(),
        )
    }

    fn process() -> MxcProcessConfig {
        MxcProcessConfig {
            command_line: "echo container".into(),
            cwd: Some("/workspace".into()),
            env: vec!["PATH=/usr/bin".into()],
            timeout: Some(5000),
        }
    }

    fn options(container_id: &str) -> MxcContainerConfigOptions {
        MxcContainerConfigOptions {
            container_id: Some(container_id.into()),
            strict_proxy_enforced_by_axis: false,
        }
    }

    fn process_options(container_id: &str) -> MxcProcessConfigOptions {
        MxcProcessConfigOptions {
            container_id: Some(container_id.into()),
            strict_proxy_enforced_by_axis: false,
        }
    }

    fn present_runtime_for_backend(id: BackendCapabilityMapId) -> RuntimeProbeSnapshot {
        backend_capability_map(id).host_dependencies.iter().fold(
            RuntimeProbeSnapshot::new(),
            |runtime, dependency| {
                runtime.with_dependency(&dependency.name, DependencyState::Present)
            },
        )
    }

    fn lxc_launch() -> ContainerLaunchOptions {
        ContainerLaunchOptions {
            rootfs: ContainerRootfsSource::LxcDistributionRelease {
                distribution: "alpine".into(),
                release: "3.23".into(),
            },
            storage_path: None,
            working_dir: Some("/workspace".into()),
            bind_mounts: vec![ContainerBindMount {
                host_path: "/workspace".into(),
                container_path: "/workspace".into(),
                access: ContainerMountAccess::ReadWrite,
            }],
            destroy_on_exit: true,
        }
    }

    fn process_execution_spec(
        id: BackendCapabilityMapId,
        mode: NetworkMode,
    ) -> Result<ProcessBackendExecutionSpec, ProcessBackendSpecError> {
        build_process_backend_execution_spec(
            &process_policy(mode),
            id,
            process_launch(),
            &present_runtime_for_backend(id),
            &PlannerOptions::new(),
        )
    }

    fn process_launch() -> ProcessLaunchOptions {
        ProcessLaunchOptions {
            command: "agent".into(),
            args: vec!["--version".into()],
            working_dir: Some("/workspace".into()),
            environment: BTreeMap::from([("AXIS_TEST".into(), "1".into())]),
            capture_output: true,
            timeout_sec: Some(3),
        }
    }

    fn process_policy(mode: NetworkMode) -> Policy {
        Policy {
            version: 1,
            name: "mxc-process-config-test".into(),
            filesystem: FilesystemPolicy {
                read_only: vec!["/usr".into()],
                read_write: vec!["/workspace".into()],
                deny: vec!["/home/user/.ssh".into()],
                compatibility: Default::default(),
            },
            process: ProcessPolicy {
                max_processes: 0,
                max_memory_mb: 0,
                cpu_rate_percent: 0,
                ..Default::default()
            },
            network: NetworkPolicy {
                mode,
                policies: Vec::new(),
            },
            inference: InferencePolicy::default(),
            gpu: GpuPolicy::default(),
            ssh: SshPolicy::default(),
            amd: None,
        }
    }

    fn wslc_launch_without_bind_mounts() -> ContainerLaunchOptions {
        ContainerLaunchOptions {
            rootfs: ContainerRootfsSource::WslImage {
                image: "alpine:latest".into(),
            },
            storage_path: Some("C:\\axis\\wslc".into()),
            working_dir: Some("/workspace".into()),
            bind_mounts: Vec::new(),
            destroy_on_exit: true,
        }
    }

    fn policy(mode: NetworkMode) -> Policy {
        Policy {
            version: 1,
            name: "mxc-container-config-test".into(),
            filesystem: FilesystemPolicy {
                read_only: Vec::new(),
                read_write: vec!["/workspace".into()],
                deny: Vec::new(),
                compatibility: Default::default(),
            },
            process: ProcessPolicy {
                max_processes: 0,
                max_memory_mb: 0,
                cpu_rate_percent: 0,
                ..Default::default()
            },
            network: NetworkPolicy {
                mode,
                policies: Vec::new(),
            },
            inference: InferencePolicy::default(),
            gpu: GpuPolicy::default(),
            ssh: SshPolicy::default(),
            amd: None,
        }
    }

    fn endpoint_policy_with_binary() -> EndpointPolicy {
        EndpointPolicy {
            name: "github".into(),
            endpoints: vec![Endpoint {
                host: "api.github.com".into(),
                port: 443,
                access: Access::ReadOnly,
                protocol: Some("https".into()),
                rules: Vec::new(),
            }],
            binaries: vec![BinaryMatch {
                path: "/usr/bin/git".into(),
            }],
        }
    }
}
