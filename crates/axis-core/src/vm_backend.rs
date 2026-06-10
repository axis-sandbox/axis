// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! VM-style backend planning.
//!
//! VM backends have launch inputs that are outside the AXIS policy contract:
//! image or snapshot source, guest command channel, copy semantics, and VM
//! lifecycle. This module keeps those inputs planner-visible so platform
//! adapters can reject unsuitable VM launches before generating MXC config.

use crate::capability::{
    BackendPlatform, BackendPolicyPlan, BackendStability, CapabilityRequirement, CapabilitySupport,
    PlannerOptions, PolicySurface, RuntimeProbeSnapshot, plan_backend_policy,
    plan_backend_requirements,
};
use crate::capability_map::{
    BackendCapabilityMapId, backend_capability_map, backend_capability_maps_for_platform,
};
use crate::policy::{NetworkMode, Policy};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmBackendConfigFormat {
    MxcLinuxMicrovmJson,
    MxcLinuxHyperlightJson,
    MxcWindowsSandboxJson,
    MxcWindowsIsolationSessionJson,
    MxcWindowsMicrovmJson,
    MxcWindowsHyperlightJson,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct VmBackendDescriptor {
    pub id: BackendCapabilityMapId,
    pub platform: BackendPlatform,
    pub config_format: VmBackendConfigFormat,
    pub suitability: VmBackendSuitability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct VmBackendSuitability {
    pub full_agent_sessions: bool,
    pub tool_snippets: bool,
    pub python_only_workloads: bool,
    pub high_risk_tasks: bool,
    pub not_suitable: bool,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmImageSource {
    MicrovmImage {
        image_path: String,
        #[serde(default)]
        image_home: Option<String>,
    },
    HyperlightSnapshot {
        snapshot_path: String,
    },
    WindowsSandboxConfig {
        config_path: String,
    },
    RuntimeDefault,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmCopyPath {
    pub host_path: String,
    pub guest_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmLaunchOptions {
    pub image: VmImageSource,
    #[serde(default)]
    pub architecture: Option<String>,
    #[serde(default)]
    pub guest_agent: Option<String>,
    #[serde(default)]
    pub guest_working_dir: Option<String>,
    #[serde(default)]
    pub copy_in: Vec<VmCopyPath>,
    #[serde(default)]
    pub copy_out: Vec<VmCopyPath>,
    #[serde(default)]
    pub required_features: Vec<String>,
    #[serde(default = "default_destroy_on_exit")]
    pub destroy_on_exit: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VmBackendSpecError {
    #[error("{0:?} is not a VM-style backend")]
    NotVmBackend(BackendCapabilityMapId),

    #[error("VM backend rejected launch before config generation: {0}")]
    RejectedBeforeConfig(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmBackendNetworkMode {
    Allow,
    Block,
    StrictProxy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VmBackendExecutionSpec {
    pub backend: String,
    pub platform: BackendPlatform,
    pub config_format: VmBackendConfigFormat,
    pub image: VmImageSource,
    #[serde(default)]
    pub architecture: Option<String>,
    #[serde(default)]
    pub guest_agent: Option<String>,
    #[serde(default)]
    pub guest_working_dir: Option<String>,
    #[serde(default)]
    pub copy_in: Vec<VmCopyPath>,
    #[serde(default)]
    pub copy_out: Vec<VmCopyPath>,
    #[serde(default)]
    pub required_features: Vec<String>,
    pub destroy_on_exit: bool,
    pub network_mode: VmBackendNetworkMode,
    pub suitability: VmBackendSuitability,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmBackendPlan {
    pub descriptor: VmBackendDescriptor,
    pub policy_plan: BackendPolicyPlan,
    pub launch_plan: BackendPolicyPlan,
}

impl VmBackendPlan {
    pub fn spawn_allowed(&self) -> bool {
        self.policy_plan.spawn_allowed() && self.launch_plan.spawn_allowed()
    }

    pub fn pre_spawn_error(&self) -> Option<String> {
        match (
            self.policy_plan.pre_spawn_error(),
            self.launch_plan.pre_spawn_error(),
        ) {
            (None, None) => None,
            (Some(policy), None) => Some(policy),
            (None, Some(launch)) => Some(launch),
            (Some(policy), Some(launch)) => Some(format!("{policy}; {launch}")),
        }
    }
}

pub const VM_BACKEND_DESCRIPTORS: &[VmBackendDescriptor] = &[
    VmBackendDescriptor {
        id: BackendCapabilityMapId::MxcLinuxMicrovm,
        platform: BackendPlatform::Linux,
        config_format: VmBackendConfigFormat::MxcLinuxMicrovmJson,
        suitability: VmBackendSuitability {
            full_agent_sessions: false,
            tool_snippets: true,
            python_only_workloads: false,
            high_risk_tasks: true,
            not_suitable: false,
            reason: "experimental microVM path; shell, copy, and strict proxy semantics are not proven for full agent sessions",
        },
    },
    VmBackendDescriptor {
        id: BackendCapabilityMapId::MxcLinuxHyperlight,
        platform: BackendPlatform::Linux,
        config_format: VmBackendConfigFormat::MxcLinuxHyperlightJson,
        suitability: VmBackendSuitability {
            full_agent_sessions: false,
            tool_snippets: true,
            python_only_workloads: false,
            high_risk_tasks: true,
            not_suitable: false,
            reason: "experimental Hyperlight path; snapshot and guest command semantics are not proven for full agent sessions",
        },
    },
    VmBackendDescriptor {
        id: BackendCapabilityMapId::MxcWindowsSandbox,
        platform: BackendPlatform::Windows,
        config_format: VmBackendConfigFormat::MxcWindowsSandboxJson,
        suitability: VmBackendSuitability {
            full_agent_sessions: false,
            tool_snippets: true,
            python_only_workloads: false,
            high_risk_tasks: true,
            not_suitable: false,
            reason: "Windows Sandbox is VM-style isolation, but AXIS guest agent, copy, and cleanup semantics are not proven for full agent sessions",
        },
    },
    VmBackendDescriptor {
        id: BackendCapabilityMapId::MxcWindowsIsolationSession,
        platform: BackendPlatform::Windows,
        config_format: VmBackendConfigFormat::MxcWindowsIsolationSessionJson,
        suitability: VmBackendSuitability {
            full_agent_sessions: false,
            tool_snippets: true,
            python_only_workloads: false,
            high_risk_tasks: true,
            not_suitable: false,
            reason: "Isolation Session is preview VM-style isolation; full agent session semantics are not proven",
        },
    },
    VmBackendDescriptor {
        id: BackendCapabilityMapId::MxcWindowsMicrovm,
        platform: BackendPlatform::Windows,
        config_format: VmBackendConfigFormat::MxcWindowsMicrovmJson,
        suitability: VmBackendSuitability {
            full_agent_sessions: false,
            tool_snippets: true,
            python_only_workloads: false,
            high_risk_tasks: true,
            not_suitable: false,
            reason: "experimental Windows microVM path; runtime artifacts and guest command semantics are not proven for full agent sessions",
        },
    },
    VmBackendDescriptor {
        id: BackendCapabilityMapId::MxcWindowsHyperlight,
        platform: BackendPlatform::Windows,
        config_format: VmBackendConfigFormat::MxcWindowsHyperlightJson,
        suitability: VmBackendSuitability {
            full_agent_sessions: false,
            tool_snippets: true,
            python_only_workloads: false,
            high_risk_tasks: true,
            not_suitable: false,
            reason: "experimental Windows Hyperlight path; snapshot and guest command semantics are not proven for full agent sessions",
        },
    },
];

pub fn vm_backend_descriptors() -> &'static [VmBackendDescriptor] {
    VM_BACKEND_DESCRIPTORS
}

pub fn vm_backend_descriptor(id: BackendCapabilityMapId) -> Option<&'static VmBackendDescriptor> {
    VM_BACKEND_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.id == id)
}

pub fn vm_backend_descriptors_for_platform(
    platform: BackendPlatform,
) -> Vec<&'static VmBackendDescriptor> {
    VM_BACKEND_DESCRIPTORS
        .iter()
        .filter(|descriptor| descriptor.platform == platform)
        .collect()
}

pub fn vm_backend_maps_for_platform(
    platform: BackendPlatform,
) -> Vec<crate::capability::BackendCapabilities> {
    backend_capability_maps_for_platform(platform)
        .into_iter()
        .filter(|backend| {
            VM_BACKEND_DESCRIPTORS
                .iter()
                .any(|descriptor| descriptor.id.as_str() == backend.name)
        })
        .collect()
}

pub fn plan_vm_backend_policy(
    policy: &Policy,
    id: BackendCapabilityMapId,
    launch: &VmLaunchOptions,
    runtime: &RuntimeProbeSnapshot,
    options: &PlannerOptions,
) -> Option<VmBackendPlan> {
    let descriptor = *vm_backend_descriptor(id)?;
    let backend = backend_capability_map(id);
    let policy_plan = plan_backend_policy(policy, &backend, runtime, options);
    let launch_plan = plan_vm_launch_options(
        &backend.name,
        backend.stability,
        descriptor,
        launch,
        runtime,
        options,
    );

    Some(VmBackendPlan {
        descriptor,
        policy_plan,
        launch_plan,
    })
}

pub fn build_vm_backend_execution_spec(
    policy: &Policy,
    id: BackendCapabilityMapId,
    launch: VmLaunchOptions,
    runtime: &RuntimeProbeSnapshot,
    options: &PlannerOptions,
) -> Result<VmBackendExecutionSpec, VmBackendSpecError> {
    let plan = plan_vm_backend_policy(policy, id, &launch, runtime, options)
        .ok_or(VmBackendSpecError::NotVmBackend(id))?;
    if !plan.spawn_allowed() {
        return Err(VmBackendSpecError::RejectedBeforeConfig(
            plan.pre_spawn_error()
                .unwrap_or_else(|| "unknown VM backend planning failure".into()),
        ));
    }

    Ok(VmBackendExecutionSpec {
        backend: plan.descriptor.id.as_str().into(),
        platform: plan.descriptor.platform,
        config_format: plan.descriptor.config_format,
        image: launch.image,
        architecture: launch.architecture,
        guest_agent: launch.guest_agent,
        guest_working_dir: launch.guest_working_dir,
        copy_in: launch.copy_in,
        copy_out: launch.copy_out,
        required_features: launch.required_features,
        destroy_on_exit: launch.destroy_on_exit,
        network_mode: vm_network_mode(policy),
        suitability: plan.descriptor.suitability,
    })
}

fn vm_network_mode(policy: &Policy) -> VmBackendNetworkMode {
    match policy.network.mode {
        NetworkMode::Allow => VmBackendNetworkMode::Allow,
        NetworkMode::Block => VmBackendNetworkMode::Block,
        NetworkMode::Proxy => VmBackendNetworkMode::StrictProxy,
    }
}

fn plan_vm_launch_options(
    backend_name: &str,
    stability: BackendStability,
    descriptor: VmBackendDescriptor,
    launch: &VmLaunchOptions,
    runtime: &RuntimeProbeSnapshot,
    options: &PlannerOptions,
) -> BackendPolicyPlan {
    let requirements = vm_launch_requirements(descriptor, launch);
    plan_backend_requirements(
        backend_name,
        descriptor.platform,
        stability,
        requirements,
        runtime,
        options,
    )
}

fn vm_launch_requirements(
    descriptor: VmBackendDescriptor,
    launch: &VmLaunchOptions,
) -> Vec<CapabilityRequirement> {
    let mut requirements = Vec::new();
    let runtime = runtime_support_for_vm(descriptor);

    push_requirement(&mut requirements, "vm.runtime", runtime.clone());
    push_requirement(
        &mut requirements,
        "vm.image",
        image_support_for_vm(descriptor, &launch.image, &runtime),
    );

    if let Some(architecture) = &launch.architecture {
        if architecture.trim().is_empty() {
            push_requirement(
                &mut requirements,
                "vm.architecture",
                CapabilitySupport::unsupported("VM architecture must not be empty"),
            );
        } else {
            push_requirement(
                &mut requirements,
                "vm.architecture",
                CapabilitySupport::AxisOwned,
            );
        }
    }

    match &launch.guest_agent {
        Some(agent) if !agent.trim().is_empty() => {
            push_requirement(&mut requirements, "vm.guest_agent", runtime.clone());
        }
        Some(_) => {
            push_requirement(
                &mut requirements,
                "vm.guest_agent",
                CapabilitySupport::unsupported("VM guest agent must not be empty"),
            );
        }
        None => {
            push_requirement(
                &mut requirements,
                "vm.guest_agent",
                CapabilitySupport::unsupported(
                    "VM launch requires a guest agent or equivalent command channel mapped by AXIS",
                ),
            );
        }
    }

    if launch.guest_working_dir.is_some() {
        push_requirement(
            &mut requirements,
            "vm.working_dir",
            CapabilitySupport::unsupported(
                "VM guest working directory mapping is not proven by AXIS",
            ),
        );
    }

    if launch
        .copy_in
        .iter()
        .chain(launch.copy_out.iter())
        .any(|copy| copy.host_path.trim().is_empty() || copy.guest_path.trim().is_empty())
    {
        push_requirement(
            &mut requirements,
            "vm.copy",
            CapabilitySupport::unsupported("VM copy paths require host and guest paths"),
        );
    } else if !launch.copy_in.is_empty() || !launch.copy_out.is_empty() {
        push_requirement(
            &mut requirements,
            "vm.copy",
            CapabilitySupport::unsupported("VM copy-in/out is not mapped by AXIS"),
        );
    }

    if launch
        .required_features
        .iter()
        .any(|feature| feature.trim().is_empty())
    {
        push_requirement(
            &mut requirements,
            "vm.features",
            CapabilitySupport::unsupported("VM feature flags must not be empty"),
        );
    } else if !launch.required_features.is_empty() {
        push_requirement(
            &mut requirements,
            "vm.features",
            CapabilitySupport::unsupported("VM backend feature flags are not mapped by AXIS"),
        );
    }

    if launch.destroy_on_exit {
        push_requirement(
            &mut requirements,
            "vm.destroy_on_exit",
            CapabilitySupport::AxisOwned,
        );
    } else {
        push_requirement(
            &mut requirements,
            "vm.destroy_on_exit",
            CapabilitySupport::unsupported(
                "persistent VM state is not mapped to AXIS lifecycle cleanup",
            ),
        );
    }

    requirements
}

fn image_support_for_vm(
    descriptor: VmBackendDescriptor,
    image: &VmImageSource,
    runtime: &CapabilitySupport,
) -> CapabilitySupport {
    match (descriptor.id, image) {
        (
            BackendCapabilityMapId::MxcLinuxMicrovm | BackendCapabilityMapId::MxcWindowsMicrovm,
            VmImageSource::MicrovmImage {
                image_path,
                image_home,
            },
        ) if !image_path.trim().is_empty()
            && image_home
                .as_deref()
                .is_none_or(|home| !home.trim().is_empty()) =>
        {
            runtime.clone()
        }
        (
            BackendCapabilityMapId::MxcLinuxHyperlight
            | BackendCapabilityMapId::MxcWindowsHyperlight,
            VmImageSource::HyperlightSnapshot { snapshot_path },
        ) if !snapshot_path.trim().is_empty() => runtime.clone(),
        (
            BackendCapabilityMapId::MxcWindowsSandbox,
            VmImageSource::WindowsSandboxConfig { config_path },
        ) if !config_path.trim().is_empty() => runtime.clone(),
        (BackendCapabilityMapId::MxcWindowsIsolationSession, VmImageSource::RuntimeDefault) => {
            runtime.clone()
        }
        (
            BackendCapabilityMapId::MxcLinuxMicrovm | BackendCapabilityMapId::MxcWindowsMicrovm,
            VmImageSource::MicrovmImage { .. },
        ) => CapabilitySupport::unsupported(
            "microVM image selection requires a non-empty image path and optional non-empty image home",
        ),
        (
            BackendCapabilityMapId::MxcLinuxHyperlight
            | BackendCapabilityMapId::MxcWindowsHyperlight,
            VmImageSource::HyperlightSnapshot { .. },
        ) => CapabilitySupport::unsupported(
            "Hyperlight snapshot selection requires a non-empty snapshot path",
        ),
        (BackendCapabilityMapId::MxcWindowsSandbox, VmImageSource::WindowsSandboxConfig { .. }) => {
            CapabilitySupport::unsupported(
                "Windows Sandbox selection requires a non-empty config path",
            )
        }
        (BackendCapabilityMapId::MxcWindowsIsolationSession, _) => CapabilitySupport::unsupported(
            "Isolation Session currently uses runtime-default VM provisioning",
        ),
        (
            BackendCapabilityMapId::MxcLinuxMicrovm | BackendCapabilityMapId::MxcWindowsMicrovm,
            _,
        ) => CapabilitySupport::unsupported("microVM backends require a microVM image source"),
        (
            BackendCapabilityMapId::MxcLinuxHyperlight
            | BackendCapabilityMapId::MxcWindowsHyperlight,
            _,
        ) => CapabilitySupport::unsupported("Hyperlight backends require a snapshot source"),
        (BackendCapabilityMapId::MxcWindowsSandbox, _) => {
            CapabilitySupport::unsupported("Windows Sandbox requires a sandbox config source")
        }
        _ => CapabilitySupport::unsupported("backend is not a VM-style backend"),
    }
}

fn runtime_support_for_vm(descriptor: VmBackendDescriptor) -> CapabilitySupport {
    let backend = backend_capability_map(descriptor.id);
    CapabilitySupport::with_dependencies(
        backend
            .host_dependencies
            .into_iter()
            .map(|dependency| dependency.name),
    )
}

fn push_requirement(
    requirements: &mut Vec<CapabilityRequirement>,
    name: &'static str,
    support: CapabilitySupport,
) {
    requirements.push(CapabilityRequirement {
        surface: PolicySurface::Vm,
        name,
        support,
    });
}

fn default_destroy_on_exit() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{BackendPlanOutcome, DependencyState};
    use crate::capability_map::host_dependency;
    use crate::policy::{
        FilesystemPolicy, GpuPolicy, InferencePolicy, NetworkMode, NetworkPolicy, Policy,
        ProcessPolicy, SshPolicy,
    };
    use std::collections::BTreeSet;

    #[test]
    fn vm_backend_catalog_covers_vm_style_paths() {
        let ids = vm_backend_descriptors()
            .iter()
            .map(|descriptor| descriptor.id)
            .collect::<BTreeSet<_>>();

        for id in [
            BackendCapabilityMapId::MxcLinuxMicrovm,
            BackendCapabilityMapId::MxcLinuxHyperlight,
            BackendCapabilityMapId::MxcWindowsSandbox,
            BackendCapabilityMapId::MxcWindowsIsolationSession,
            BackendCapabilityMapId::MxcWindowsMicrovm,
            BackendCapabilityMapId::MxcWindowsHyperlight,
        ] {
            assert!(ids.contains(&id), "missing VM backend {id:?}");
        }
    }

    #[test]
    fn vm_backend_catalog_is_partitioned_by_platform() {
        assert_eq!(
            vm_backend_descriptors_for_platform(BackendPlatform::Linux).len(),
            2
        );
        assert_eq!(
            vm_backend_descriptors_for_platform(BackendPlatform::Windows).len(),
            4
        );
        assert!(vm_backend_descriptors_for_platform(BackendPlatform::Macos).is_empty());
    }

    #[test]
    fn vm_backend_maps_are_filterable_by_platform() {
        let linux_maps = vm_backend_maps_for_platform(BackendPlatform::Linux);
        let windows_maps = vm_backend_maps_for_platform(BackendPlatform::Windows);

        assert_eq!(linux_maps.len(), 2);
        assert_eq!(windows_maps.len(), 4);
        assert!(
            linux_maps
                .iter()
                .all(|backend| backend.platform == BackendPlatform::Linux)
        );
        assert!(
            windows_maps
                .iter()
                .any(|backend| backend.name == "mxc-windows-sandbox")
        );
    }

    #[test]
    fn vm_suitability_does_not_oversell_full_agent_sessions() {
        for descriptor in vm_backend_descriptors() {
            assert!(!descriptor.suitability.full_agent_sessions);
            assert!(descriptor.suitability.tool_snippets);
            assert!(descriptor.suitability.high_risk_tasks);
            assert!(!descriptor.suitability.not_suitable);
            assert!(descriptor.suitability.reason.contains("not proven"));
        }
    }

    #[test]
    fn vm_execution_spec_covers_all_vm_backend_formats() {
        for descriptor in vm_backend_descriptors() {
            let launch = launch_for_backend(descriptor.id);
            let runtime = present_runtime_for_backend(descriptor.id);
            let spec = build_vm_backend_execution_spec(
                &policy(NetworkMode::Allow),
                descriptor.id,
                launch,
                &runtime,
                &PlannerOptions::new(),
            )
            .unwrap_or_else(|err| {
                panic!("{} rejected unexpectedly: {err}", descriptor.id.as_str())
            });

            assert_eq!(spec.backend, descriptor.id.as_str());
            assert_eq!(spec.platform, descriptor.platform);
            assert_eq!(spec.config_format, descriptor.config_format);
            assert_eq!(spec.network_mode, VmBackendNetworkMode::Allow);
            assert_eq!(spec.suitability, descriptor.suitability);
            assert!(spec.destroy_on_exit);
        }
    }

    #[test]
    fn vm_execution_spec_rejects_non_vm_backend_before_config() {
        let err = build_vm_backend_execution_spec(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcLinuxLxc,
            microvm_launch(),
            &linux_microvm_runtime(),
            &PlannerOptions::new(),
        )
        .unwrap_err();

        assert_eq!(
            err,
            VmBackendSpecError::NotVmBackend(BackendCapabilityMapId::MxcLinuxLxc)
        );
    }

    #[test]
    fn vm_execution_spec_rejects_unmapped_proxy_before_config() {
        let err = build_vm_backend_execution_spec(
            &policy(NetworkMode::Proxy),
            BackendCapabilityMapId::MxcLinuxMicrovm,
            microvm_launch(),
            &linux_microvm_runtime(),
            &PlannerOptions::new(),
        )
        .unwrap_err();

        assert!(matches!(err, VmBackendSpecError::RejectedBeforeConfig(_)));
        assert!(err.to_string().contains("audit.bypass_evidence"));
    }

    #[test]
    fn vm_execution_spec_rejects_unmapped_copy_before_config() {
        let mut launch = microvm_launch();
        launch.copy_in = vec![VmCopyPath {
            host_path: "/tmp/in".into(),
            guest_path: "/workspace/in".into(),
        }];

        let err = build_vm_backend_execution_spec(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcLinuxMicrovm,
            launch,
            &linux_microvm_runtime(),
            &PlannerOptions::new(),
        )
        .unwrap_err();

        assert!(matches!(err, VmBackendSpecError::RejectedBeforeConfig(_)));
        assert!(err.to_string().contains("vm.copy"));
    }

    #[test]
    fn vm_execution_spec_serializes_fake_executor_boundary() {
        let launch = VmLaunchOptions {
            image: VmImageSource::WindowsSandboxConfig {
                config_path: "C:\\axis\\sandbox.wsb".into(),
            },
            guest_agent: Some("axis-guest-agent.exe".into()),
            ..minimal_vm_launch()
        };
        let runtime = present_runtime_for_backend(BackendCapabilityMapId::MxcWindowsSandbox);

        let spec = build_vm_backend_execution_spec(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcWindowsSandbox,
            launch,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();
        let json = serde_json::to_value(&spec).unwrap();

        assert_eq!(json["backend"], "mxc-windows-sandbox");
        assert_eq!(json["config_format"], "mxc_windows_sandbox_json");
        assert_eq!(json["network_mode"], "allow");
        assert_eq!(json["guest_agent"], "axis-guest-agent.exe");
        assert_eq!(json["suitability"]["full_agent_sessions"], false);
    }

    #[test]
    fn linux_microvm_with_present_dependencies_is_allowed_for_minimal_launch() {
        let plan = plan_vm_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcLinuxMicrovm,
            &microvm_launch(),
            &linux_microvm_runtime(),
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(plan.spawn_allowed(), "{:?}", plan.pre_spawn_error());
        for requirement in [
            "vm.runtime",
            "vm.image",
            "vm.guest_agent",
            "vm.destroy_on_exit",
        ] {
            assert!(
                plan.launch_plan
                    .decisions
                    .iter()
                    .any(|decision| decision.requirement == requirement),
                "missing VM launch decision {requirement}"
            );
        }
    }

    #[test]
    fn linux_microvm_missing_kvm_blocks_before_spawn() {
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(
                host_dependency::MXC_MICROVM_RUNTIME,
                DependencyState::Present,
            );

        let plan = plan_vm_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcLinuxMicrovm,
            &microvm_launch(),
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!plan.spawn_allowed());
        let error = plan.pre_spawn_error().unwrap();
        assert!(error.contains(host_dependency::LINUX_KVM));
        assert!(error.contains("missing host dependency"));
    }

    #[test]
    fn microvm_rejects_snapshot_source() {
        let mut launch = microvm_launch();
        launch.image = VmImageSource::HyperlightSnapshot {
            snapshot_path: "/var/lib/axis/snap".into(),
        };

        let plan = plan_vm_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcLinuxMicrovm,
            &launch,
            &linux_microvm_runtime(),
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(matches!(
            plan.launch_plan.outcome,
            BackendPlanOutcome::Unsupported { .. }
        ));
        assert!(plan.pre_spawn_error().unwrap().contains("vm.image"));
    }

    #[test]
    fn hyperlight_requires_non_empty_snapshot() {
        let launch = VmLaunchOptions {
            image: VmImageSource::HyperlightSnapshot {
                snapshot_path: String::new(),
            },
            guest_agent: Some("axis-guest-agent".into()),
            ..minimal_vm_launch()
        };

        let plan = plan_vm_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcLinuxHyperlight,
            &launch,
            &linux_hyperlight_runtime(),
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!plan.spawn_allowed());
        assert!(plan.pre_spawn_error().unwrap().contains("vm.image"));
    }

    #[test]
    fn hyperlight_snapshot_with_present_dependencies_is_allowed() {
        let launch = VmLaunchOptions {
            image: VmImageSource::HyperlightSnapshot {
                snapshot_path: "/var/lib/axis/hyperlight.snap".into(),
            },
            guest_agent: Some("axis-guest-agent".into()),
            ..minimal_vm_launch()
        };

        let plan = plan_vm_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcLinuxHyperlight,
            &launch,
            &linux_hyperlight_runtime(),
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(plan.spawn_allowed(), "{:?}", plan.pre_spawn_error());
    }

    #[test]
    fn windows_sandbox_config_with_present_dependencies_is_allowed() {
        let launch = VmLaunchOptions {
            image: VmImageSource::WindowsSandboxConfig {
                config_path: "C:\\axis\\sandbox.wsb".into(),
            },
            guest_agent: Some("axis-guest-agent.exe".into()),
            ..minimal_vm_launch()
        };
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::WINDOWS_SANDBOX, DependencyState::Present);

        let plan = plan_vm_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcWindowsSandbox,
            &launch,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(plan.spawn_allowed(), "{:?}", plan.pre_spawn_error());
    }

    #[test]
    fn isolation_session_runtime_default_with_present_dependencies_is_allowed() {
        let plan = plan_vm_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcWindowsIsolationSession,
            &minimal_vm_launch(),
            &windows_isolation_session_runtime(),
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(plan.spawn_allowed(), "{:?}", plan.pre_spawn_error());
    }

    #[test]
    fn isolation_session_requires_runtime_default_source() {
        let plan = plan_vm_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcWindowsIsolationSession,
            &microvm_launch(),
            &windows_isolation_session_runtime(),
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!plan.spawn_allowed());
        assert!(plan.pre_spawn_error().unwrap().contains("vm.image"));
    }

    #[test]
    fn windows_hyperlight_missing_runtime_dependency_blocks_before_spawn() {
        let launch = VmLaunchOptions {
            image: VmImageSource::HyperlightSnapshot {
                snapshot_path: "C:\\axis\\hyperlight.snap".into(),
            },
            guest_agent: Some("axis-guest-agent.exe".into()),
            ..minimal_vm_launch()
        };
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::WINDOWS_WHP, DependencyState::Present);

        let plan = plan_vm_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcWindowsHyperlight,
            &launch,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!plan.spawn_allowed());
        assert!(
            plan.pre_spawn_error()
                .unwrap()
                .contains(host_dependency::WINDOWS_HYPERLIGHT_RUNTIME)
        );
    }

    #[test]
    fn proxy_remains_rejected_when_vm_bypass_evidence_is_unmapped() {
        let plan = plan_vm_backend_policy(
            &policy(NetworkMode::Proxy),
            BackendCapabilityMapId::MxcLinuxMicrovm,
            &microvm_launch(),
            &linux_microvm_runtime(),
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(matches!(
            plan.policy_plan.outcome,
            BackendPlanOutcome::Unsupported { .. }
        ));
        assert!(!plan.spawn_allowed());
        assert!(
            plan.pre_spawn_error()
                .unwrap()
                .contains("audit.bypass_evidence")
        );
    }

    #[test]
    fn vm_copy_paths_are_rejected_until_mapped() {
        let mut launch = microvm_launch();
        launch.copy_in = vec![VmCopyPath {
            host_path: "/tmp/in".into(),
            guest_path: "/workspace/in".into(),
        }];

        let plan = plan_vm_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcLinuxMicrovm,
            &launch,
            &linux_microvm_runtime(),
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!plan.spawn_allowed());
        assert!(plan.pre_spawn_error().unwrap().contains("vm.copy"));
    }

    #[test]
    fn vm_guest_working_dir_is_rejected_until_mapped() {
        let mut launch = microvm_launch();
        launch.guest_working_dir = Some("/workspace".into());

        let plan = plan_vm_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcLinuxMicrovm,
            &launch,
            &linux_microvm_runtime(),
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!plan.spawn_allowed());
        assert!(plan.pre_spawn_error().unwrap().contains("vm.working_dir"));
    }

    #[test]
    fn persistent_vm_state_is_rejected_until_cleanup_is_mapped() {
        let mut launch = microvm_launch();
        launch.destroy_on_exit = false;

        let plan = plan_vm_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcLinuxMicrovm,
            &launch,
            &linux_microvm_runtime(),
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!plan.spawn_allowed());
        assert!(
            plan.pre_spawn_error()
                .unwrap()
                .contains("vm.destroy_on_exit")
        );
    }

    #[test]
    fn vm_launch_rejects_missing_guest_agent() {
        let mut launch = microvm_launch();
        launch.guest_agent = None;

        let plan = plan_vm_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcLinuxMicrovm,
            &launch,
            &linux_microvm_runtime(),
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!plan.spawn_allowed());
        assert!(plan.pre_spawn_error().unwrap().contains("vm.guest_agent"));
    }

    #[test]
    fn vm_launch_rejects_empty_guest_agent_and_architecture() {
        let mut launch = microvm_launch();
        launch.guest_agent = Some(" ".into());
        launch.architecture = Some(String::new());

        let plan = plan_vm_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcLinuxMicrovm,
            &launch,
            &linux_microvm_runtime(),
            &PlannerOptions::new(),
        )
        .unwrap();

        let error = plan.pre_spawn_error().unwrap();
        assert!(error.contains("vm.guest_agent"));
        assert!(error.contains("vm.architecture"));
    }

    #[test]
    fn microvm_rejects_empty_image_home() {
        let mut launch = microvm_launch();
        launch.image = VmImageSource::MicrovmImage {
            image_path: "/var/lib/axis/microvm.img".into(),
            image_home: Some(String::new()),
        };

        let plan = plan_vm_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcLinuxMicrovm,
            &launch,
            &linux_microvm_runtime(),
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!plan.spawn_allowed());
        assert!(plan.pre_spawn_error().unwrap().contains("vm.image"));
    }

    #[test]
    fn vm_launch_rejects_unmapped_feature_flags_and_empty_copy_paths() {
        let mut launch = microvm_launch();
        launch.required_features = vec!["snapshot_restore".into()];
        launch.copy_out = vec![VmCopyPath {
            host_path: String::new(),
            guest_path: "/workspace/out".into(),
        }];

        let plan = plan_vm_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcLinuxMicrovm,
            &launch,
            &linux_microvm_runtime(),
            &PlannerOptions::new(),
        )
        .unwrap();

        let error = plan.pre_spawn_error().unwrap();
        assert!(error.contains("vm.features"));
        assert!(error.contains("vm.copy"));
    }

    #[test]
    fn non_vm_backend_is_not_plannable_through_vm_facade() {
        assert!(
            plan_vm_backend_policy(
                &policy(NetworkMode::Allow),
                BackendCapabilityMapId::MxcLinuxLxc,
                &microvm_launch(),
                &linux_microvm_runtime(),
                &PlannerOptions::new(),
            )
            .is_none()
        );
    }

    fn launch_for_backend(id: BackendCapabilityMapId) -> VmLaunchOptions {
        match id {
            BackendCapabilityMapId::MxcLinuxMicrovm | BackendCapabilityMapId::MxcWindowsMicrovm => {
                microvm_launch()
            }
            BackendCapabilityMapId::MxcLinuxHyperlight
            | BackendCapabilityMapId::MxcWindowsHyperlight => VmLaunchOptions {
                image: VmImageSource::HyperlightSnapshot {
                    snapshot_path: "/var/lib/axis/hyperlight.snap".into(),
                },
                guest_agent: Some("axis-guest-agent".into()),
                ..minimal_vm_launch()
            },
            BackendCapabilityMapId::MxcWindowsSandbox => VmLaunchOptions {
                image: VmImageSource::WindowsSandboxConfig {
                    config_path: "C:\\axis\\sandbox.wsb".into(),
                },
                guest_agent: Some("axis-guest-agent.exe".into()),
                ..minimal_vm_launch()
            },
            BackendCapabilityMapId::MxcWindowsIsolationSession => minimal_vm_launch(),
            other => panic!("unexpected VM backend id {other:?}"),
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

    fn minimal_vm_launch() -> VmLaunchOptions {
        VmLaunchOptions {
            image: VmImageSource::RuntimeDefault,
            architecture: Some("x86_64".into()),
            guest_agent: Some("axis-guest-agent".into()),
            guest_working_dir: None,
            copy_in: Vec::new(),
            copy_out: Vec::new(),
            required_features: Vec::new(),
            destroy_on_exit: true,
        }
    }

    fn microvm_launch() -> VmLaunchOptions {
        VmLaunchOptions {
            image: VmImageSource::MicrovmImage {
                image_path: "/var/lib/axis/microvm.img".into(),
                image_home: Some("/var/lib/axis/images".into()),
            },
            ..minimal_vm_launch()
        }
    }

    fn linux_microvm_runtime() -> RuntimeProbeSnapshot {
        RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_KVM, DependencyState::Present)
            .with_dependency(
                host_dependency::MXC_MICROVM_RUNTIME,
                DependencyState::Present,
            )
    }

    fn linux_hyperlight_runtime() -> RuntimeProbeSnapshot {
        RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_KVM, DependencyState::Present)
            .with_dependency(
                host_dependency::MXC_HYPERLIGHT_RUNTIME,
                DependencyState::Present,
            )
    }

    fn windows_isolation_session_runtime() -> RuntimeProbeSnapshot {
        RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(
                host_dependency::WINDOWS_ISOLATION_SESSION,
                DependencyState::Present,
            )
    }

    fn policy(mode: NetworkMode) -> Policy {
        Policy {
            version: 1,
            name: "vm-backend-test".into(),
            filesystem: FilesystemPolicy {
                read_only: Vec::new(),
                read_write: vec!["{workspace}".into()],
                deny: Vec::new(),
                compatibility: Default::default(),
            },
            process: ProcessPolicy {
                max_processes: 0,
                max_memory_mb: 0,
                cpu_rate_percent: 0,
                run_as_user: None,
                blocked_syscalls: Vec::new(),
                timeout_sec: None,
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
}
