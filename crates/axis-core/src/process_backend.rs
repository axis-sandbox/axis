// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Process-style backend planning.
//!
//! This module keeps process backend selection platform-neutral. Platform
//! adapters consume these descriptors, then translate only planner-approved
//! launches into their local config formats.

use crate::capability::{
    BackendPlatform, BackendPolicyPlan, PlannerOptions, RuntimeProbeSnapshot, plan_backend_policy,
};
use crate::capability_map::{
    BackendCapabilityMapId, backend_capability_map, backend_capability_maps_for_platform,
};
use crate::policy::Policy;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessBackendConfigFormat {
    AxisNativeLinux,
    MxcLinuxJson,
    AxisNativeMacosSeatbeltProfile,
    MxcMacosSeatbeltProfile,
    AxisNativeWindowsProcess,
    MxcWindowsProcessContainer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessBackendDescriptor {
    pub id: BackendCapabilityMapId,
    pub platform: BackendPlatform,
    pub config_format: ProcessBackendConfigFormat,
    pub native_axis_backend: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessBackendPlan {
    pub descriptor: ProcessBackendDescriptor,
    pub policy_plan: BackendPolicyPlan,
}

impl ProcessBackendPlan {
    pub fn spawn_allowed(&self) -> bool {
        self.policy_plan.spawn_allowed()
    }

    pub fn pre_spawn_error(&self) -> Option<String> {
        self.policy_plan.pre_spawn_error()
    }
}

pub const PROCESS_BACKEND_DESCRIPTORS: &[ProcessBackendDescriptor] = &[
    ProcessBackendDescriptor {
        id: BackendCapabilityMapId::AxisNativeLinux,
        platform: BackendPlatform::Linux,
        config_format: ProcessBackendConfigFormat::AxisNativeLinux,
        native_axis_backend: true,
    },
    ProcessBackendDescriptor {
        id: BackendCapabilityMapId::MxcLinuxBubblewrap,
        platform: BackendPlatform::Linux,
        config_format: ProcessBackendConfigFormat::MxcLinuxJson,
        native_axis_backend: false,
    },
    ProcessBackendDescriptor {
        id: BackendCapabilityMapId::AxisNativeMacosSeatbelt,
        platform: BackendPlatform::Macos,
        config_format: ProcessBackendConfigFormat::AxisNativeMacosSeatbeltProfile,
        native_axis_backend: true,
    },
    ProcessBackendDescriptor {
        id: BackendCapabilityMapId::MxcMacosSeatbelt,
        platform: BackendPlatform::Macos,
        config_format: ProcessBackendConfigFormat::MxcMacosSeatbeltProfile,
        native_axis_backend: false,
    },
    ProcessBackendDescriptor {
        id: BackendCapabilityMapId::AxisNativeWindows,
        platform: BackendPlatform::Windows,
        config_format: ProcessBackendConfigFormat::AxisNativeWindowsProcess,
        native_axis_backend: true,
    },
    ProcessBackendDescriptor {
        id: BackendCapabilityMapId::MxcWindowsProcessContainer,
        platform: BackendPlatform::Windows,
        config_format: ProcessBackendConfigFormat::MxcWindowsProcessContainer,
        native_axis_backend: false,
    },
];

pub fn process_backend_descriptors() -> &'static [ProcessBackendDescriptor] {
    PROCESS_BACKEND_DESCRIPTORS
}

pub fn process_backend_descriptor(
    id: BackendCapabilityMapId,
) -> Option<&'static ProcessBackendDescriptor> {
    PROCESS_BACKEND_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.id == id)
}

pub fn process_backend_descriptors_for_platform(
    platform: BackendPlatform,
) -> Vec<&'static ProcessBackendDescriptor> {
    PROCESS_BACKEND_DESCRIPTORS
        .iter()
        .filter(|descriptor| descriptor.platform == platform)
        .collect()
}

pub fn plan_process_backend_policy(
    policy: &Policy,
    id: BackendCapabilityMapId,
    runtime: &RuntimeProbeSnapshot,
    options: &PlannerOptions,
) -> Option<ProcessBackendPlan> {
    let descriptor = *process_backend_descriptor(id)?;
    let backend = backend_capability_map(id);
    let policy_plan = plan_backend_policy(policy, &backend, runtime, options);

    Some(ProcessBackendPlan {
        descriptor,
        policy_plan,
    })
}

pub fn process_backend_maps_for_platform(
    platform: BackendPlatform,
) -> Vec<crate::capability::BackendCapabilities> {
    backend_capability_maps_for_platform(platform)
        .into_iter()
        .filter(|backend| {
            PROCESS_BACKEND_DESCRIPTORS
                .iter()
                .any(|descriptor| descriptor.id.as_str() == backend.name)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{BackendPlanOutcome, CapabilitySupport, DependencyState};
    use crate::capability_map::host_dependency;
    use crate::policy::{
        Access, BinaryMatch, Endpoint, EndpointPolicy, FilesystemPolicy, GpuPolicy,
        InferencePolicy, NetworkMode, NetworkPolicy, Policy, ProcessPolicy, SshPolicy,
    };
    use std::collections::BTreeSet;

    #[test]
    fn process_backend_catalog_covers_required_platform_paths() {
        let ids = process_backend_descriptors()
            .iter()
            .map(|descriptor| descriptor.id)
            .collect::<BTreeSet<_>>();

        for id in [
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            BackendCapabilityMapId::MxcWindowsProcessContainer,
            BackendCapabilityMapId::MxcMacosSeatbelt,
            BackendCapabilityMapId::AxisNativeLinux,
            BackendCapabilityMapId::AxisNativeMacosSeatbelt,
            BackendCapabilityMapId::AxisNativeWindows,
        ] {
            assert!(ids.contains(&id), "missing process backend {id:?}");
        }
    }

    #[test]
    fn process_backend_catalog_is_partitioned_by_platform() {
        assert_eq!(
            process_backend_descriptors_for_platform(BackendPlatform::Linux).len(),
            2
        );
        assert_eq!(
            process_backend_descriptors_for_platform(BackendPlatform::Macos).len(),
            2
        );
        assert_eq!(
            process_backend_descriptors_for_platform(BackendPlatform::Windows).len(),
            2
        );
        assert!(process_backend_descriptors_for_platform(BackendPlatform::Other).is_empty());
    }

    #[test]
    fn process_backend_maps_are_filterable_by_platform() {
        let linux_maps = process_backend_maps_for_platform(BackendPlatform::Linux);

        assert_eq!(linux_maps.len(), 2);
        assert!(
            linux_maps
                .iter()
                .any(|backend| backend.name == "mxc-linux-bubblewrap")
        );
        assert!(
            linux_maps
                .iter()
                .all(|backend| backend.platform == BackendPlatform::Linux)
        );
    }

    #[test]
    fn process_backend_config_formats_are_explicit() {
        for descriptor in process_backend_descriptors() {
            match descriptor.id {
                BackendCapabilityMapId::AxisNativeLinux => {
                    assert_eq!(
                        descriptor.config_format,
                        ProcessBackendConfigFormat::AxisNativeLinux
                    );
                    assert!(descriptor.native_axis_backend);
                }
                BackendCapabilityMapId::MxcLinuxBubblewrap => {
                    assert_eq!(
                        descriptor.config_format,
                        ProcessBackendConfigFormat::MxcLinuxJson
                    );
                    assert!(!descriptor.native_axis_backend);
                }
                BackendCapabilityMapId::AxisNativeMacosSeatbelt => {
                    assert_eq!(
                        descriptor.config_format,
                        ProcessBackendConfigFormat::AxisNativeMacosSeatbeltProfile
                    );
                    assert!(descriptor.native_axis_backend);
                }
                BackendCapabilityMapId::MxcMacosSeatbelt => {
                    assert_eq!(
                        descriptor.config_format,
                        ProcessBackendConfigFormat::MxcMacosSeatbeltProfile
                    );
                    assert!(!descriptor.native_axis_backend);
                }
                BackendCapabilityMapId::AxisNativeWindows => {
                    assert_eq!(
                        descriptor.config_format,
                        ProcessBackendConfigFormat::AxisNativeWindowsProcess
                    );
                    assert!(descriptor.native_axis_backend);
                }
                BackendCapabilityMapId::MxcWindowsProcessContainer => {
                    assert_eq!(
                        descriptor.config_format,
                        ProcessBackendConfigFormat::MxcWindowsProcessContainer
                    );
                    assert!(!descriptor.native_axis_backend);
                }
                other => panic!("unexpected process backend descriptor {other:?}"),
            }
        }
    }

    #[test]
    fn planner_records_process_surfaces_for_mxc_linux() {
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_BUBBLEWRAP, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_USERNS, DependencyState::Present)
            .with_dependency(
                host_dependency::AXIS_SECCOMP_LAUNCHER,
                DependencyState::Present,
            );
        let mut policy = process_policy(NetworkMode::Block);
        policy.process.timeout_sec = Some(5);

        let plan = plan_process_backend_policy(
            &policy,
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(plan.spawn_allowed(), "{:?}", plan.pre_spawn_error());
        for requirement in [
            "filesystem.read_only",
            "filesystem.read_write",
            "filesystem.deny",
            "filesystem.workspace",
            "process.command",
            "process.working_dir",
            "process.environment",
            "process.stdio",
            "process.timeout",
            "resources.timeout",
            "network.block",
        ] {
            assert!(
                plan.policy_plan
                    .decisions
                    .iter()
                    .any(|decision| decision.requirement == requirement),
                "missing planner decision {requirement}"
            );
        }
    }

    #[test]
    fn mxc_bubblewrap_cooperative_proxy_is_weaker_only() {
        let backend = backend_capability_map(BackendCapabilityMapId::MxcLinuxBubblewrap);

        let CapabilitySupport::WeakerOnly { reason } = backend.network.cooperative_proxy else {
            panic!("MXC bubblewrap cooperative proxy must not be treated as exact");
        };

        assert!(reason.contains("proxy environment"));
        assert!(reason.contains("direct sockets"));
    }

    #[test]
    fn strict_proxy_is_axis_owned_for_mxc_linux_process_backend() {
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_BUBBLEWRAP, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_USERNS, DependencyState::Present)
            .with_dependency(
                host_dependency::AXIS_SECCOMP_LAUNCHER,
                DependencyState::Present,
            );
        let policy = process_policy(NetworkMode::Proxy);

        let plan = plan_process_backend_policy(
            &policy,
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(plan.spawn_allowed(), "{:?}", plan.pre_spawn_error());
        let strict_proxy = plan
            .policy_plan
            .decisions
            .iter()
            .find(|decision| decision.requirement == "network.strict_proxy")
            .unwrap();
        assert_eq!(strict_proxy.support, CapabilitySupport::AxisOwned);
    }

    #[test]
    fn binary_restricted_proxy_requires_attribution_dependency() {
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_BUBBLEWRAP, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_USERNS, DependencyState::Present)
            .with_dependency(
                host_dependency::AXIS_SECCOMP_LAUNCHER,
                DependencyState::Present,
            );
        let mut policy = process_policy(NetworkMode::Proxy);
        policy.network.policies.push(endpoint_policy_with_binary());

        let plan = plan_process_backend_policy(
            &policy,
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!plan.spawn_allowed());
        let error = plan.pre_spawn_error().unwrap();
        assert!(error.contains("network.binary_attribution"));
        assert!(error.contains(host_dependency::LINUX_SECCOMP_NOTIFY));
    }

    #[test]
    fn macos_seatbelt_rejects_syscall_filtering_before_spawn() {
        let mut policy = process_policy(NetworkMode::Allow);
        policy.process.blocked_syscalls.push("ptrace".into());
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MACOS_SEATBELT, DependencyState::Present);

        let plan = plan_process_backend_policy(
            &policy,
            BackendCapabilityMapId::MxcMacosSeatbelt,
            &runtime,
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
                .contains("process.syscall_filtering")
        );
    }

    #[test]
    fn windows_processcontainer_rejects_proxy_when_bypass_evidence_is_unmapped() {
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(
                host_dependency::WINDOWS_PROCESS_CONTAINER,
                DependencyState::Present,
            )
            .with_dependency(host_dependency::WINDOWS_JOBOBJECT, DependencyState::Present);
        let policy = process_policy(NetworkMode::Proxy);

        let plan = plan_process_backend_policy(
            &policy,
            BackendCapabilityMapId::MxcWindowsProcessContainer,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(matches!(
            plan.policy_plan.outcome,
            BackendPlanOutcome::Unsupported { .. }
        ));
        assert!(!plan.spawn_allowed());
        let error = plan.pre_spawn_error().unwrap();
        assert!(error.contains("audit.bypass_evidence"));

        let strict_proxy = plan
            .policy_plan
            .decisions
            .iter()
            .find(|decision| decision.requirement == "network.strict_proxy")
            .unwrap();
        assert!(matches!(
            strict_proxy.support,
            CapabilitySupport::WeakerOnly { .. }
        ));
    }

    #[test]
    fn process_identity_is_planned_for_native_and_mxc_paths() {
        let mut policy = process_policy(NetworkMode::Allow);
        policy.process.run_as_user = Some("agent".into());

        let linux_runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_BUBBLEWRAP, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_USERNS, DependencyState::Present)
            .with_dependency(
                host_dependency::AXIS_SECCOMP_LAUNCHER,
                DependencyState::Present,
            );
        let linux = plan_process_backend_policy(
            &policy,
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            &linux_runtime,
            &PlannerOptions::new(),
        )
        .unwrap();
        assert!(linux.spawn_allowed(), "{:?}", linux.pre_spawn_error());
        assert!(
            linux
                .policy_plan
                .decisions
                .iter()
                .any(|decision| decision.requirement == "process.user_identity")
        );

        let macos_runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MACOS_SEATBELT, DependencyState::Present);
        let macos = plan_process_backend_policy(
            &policy,
            BackendCapabilityMapId::MxcMacosSeatbelt,
            &macos_runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!macos.spawn_allowed());
        assert!(
            macos
                .pre_spawn_error()
                .unwrap()
                .contains("process.user_identity")
        );
    }

    #[test]
    fn non_process_backend_is_not_plannable_through_process_facade() {
        let runtime = RuntimeProbeSnapshot::new();
        let policy = process_policy(NetworkMode::Allow);

        assert!(
            plan_process_backend_policy(
                &policy,
                BackendCapabilityMapId::MxcLinuxLxc,
                &runtime,
                &PlannerOptions::new()
            )
            .is_none()
        );
    }

    fn process_policy(mode: NetworkMode) -> Policy {
        Policy {
            version: 1,
            name: "process-backend-test".into(),
            filesystem: FilesystemPolicy {
                read_only: vec!["/usr".into()],
                read_write: vec!["{workspace}".into()],
                deny: vec!["~/.ssh".into()],
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
