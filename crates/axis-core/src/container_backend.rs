// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Container-style backend planning.
//!
//! Container backends have launch inputs that are not part of the AXIS policy
//! contract, such as rootfs/image source and storage location. This module
//! keeps those launch requirements planner-visible before a platform adapter
//! generates MXC config.

use crate::capability::{
    BackendPlatform, BackendPolicyPlan, BackendStability, CapabilityRequirement, CapabilitySupport,
    PlannerOptions, PolicySurface, RuntimeProbeSnapshot, plan_backend_policy,
    plan_backend_requirements,
};
use crate::capability_map::{
    BackendCapabilityMapId, backend_capability_map, backend_capability_maps_for_platform,
    host_dependency,
};
use crate::policy::Policy;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerBackendConfigFormat {
    MxcLinuxLxcJson,
    MxcWindowsWslcJson,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerBackendDescriptor {
    pub id: BackendCapabilityMapId,
    pub platform: BackendPlatform,
    pub config_format: ContainerBackendConfigFormat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerRootfsSource {
    LxcDistributionRelease {
        distribution: String,
        release: String,
    },
    WslImage {
        image: String,
    },
    WslImageTar {
        image: String,
        image_tar_path: String,
    },
    ExistingRootfs {
        path: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerMountAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerBindMount {
    pub host_path: String,
    pub container_path: String,
    pub access: ContainerMountAccess,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerLaunchOptions {
    pub rootfs: ContainerRootfsSource,
    #[serde(default)]
    pub storage_path: Option<String>,
    #[serde(default)]
    pub working_dir: Option<String>,
    #[serde(default)]
    pub bind_mounts: Vec<ContainerBindMount>,
    #[serde(default = "default_destroy_on_exit")]
    pub destroy_on_exit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerBackendPlan {
    pub descriptor: ContainerBackendDescriptor,
    pub policy_plan: BackendPolicyPlan,
    pub launch_plan: BackendPolicyPlan,
}

impl ContainerBackendPlan {
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

pub const CONTAINER_BACKEND_DESCRIPTORS: &[ContainerBackendDescriptor] = &[
    ContainerBackendDescriptor {
        id: BackendCapabilityMapId::MxcLinuxLxc,
        platform: BackendPlatform::Linux,
        config_format: ContainerBackendConfigFormat::MxcLinuxLxcJson,
    },
    ContainerBackendDescriptor {
        id: BackendCapabilityMapId::MxcWindowsWslc,
        platform: BackendPlatform::Windows,
        config_format: ContainerBackendConfigFormat::MxcWindowsWslcJson,
    },
];

pub fn container_backend_descriptors() -> &'static [ContainerBackendDescriptor] {
    CONTAINER_BACKEND_DESCRIPTORS
}

pub fn container_backend_descriptor(
    id: BackendCapabilityMapId,
) -> Option<&'static ContainerBackendDescriptor> {
    CONTAINER_BACKEND_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.id == id)
}

pub fn container_backend_descriptors_for_platform(
    platform: BackendPlatform,
) -> Vec<&'static ContainerBackendDescriptor> {
    CONTAINER_BACKEND_DESCRIPTORS
        .iter()
        .filter(|descriptor| descriptor.platform == platform)
        .collect()
}

pub fn container_backend_maps_for_platform(
    platform: BackendPlatform,
) -> Vec<crate::capability::BackendCapabilities> {
    backend_capability_maps_for_platform(platform)
        .into_iter()
        .filter(|backend| {
            CONTAINER_BACKEND_DESCRIPTORS
                .iter()
                .any(|descriptor| descriptor.id.as_str() == backend.name)
        })
        .collect()
}

pub fn plan_container_backend_policy(
    policy: &Policy,
    id: BackendCapabilityMapId,
    launch: &ContainerLaunchOptions,
    runtime: &RuntimeProbeSnapshot,
    options: &PlannerOptions,
) -> Option<ContainerBackendPlan> {
    let descriptor = *container_backend_descriptor(id)?;
    let backend = backend_capability_map(id);
    let policy_plan = plan_backend_policy(policy, &backend, runtime, options);
    let launch_plan = plan_container_launch_options(
        &backend.name,
        backend.stability,
        descriptor,
        launch,
        runtime,
        options,
    );

    Some(ContainerBackendPlan {
        descriptor,
        policy_plan,
        launch_plan,
    })
}

fn plan_container_launch_options(
    backend_name: &str,
    stability: BackendStability,
    descriptor: ContainerBackendDescriptor,
    launch: &ContainerLaunchOptions,
    runtime: &RuntimeProbeSnapshot,
    options: &PlannerOptions,
) -> BackendPolicyPlan {
    let requirements = container_launch_requirements(descriptor, launch);
    plan_backend_requirements(
        backend_name,
        descriptor.platform,
        stability,
        requirements,
        runtime,
        options,
    )
}

fn container_launch_requirements(
    descriptor: ContainerBackendDescriptor,
    launch: &ContainerLaunchOptions,
) -> Vec<CapabilityRequirement> {
    let mut requirements = Vec::new();
    let container_runtime = runtime_support_for_container(descriptor);

    match (descriptor.id, &launch.rootfs) {
        (
            BackendCapabilityMapId::MxcLinuxLxc,
            ContainerRootfsSource::LxcDistributionRelease {
                distribution,
                release,
            },
        ) if !distribution.trim().is_empty() && !release.trim().is_empty() => {
            push_requirement(
                &mut requirements,
                "container.rootfs",
                container_runtime.clone(),
            );
        }
        (BackendCapabilityMapId::MxcWindowsWslc, ContainerRootfsSource::WslImage { image })
            if !image.trim().is_empty() =>
        {
            push_requirement(
                &mut requirements,
                "container.image",
                container_runtime.clone(),
            );
        }
        (
            BackendCapabilityMapId::MxcWindowsWslc,
            ContainerRootfsSource::WslImageTar {
                image,
                image_tar_path,
            },
        ) if !image.trim().is_empty() && !image_tar_path.trim().is_empty() => {
            push_requirement(
                &mut requirements,
                "container.image_tar",
                container_runtime.clone(),
            );
        }
        (
            BackendCapabilityMapId::MxcLinuxLxc,
            ContainerRootfsSource::LxcDistributionRelease { .. },
        ) => {
            push_requirement(
                &mut requirements,
                "container.rootfs",
                CapabilitySupport::unsupported(
                    "LXC rootfs selection requires non-empty distribution and release",
                ),
            );
        }
        (BackendCapabilityMapId::MxcWindowsWslc, ContainerRootfsSource::WslImage { .. }) => {
            push_requirement(
                &mut requirements,
                "container.image",
                CapabilitySupport::unsupported("WSLC image selection requires a non-empty image"),
            );
        }
        (BackendCapabilityMapId::MxcWindowsWslc, ContainerRootfsSource::WslImageTar { .. }) => {
            push_requirement(
                &mut requirements,
                "container.image_tar",
                CapabilitySupport::unsupported(
                    "WSLC image tar import requires non-empty image and image_tar_path",
                ),
            );
        }
        (BackendCapabilityMapId::MxcLinuxLxc, _) => {
            push_requirement(
                &mut requirements,
                "container.rootfs",
                CapabilitySupport::unsupported(
                    "MXC LXC currently requires distribution/release rootfs selection",
                ),
            );
        }
        (BackendCapabilityMapId::MxcWindowsWslc, _) => {
            push_requirement(
                &mut requirements,
                "container.image",
                CapabilitySupport::unsupported(
                    "MXC WSLC currently requires an image name or image tar import",
                ),
            );
        }
        _ => {}
    }

    if let Some(storage_path) = &launch.storage_path {
        if storage_path.trim().is_empty() {
            push_requirement(
                &mut requirements,
                "container.storage",
                CapabilitySupport::unsupported("container storage path must not be empty"),
            );
        } else if matches!(descriptor.id, BackendCapabilityMapId::MxcWindowsWslc) {
            push_requirement(
                &mut requirements,
                "container.storage",
                container_runtime.clone(),
            );
        } else {
            push_requirement(
                &mut requirements,
                "container.storage",
                CapabilitySupport::unsupported("custom LXC storage path is not mapped by AXIS"),
            );
        }
    }

    if let Some(working_dir) = &launch.working_dir {
        if working_dir.trim().is_empty() {
            push_requirement(
                &mut requirements,
                "container.working_dir",
                CapabilitySupport::unsupported("container working directory must not be empty"),
            );
        } else {
            push_requirement(
                &mut requirements,
                "container.working_dir",
                container_runtime.clone(),
            );
        }
    }

    if launch
        .bind_mounts
        .iter()
        .any(|mount| mount.host_path.trim().is_empty() || mount.container_path.trim().is_empty())
    {
        push_requirement(
            &mut requirements,
            "container.bind_mounts",
            CapabilitySupport::unsupported(
                "container bind mounts require host and container paths",
            ),
        );
    } else if !launch.bind_mounts.is_empty() {
        push_requirement(
            &mut requirements,
            "container.bind_mounts",
            container_runtime,
        );
    }

    if launch.destroy_on_exit {
        push_requirement(
            &mut requirements,
            "container.destroy_on_exit",
            CapabilitySupport::AxisOwned,
        );
    } else {
        push_requirement(
            &mut requirements,
            "container.destroy_on_exit",
            CapabilitySupport::unsupported(
                "persistent container state is not mapped to AXIS lifecycle cleanup",
            ),
        );
    }

    requirements
}

fn runtime_support_for_container(descriptor: ContainerBackendDescriptor) -> CapabilitySupport {
    match descriptor.id {
        BackendCapabilityMapId::MxcLinuxLxc => CapabilitySupport::with_dependencies([
            host_dependency::MXC_EXECUTOR,
            host_dependency::LINUX_LXC,
        ]),
        BackendCapabilityMapId::MxcWindowsWslc => CapabilitySupport::with_dependencies([
            host_dependency::MXC_EXECUTOR,
            host_dependency::WINDOWS_WSL2,
        ]),
        _ => CapabilitySupport::unsupported("backend is not a container backend"),
    }
}

fn push_requirement(
    requirements: &mut Vec<CapabilityRequirement>,
    name: &'static str,
    support: CapabilitySupport,
) {
    requirements.push(CapabilityRequirement {
        surface: PolicySurface::Container,
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
    use crate::capability::{BackendPlanOutcome, DependencyState, PolicySurface};
    use crate::policy::{
        FilesystemPolicy, GpuPolicy, InferencePolicy, NetworkMode, NetworkPolicy, Policy,
        ProcessPolicy, SshPolicy,
    };
    use std::collections::BTreeSet;

    #[test]
    fn container_backend_catalog_covers_lxc_and_wslc() {
        let ids = container_backend_descriptors()
            .iter()
            .map(|descriptor| descriptor.id)
            .collect::<BTreeSet<_>>();

        assert!(ids.contains(&BackendCapabilityMapId::MxcLinuxLxc));
        assert!(ids.contains(&BackendCapabilityMapId::MxcWindowsWslc));
    }

    #[test]
    fn container_backend_catalog_is_partitioned_by_platform() {
        assert_eq!(
            container_backend_descriptors_for_platform(BackendPlatform::Linux).len(),
            1
        );
        assert_eq!(
            container_backend_descriptors_for_platform(BackendPlatform::Windows).len(),
            1
        );
        assert!(container_backend_descriptors_for_platform(BackendPlatform::Macos).is_empty());
    }

    #[test]
    fn container_backend_maps_are_filterable_by_platform() {
        let linux_maps = container_backend_maps_for_platform(BackendPlatform::Linux);
        let windows_maps = container_backend_maps_for_platform(BackendPlatform::Windows);

        assert_eq!(linux_maps.len(), 1);
        assert_eq!(linux_maps[0].name, "mxc-linux-lxc");
        assert_eq!(windows_maps.len(), 1);
        assert_eq!(windows_maps[0].name, "mxc-windows-wslc");
    }

    #[test]
    fn lxc_distribution_release_with_present_dependencies_is_allowed() {
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_LXC, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_CGROUP_V2, DependencyState::Present);
        let launch = lxc_launch();

        let plan = plan_container_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcLinuxLxc,
            &launch,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(plan.spawn_allowed(), "{:?}", plan.pre_spawn_error());
        for requirement in [
            "container.rootfs",
            "container.working_dir",
            "container.bind_mounts",
            "container.destroy_on_exit",
        ] {
            assert!(
                plan.launch_plan
                    .decisions
                    .iter()
                    .any(|decision| decision.requirement == requirement),
                "missing launch decision {requirement}"
            );
        }
    }

    #[test]
    fn lxc_missing_lxc_dependency_blocks_before_spawn() {
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_CGROUP_V2, DependencyState::Present);
        let launch = lxc_launch();

        let plan = plan_container_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcLinuxLxc,
            &launch,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!plan.spawn_allowed());
        let error = plan.pre_spawn_error().unwrap();
        assert!(error.contains(host_dependency::LINUX_LXC));
        assert!(error.contains("missing host dependency"));
    }

    #[test]
    fn lxc_resource_limits_require_cgroup_dependency() {
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_LXC, DependencyState::Present);
        let launch = lxc_launch();
        let mut policy = policy(NetworkMode::Allow);
        policy.process.max_memory_mb = 64;

        let plan = plan_container_backend_policy(
            &policy,
            BackendCapabilityMapId::MxcLinuxLxc,
            &launch,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!plan.spawn_allowed());
        let error = plan.pre_spawn_error().unwrap();
        assert!(error.contains("resources.memory"));
        assert!(error.contains(host_dependency::LINUX_CGROUP_V2));
    }

    #[test]
    fn lxc_rejects_wsl_image_source() {
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_LXC, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_CGROUP_V2, DependencyState::Present);
        let launch = ContainerLaunchOptions {
            rootfs: ContainerRootfsSource::WslImage {
                image: "alpine:latest".into(),
            },
            storage_path: None,
            working_dir: None,
            bind_mounts: Vec::new(),
            destroy_on_exit: true,
        };

        let plan = plan_container_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcLinuxLxc,
            &launch,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(matches!(
            plan.launch_plan.outcome,
            BackendPlanOutcome::Unsupported { .. }
        ));
        assert!(plan.pre_spawn_error().unwrap().contains("container.rootfs"));
    }

    #[test]
    fn lxc_rejects_custom_storage_until_mapped() {
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_LXC, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_CGROUP_V2, DependencyState::Present);
        let mut launch = lxc_launch();
        launch.storage_path = Some("/var/lib/axis/lxc".into());

        let plan = plan_container_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcLinuxLxc,
            &launch,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!plan.spawn_allowed());
        assert!(
            plan.pre_spawn_error()
                .unwrap()
                .contains("container.storage")
        );
    }

    #[test]
    fn wslc_image_with_present_dependencies_is_allowed_for_allow_policy() {
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::WINDOWS_WSL2, DependencyState::Present);
        let launch = wslc_launch();

        let plan = plan_container_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcWindowsWslc,
            &launch,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(plan.spawn_allowed(), "{:?}", plan.pre_spawn_error());
        assert!(
            plan.launch_plan
                .decisions
                .iter()
                .any(|decision| decision.requirement == "container.image")
        );
        assert!(
            plan.launch_plan
                .decisions
                .iter()
                .any(|decision| decision.requirement == "container.storage")
        );
    }

    #[test]
    fn wslc_image_tar_requires_tar_path() {
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::WINDOWS_WSL2, DependencyState::Present);
        let launch = ContainerLaunchOptions {
            rootfs: ContainerRootfsSource::WslImageTar {
                image: "alpine-export:latest".into(),
                image_tar_path: String::new(),
            },
            storage_path: None,
            working_dir: None,
            bind_mounts: Vec::new(),
            destroy_on_exit: true,
        };

        let plan = plan_container_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcWindowsWslc,
            &launch,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!plan.spawn_allowed());
        assert!(
            plan.pre_spawn_error()
                .unwrap()
                .contains("container.image_tar")
        );
    }

    #[test]
    fn wslc_block_network_is_weaker_until_explicitly_accepted() {
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::WINDOWS_WSL2, DependencyState::Present);
        let launch = wslc_launch();

        let plan = plan_container_backend_policy(
            &policy(NetworkMode::Block),
            BackendCapabilityMapId::MxcWindowsWslc,
            &launch,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(matches!(
            plan.policy_plan.outcome,
            BackendPlanOutcome::WeakerOnly {
                accepted: false,
                ..
            }
        ));
        assert!(!plan.spawn_allowed());

        let accepted = plan_container_backend_policy(
            &policy(NetworkMode::Block),
            BackendCapabilityMapId::MxcWindowsWslc,
            &launch,
            &runtime,
            &PlannerOptions::new().accept_weaker_surface(PolicySurface::Network),
        )
        .unwrap();
        assert!(accepted.spawn_allowed(), "{:?}", accepted.pre_spawn_error());
    }

    #[test]
    fn wslc_denied_paths_are_weaker_and_not_spawnable_by_default() {
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::WINDOWS_WSL2, DependencyState::Present);
        let launch = wslc_launch();
        let mut policy = policy(NetworkMode::Allow);
        policy.filesystem.deny.push("C:\\Users\\agent\\.ssh".into());

        let plan = plan_container_backend_policy(
            &policy,
            BackendCapabilityMapId::MxcWindowsWslc,
            &launch,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!plan.spawn_allowed());
        assert!(
            plan.pre_spawn_error()
                .unwrap()
                .contains("backend offers only weaker behavior")
        );
    }

    #[test]
    fn wslc_resource_limits_are_weaker_and_not_spawnable_by_default() {
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::WINDOWS_WSL2, DependencyState::Present);
        let launch = wslc_launch();
        let mut policy = policy(NetworkMode::Allow);
        policy.process.max_memory_mb = 1024;

        let plan = plan_container_backend_policy(
            &policy,
            BackendCapabilityMapId::MxcWindowsWslc,
            &launch,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!plan.spawn_allowed());
        let error = plan.pre_spawn_error().unwrap();
        assert!(error.contains("resources.memory"));
        assert!(error.contains("cleanup.resources"));
    }

    #[test]
    fn wslc_proxy_remains_rejected_when_bypass_evidence_is_unmapped() {
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::WINDOWS_WSL2, DependencyState::Present);
        let launch = wslc_launch();

        let plan = plan_container_backend_policy(
            &policy(NetworkMode::Proxy),
            BackendCapabilityMapId::MxcWindowsWslc,
            &launch,
            &runtime,
            &PlannerOptions::new().accept_weaker_surface(PolicySurface::Network),
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
    fn persistent_container_state_is_rejected_until_lifecycle_cleanup_is_mapped() {
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_LXC, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_CGROUP_V2, DependencyState::Present);
        let mut launch = lxc_launch();
        launch.destroy_on_exit = false;

        let plan = plan_container_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcLinuxLxc,
            &launch,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!plan.spawn_allowed());
        assert!(
            plan.pre_spawn_error()
                .unwrap()
                .contains("container.destroy_on_exit")
        );
    }

    #[test]
    fn empty_container_working_directory_is_rejected_before_spawn() {
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_LXC, DependencyState::Present);
        let mut launch = lxc_launch();
        launch.working_dir = Some(String::new());

        let plan = plan_container_backend_policy(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcLinuxLxc,
            &launch,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!plan.spawn_allowed());
        assert!(
            plan.pre_spawn_error()
                .unwrap()
                .contains("container.working_dir")
        );
    }

    #[test]
    fn non_container_backend_is_not_plannable_through_container_facade() {
        let runtime = RuntimeProbeSnapshot::new();

        assert!(
            plan_container_backend_policy(
                &policy(NetworkMode::Allow),
                BackendCapabilityMapId::MxcLinuxBubblewrap,
                &lxc_launch(),
                &runtime,
                &PlannerOptions::new(),
            )
            .is_none()
        );
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

    fn wslc_launch() -> ContainerLaunchOptions {
        ContainerLaunchOptions {
            rootfs: ContainerRootfsSource::WslImage {
                image: "alpine:latest".into(),
            },
            storage_path: Some("C:\\axis\\wslc".into()),
            working_dir: Some("/workspace".into()),
            bind_mounts: vec![ContainerBindMount {
                host_path: "C:\\workspace".into(),
                container_path: "/workspace".into(),
                access: ContainerMountAccess::ReadWrite,
            }],
            destroy_on_exit: true,
        }
    }

    fn policy(mode: NetworkMode) -> Policy {
        Policy {
            version: 1,
            name: "container-backend-test".into(),
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
}
