// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Backend default decisions and benchmark evidence requirements.
//!
//! This module is intentionally side-effect free. Runtime benchmark harnesses
//! and public decision records consume the same records so default selection
//! cannot drift away from the required evidence.

use crate::capability::BackendPlatform;
use crate::capability_map::BackendCapabilityMapId;
use serde::{Serialize, Serializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendExecutionClass {
    Process,
    Container,
    Vm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendDefaultStatus {
    CurrentDefault,
    Retained,
    Candidate,
    ExperimentalOptIn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendBenchmarkMetric {
    Startup,
    Teardown,
    ColdStart,
    WarmStart,
    MaxRss,
    FileDescriptors,
    ProcessCount,
    Density,
    HostDependencyCost,
    SecurityCoverage,
    UnsupportedPolicyCount,
    CleanupFailures,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BackendDefaultRecord {
    #[serde(serialize_with = "serialize_backend_id")]
    pub id: BackendCapabilityMapId,
    pub platform: BackendPlatform,
    pub execution_class: BackendExecutionClass,
    pub status: BackendDefaultStatus,
    pub rationale: &'static str,
    pub required_benchmark_metrics: &'static [BackendBenchmarkMetric],
    pub required_security_evidence: &'static [&'static str],
    pub benchmark_gate: Option<&'static str>,
}

fn serialize_backend_id<S>(id: &BackendCapabilityMapId, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(id.as_str())
}

const PROCESS_METRICS: &[BackendBenchmarkMetric] = &[
    BackendBenchmarkMetric::Startup,
    BackendBenchmarkMetric::Teardown,
    BackendBenchmarkMetric::MaxRss,
    BackendBenchmarkMetric::FileDescriptors,
    BackendBenchmarkMetric::ProcessCount,
    BackendBenchmarkMetric::Density,
    BackendBenchmarkMetric::HostDependencyCost,
    BackendBenchmarkMetric::SecurityCoverage,
    BackendBenchmarkMetric::UnsupportedPolicyCount,
    BackendBenchmarkMetric::CleanupFailures,
];

const CONTAINER_METRICS: &[BackendBenchmarkMetric] = &[
    BackendBenchmarkMetric::Startup,
    BackendBenchmarkMetric::Teardown,
    BackendBenchmarkMetric::ColdStart,
    BackendBenchmarkMetric::WarmStart,
    BackendBenchmarkMetric::MaxRss,
    BackendBenchmarkMetric::FileDescriptors,
    BackendBenchmarkMetric::ProcessCount,
    BackendBenchmarkMetric::Density,
    BackendBenchmarkMetric::HostDependencyCost,
    BackendBenchmarkMetric::SecurityCoverage,
    BackendBenchmarkMetric::UnsupportedPolicyCount,
    BackendBenchmarkMetric::CleanupFailures,
];

const VM_METRICS: &[BackendBenchmarkMetric] = &[
    BackendBenchmarkMetric::ColdStart,
    BackendBenchmarkMetric::WarmStart,
    BackendBenchmarkMetric::Teardown,
    BackendBenchmarkMetric::MaxRss,
    BackendBenchmarkMetric::ProcessCount,
    BackendBenchmarkMetric::Density,
    BackendBenchmarkMetric::HostDependencyCost,
    BackendBenchmarkMetric::SecurityCoverage,
    BackendBenchmarkMetric::UnsupportedPolicyCount,
    BackendBenchmarkMetric::CleanupFailures,
];

const SECURITY_EVIDENCE: &[&str] = &[
    "planner exact/weaker/unsupported policy outcome counts",
    "negative tests for unsupported or weaker policy surfaces",
    "credential-boundary and proxy-bypass coverage",
    "cleanup failure and resource-leak coverage",
];

const NATIVE_SECURITY_EVIDENCE: &[&str] = &[
    "current native security test matrix",
    "planner exact/weaker/unsupported policy outcome counts",
    "credential-boundary and proxy-bypass coverage",
    "cleanup failure and resource-leak coverage",
];

pub const BACKEND_DEFAULT_RECORDS: &[BackendDefaultRecord] = &[
    BackendDefaultRecord {
        id: BackendCapabilityMapId::AxisNativeLinux,
        platform: BackendPlatform::Linux,
        execution_class: BackendExecutionClass::Process,
        status: BackendDefaultStatus::Retained,
        rationale: "Native Linux remains selectable because direct Landlock, seccomp, strict native netns proxy integration, and binary attribution are AXIS-owned capabilities that MXC Bubblewrap has not fully replaced.",
        required_benchmark_metrics: PROCESS_METRICS,
        required_security_evidence: NATIVE_SECURITY_EVIDENCE,
        benchmark_gate: Some(
            "AXIS_RUNTIME_METRICS_PROVIDERS=axis_native cargo run --locked -p axis-bench --bin runtime-metrics",
        ),
    },
    BackendDefaultRecord {
        id: BackendCapabilityMapId::MxcLinuxBubblewrap,
        platform: BackendPlatform::Linux,
        execution_class: BackendExecutionClass::Process,
        status: BackendDefaultStatus::CurrentDefault,
        rationale: "MXC Bubblewrap is the Linux process default for packaged no-admin runs. AXIS supplies seccomp, resource, credential, proxy policy, and cleanup layers around the MXC process backend.",
        required_benchmark_metrics: PROCESS_METRICS,
        required_security_evidence: SECURITY_EVIDENCE,
        benchmark_gate: Some(
            "AXIS_RUNTIME_METRICS_PROVIDERS=mxc AXIS_RUNTIME_METRICS_PROFILES=mxc_process cargo run --locked -p axis-bench --bin runtime-metrics",
        ),
    },
    BackendDefaultRecord {
        id: BackendCapabilityMapId::MxcLinuxLxc,
        platform: BackendPlatform::Linux,
        execution_class: BackendExecutionClass::Container,
        status: BackendDefaultStatus::Candidate,
        rationale: "MXC LXC is evaluated as a container backend, not a lightweight process default, because it carries image/runtime dependency cost and different lifecycle semantics.",
        required_benchmark_metrics: CONTAINER_METRICS,
        required_security_evidence: SECURITY_EVIDENCE,
        benchmark_gate: Some("AXIS_BENCH_MXC_LXC=1"),
    },
    BackendDefaultRecord {
        id: BackendCapabilityMapId::MxcLinuxMicrovm,
        platform: BackendPlatform::Linux,
        execution_class: BackendExecutionClass::Vm,
        status: BackendDefaultStatus::ExperimentalOptIn,
        rationale: "MXC MicroVM is experimental for high-risk or VM-style workloads and must not be selected as a default full-agent backend without KVM-dependent benchmark and security evidence.",
        required_benchmark_metrics: VM_METRICS,
        required_security_evidence: SECURITY_EVIDENCE,
        benchmark_gate: Some("AXIS_BENCH_MXC_MICROVM=1"),
    },
    BackendDefaultRecord {
        id: BackendCapabilityMapId::MxcLinuxHyperlight,
        platform: BackendPlatform::Linux,
        execution_class: BackendExecutionClass::Vm,
        status: BackendDefaultStatus::ExperimentalOptIn,
        rationale: "MXC Hyperlight is experimental for snapshot-style workloads and remains opt-in until runtime artifacts, startup, density, and policy limitations are proven.",
        required_benchmark_metrics: VM_METRICS,
        required_security_evidence: SECURITY_EVIDENCE,
        benchmark_gate: Some("AXIS_BENCH_MXC_HYPERLIGHT=1"),
    },
    BackendDefaultRecord {
        id: BackendCapabilityMapId::AxisNativeMacosSeatbelt,
        platform: BackendPlatform::Macos,
        execution_class: BackendExecutionClass::Process,
        status: BackendDefaultStatus::CurrentDefault,
        rationale: "Native macOS Seatbelt remains the process default while it preserves the no-extra-runtime sandbox path and platform-native filesystem and network-deny controls.",
        required_benchmark_metrics: PROCESS_METRICS,
        required_security_evidence: NATIVE_SECURITY_EVIDENCE,
        benchmark_gate: Some("cargo run --locked -p axis-bench --bin success-metrics"),
    },
    BackendDefaultRecord {
        id: BackendCapabilityMapId::MxcMacosSeatbelt,
        platform: BackendPlatform::Macos,
        execution_class: BackendExecutionClass::Process,
        status: BackendDefaultStatus::Candidate,
        rationale: "MXC Seatbelt is a macOS process candidate and must prove equivalent profile generation, lifecycle, packaging, startup, and dependency cost before replacing the native default.",
        required_benchmark_metrics: PROCESS_METRICS,
        required_security_evidence: SECURITY_EVIDENCE,
        benchmark_gate: Some("AXIS_BENCH_MXC_MACOS_SEATBELT=1"),
    },
    BackendDefaultRecord {
        id: BackendCapabilityMapId::AxisNativeWindows,
        platform: BackendPlatform::Windows,
        execution_class: BackendExecutionClass::Process,
        status: BackendDefaultStatus::Candidate,
        rationale: "Native Windows remains unavailable until Restricted Token, Job Object, filesystem, environment, and network controls are applied to the spawned process and validated as one boundary.",
        required_benchmark_metrics: PROCESS_METRICS,
        required_security_evidence: NATIVE_SECURITY_EVIDENCE,
        benchmark_gate: Some("cargo run --locked -p axis-bench --bin success-metrics"),
    },
    BackendDefaultRecord {
        id: BackendCapabilityMapId::MxcWindowsProcessContainer,
        platform: BackendPlatform::Windows,
        execution_class: BackendExecutionClass::Process,
        status: BackendDefaultStatus::CurrentDefault,
        rationale: "MXC ProcessContainer is the Windows process default. AXIS rejects unsupported policy surfaces, sanitizes the executor boundary, and owns timeout and cleanup around the packaged MXC runtime.",
        required_benchmark_metrics: PROCESS_METRICS,
        required_security_evidence: SECURITY_EVIDENCE,
        benchmark_gate: Some("AXIS_BENCH_MXC_WINDOWS_PROCESSCONTAINER=1"),
    },
    BackendDefaultRecord {
        id: BackendCapabilityMapId::MxcWindowsIsolationSession,
        platform: BackendPlatform::Windows,
        execution_class: BackendExecutionClass::Vm,
        status: BackendDefaultStatus::ExperimentalOptIn,
        rationale: "MXC Isolation Session remains opt-in because VM-style provisioning has distinct dependency, lifecycle, and density costs from process backends.",
        required_benchmark_metrics: VM_METRICS,
        required_security_evidence: SECURITY_EVIDENCE,
        benchmark_gate: Some("AXIS_BENCH_MXC_WINDOWS_ISOLATION_SESSION=1"),
    },
    BackendDefaultRecord {
        id: BackendCapabilityMapId::MxcWindowsSandbox,
        platform: BackendPlatform::Windows,
        execution_class: BackendExecutionClass::Vm,
        status: BackendDefaultStatus::ExperimentalOptIn,
        rationale: "Windows Sandbox remains opt-in for high-risk tasks until startup, density, filesystem mapping, and cleanup behavior are measured against process alternatives.",
        required_benchmark_metrics: VM_METRICS,
        required_security_evidence: SECURITY_EVIDENCE,
        benchmark_gate: Some("AXIS_BENCH_MXC_WINDOWS_SANDBOX=1"),
    },
    BackendDefaultRecord {
        id: BackendCapabilityMapId::MxcWindowsWslc,
        platform: BackendPlatform::Windows,
        execution_class: BackendExecutionClass::Container,
        status: BackendDefaultStatus::Candidate,
        rationale: "MXC WSLC is evaluated as a container backend because WSL2 distribution lifecycle and VM-scoped resources differ from AXIS process-backend defaults.",
        required_benchmark_metrics: CONTAINER_METRICS,
        required_security_evidence: SECURITY_EVIDENCE,
        benchmark_gate: Some("AXIS_BENCH_MXC_WINDOWS_WSLC=1"),
    },
    BackendDefaultRecord {
        id: BackendCapabilityMapId::MxcWindowsMicrovm,
        platform: BackendPlatform::Windows,
        execution_class: BackendExecutionClass::Vm,
        status: BackendDefaultStatus::ExperimentalOptIn,
        rationale: "Windows MicroVM remains experimental until WHP dependency cost, startup, memory, density, and policy limitations are proven.",
        required_benchmark_metrics: VM_METRICS,
        required_security_evidence: SECURITY_EVIDENCE,
        benchmark_gate: Some("AXIS_BENCH_MXC_WINDOWS_MICROVM=1"),
    },
    BackendDefaultRecord {
        id: BackendCapabilityMapId::MxcWindowsHyperlight,
        platform: BackendPlatform::Windows,
        execution_class: BackendExecutionClass::Vm,
        status: BackendDefaultStatus::ExperimentalOptIn,
        rationale: "Windows Hyperlight remains experimental until runtime artifact handling, startup, density, and policy limitations are proven.",
        required_benchmark_metrics: VM_METRICS,
        required_security_evidence: SECURITY_EVIDENCE,
        benchmark_gate: Some("AXIS_BENCH_MXC_WINDOWS_HYPERLIGHT=1"),
    },
];

pub fn backend_default_records() -> &'static [BackendDefaultRecord] {
    BACKEND_DEFAULT_RECORDS
}

pub fn backend_default_record(id: BackendCapabilityMapId) -> Option<&'static BackendDefaultRecord> {
    BACKEND_DEFAULT_RECORDS
        .iter()
        .find(|record| record.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_map::BACKEND_CAPABILITY_MAP_IDS;
    use std::collections::BTreeSet;

    #[test]
    fn default_records_cover_every_backend_capability_map() {
        let expected = BACKEND_CAPABILITY_MAP_IDS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let actual = backend_default_records()
            .iter()
            .map(|record| record.id)
            .collect::<BTreeSet<_>>();

        assert_eq!(
            actual, expected,
            "every backend capability map needs benchmark/default evidence requirements"
        );
    }

    #[test]
    fn current_process_defaults_match_implemented_platform_choices() {
        for (platform, expected) in [
            (
                BackendPlatform::Linux,
                BackendCapabilityMapId::MxcLinuxBubblewrap,
            ),
            (
                BackendPlatform::Macos,
                BackendCapabilityMapId::AxisNativeMacosSeatbelt,
            ),
            (
                BackendPlatform::Windows,
                BackendCapabilityMapId::MxcWindowsProcessContainer,
            ),
        ] {
            let defaults = backend_default_records()
                .iter()
                .filter(|record| {
                    record.platform == platform
                        && record.execution_class == BackendExecutionClass::Process
                        && record.status == BackendDefaultStatus::CurrentDefault
                })
                .collect::<Vec<_>>();

            assert_eq!(
                defaults.len(),
                1,
                "{platform:?} must have one process default"
            );
            assert_eq!(
                defaults[0].id, expected,
                "{platform:?} process default must match the declared backend decision"
            );
        }
    }

    #[test]
    fn non_default_records_require_security_and_benchmark_evidence() {
        for record in backend_default_records()
            .iter()
            .filter(|record| record.status != BackendDefaultStatus::CurrentDefault)
        {
            for metric in [
                BackendBenchmarkMetric::HostDependencyCost,
                BackendBenchmarkMetric::SecurityCoverage,
                BackendBenchmarkMetric::UnsupportedPolicyCount,
                BackendBenchmarkMetric::CleanupFailures,
            ] {
                assert!(
                    record.required_benchmark_metrics.contains(&metric),
                    "{} missing required metric {metric:?}",
                    record.id.as_str()
                );
            }
            assert!(
                record.required_security_evidence.len() >= 4,
                "{} must require defensive security evidence",
                record.id.as_str()
            );
            assert!(
                record.benchmark_gate.is_some(),
                "{} must name its benchmark gate or smoke command",
                record.id.as_str()
            );
        }
    }

    #[test]
    fn mxc_non_default_records_use_backend_specific_benchmark_gates() {
        for record in backend_default_records().iter().filter(|record| {
            record.status != BackendDefaultStatus::CurrentDefault
                && record.id.as_str().starts_with("mxc-")
        }) {
            let gate = record.benchmark_gate.unwrap();
            assert!(
                gate.starts_with("AXIS_BENCH_MXC_"),
                "{} must use a backend-specific benchmark gate, got {gate}",
                record.id.as_str()
            );
        }
    }

    #[test]
    fn vm_backends_are_not_full_agent_defaults() {
        for record in backend_default_records()
            .iter()
            .filter(|record| record.execution_class == BackendExecutionClass::Vm)
        {
            assert_eq!(
                record.status,
                BackendDefaultStatus::ExperimentalOptIn,
                "{} must remain opt-in until VM-style policy and benchmark evidence exists",
                record.id.as_str()
            );
            assert!(
                record
                    .required_benchmark_metrics
                    .contains(&BackendBenchmarkMetric::ColdStart)
                    && record
                        .required_benchmark_metrics
                        .contains(&BackendBenchmarkMetric::WarmStart)
                    && record
                        .required_benchmark_metrics
                        .contains(&BackendBenchmarkMetric::Density),
                "{} must require cold, warm, and density benchmark evidence",
                record.id.as_str()
            );
        }
    }

    #[test]
    fn lookup_returns_the_declared_record() {
        for record in backend_default_records() {
            assert_eq!(backend_default_record(record.id), Some(record));
        }
    }
}
