// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Backend policy evidence reports.
//!
//! These reports are side-effect free. They exercise the shared capability
//! planner against a fixed policy scenario suite and summarize the exact,
//! host-dependent, weaker, and unsupported outcomes used by backend default
//! decisions and benchmark records.

use crate::backend_defaults::{BackendDefaultStatus, backend_default_record};
use crate::capability::{
    BackendPlanOutcome, BackendPlatform, BackendStability, CapabilitySupport, DependencyState,
    PlannerOptions, RuntimeProbeSnapshot, SurfaceDecision, plan_backend_policy,
};
use crate::capability_map::{
    BACKEND_CAPABILITY_MAP_IDS, BackendCapabilityMapId, backend_capability_map,
};
use crate::policy::Policy;
use serde::Serialize;

const POLICY_SCENARIOS: &[PolicyScenario] = &[
    PolicyScenario {
        name: "allow_minimal",
        description: "minimal process execution with allow-mode network",
        yaml: r#"
version: 1
name: evidence-allow-minimal
filesystem:
  read_only:
    - /usr
  read_write:
    - "{workspace}"
process:
  max_processes: 0
  max_memory_mb: 0
  cpu_rate_percent: 0
network:
  mode: allow
"#,
    },
    PolicyScenario {
        name: "block_resources_syscalls",
        description: "block-mode execution with filesystem denial, resources, timeout, and syscall filtering",
        yaml: r#"
version: 1
name: evidence-block-resources-syscalls
filesystem:
  read_only:
    - /usr
  read_write:
    - "{workspace}"
  deny:
    - /home
process:
  max_processes: 8
  max_memory_mb: 512
  cpu_rate_percent: 50
  blocked_syscalls:
    - ptrace
  timeout_sec: 5
network:
  mode: block
"#,
    },
    PolicyScenario {
        name: "strict_proxy_binary",
        description: "strict proxy endpoint policy with binary attribution",
        yaml: r#"
version: 1
name: evidence-strict-proxy-binary
filesystem:
  read_only:
    - /usr
  read_write:
    - "{workspace}"
process:
  max_processes: 0
  max_memory_mb: 0
  cpu_rate_percent: 0
network:
  mode: proxy
  policies:
    - name: inference-local
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write
      binaries:
        - path: "*/python*"
"#,
    },
    PolicyScenario {
        name: "portable_isolated_no_children",
        description: "portable isolated identity with an atomic one-process tree limit",
        yaml: r#"
version: 1
name: evidence-portable-isolated-no-children
filesystem:
  read_write:
    - "{workspace}"
process:
  identity: isolated
  child_processes: deny
  max_memory_mb: 0
  cpu_rate_percent: 0
network:
  mode: block
"#,
    },
    PolicyScenario {
        name: "inference_routes_streaming",
        description: "local inference, local host-boundary credentials, and external streaming",
        yaml: r#"
version: 1
name: evidence-inference-local-external-streaming
filesystem:
  read_only:
    - /usr
  read_write:
    - "{workspace}"
process:
  max_processes: 0
  max_memory_mb: 0
  cpu_rate_percent: 0
network:
  mode: proxy
  policies:
    - name: inference-local
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write
inference:
  default_provider: local-rocm
  routes:
    - name: local-rocm
      endpoint: "http://inference.local"
      protocols: [openai_chat_completions, model_discovery]
      model: "llama-4-scout-109b"
    - name: external-anthropic
      provider: anthropic
      model: "claude-sonnet-4"
      protocols: [messages_streaming]
    - name: local-authenticated
      endpoint: "http://inference.local:8081"
      api_key_env: LOCAL_INFERENCE_KEY
"#,
    },
];

#[derive(Debug, Clone, Copy)]
struct PolicyScenario {
    name: &'static str,
    description: &'static str,
    yaml: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackendEvidenceReport {
    pub backend: &'static str,
    pub platform: BackendPlatform,
    pub stability: BackendStability,
    pub default_status: Option<BackendDefaultStatus>,
    pub benchmark_gate: Option<&'static str>,
    pub host_dependencies: Vec<String>,
    pub scenario_count: usize,
    pub outcome_counts: PolicyOutcomeCounts,
    pub support_counts: SupportCounts,
    pub scenarios: Vec<PolicyScenarioEvidence>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PolicyOutcomeCounts {
    pub exact: usize,
    pub exact_with_host_dependency: usize,
    pub weaker_only: usize,
    pub unsupported: usize,
    pub spawn_allowed_with_declared_dependencies: usize,
    pub spawn_allowed_without_host_dependencies: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SupportCounts {
    pub exact: usize,
    pub axis_owned: usize,
    pub exact_with_host_dependency: usize,
    pub weaker_only: usize,
    pub unsupported: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyScenarioEvidence {
    pub scenario: &'static str,
    pub description: &'static str,
    pub outcome: PolicyOutcomeKind,
    pub spawn_allowed_with_declared_dependencies: bool,
    pub spawn_allowed_without_host_dependencies: bool,
    pub decision_count: usize,
    pub support_counts: SupportCounts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOutcomeKind {
    Exact,
    ExactWithHostDependency,
    WeakerOnly,
    Unsupported,
}

pub fn backend_evidence_reports() -> Vec<BackendEvidenceReport> {
    BACKEND_CAPABILITY_MAP_IDS
        .iter()
        .copied()
        .map(backend_evidence_report)
        .collect()
}

pub fn backend_evidence_report(id: BackendCapabilityMapId) -> BackendEvidenceReport {
    let backend = backend_capability_map(id);
    let declared_runtime = runtime_with_declared_dependencies_present(&backend);
    let empty_runtime = RuntimeProbeSnapshot::new();
    let options = PlannerOptions::new();

    let mut outcome_counts = PolicyOutcomeCounts::default();
    let mut support_counts = SupportCounts::default();
    let mut scenarios = Vec::with_capacity(POLICY_SCENARIOS.len());

    for scenario in POLICY_SCENARIOS {
        let policy = scenario.policy();
        let declared_plan = plan_backend_policy(&policy, &backend, &declared_runtime, &options);
        let empty_plan = plan_backend_policy(&policy, &backend, &empty_runtime, &options);
        let outcome = PolicyOutcomeKind::from_plan_outcome(&declared_plan.outcome);
        let scenario_support_counts = support_counts_for_decisions(&declared_plan.decisions);

        outcome_counts.record(outcome);
        if declared_plan.spawn_allowed() {
            outcome_counts.spawn_allowed_with_declared_dependencies += 1;
        }
        if empty_plan.spawn_allowed() {
            outcome_counts.spawn_allowed_without_host_dependencies += 1;
        }
        support_counts.add(&scenario_support_counts);

        scenarios.push(PolicyScenarioEvidence {
            scenario: scenario.name,
            description: scenario.description,
            outcome,
            spawn_allowed_with_declared_dependencies: declared_plan.spawn_allowed(),
            spawn_allowed_without_host_dependencies: empty_plan.spawn_allowed(),
            decision_count: declared_plan.decisions.len(),
            support_counts: scenario_support_counts,
        });
    }

    let default_record = backend_default_record(id);
    BackendEvidenceReport {
        backend: id.as_str(),
        platform: backend.platform,
        stability: backend.stability,
        default_status: default_record.map(|record| record.status),
        benchmark_gate: default_record.and_then(|record| record.benchmark_gate),
        host_dependencies: backend
            .host_dependencies
            .iter()
            .map(|dependency| dependency.name.clone())
            .collect(),
        scenario_count: scenarios.len(),
        outcome_counts,
        support_counts,
        scenarios,
    }
}

impl PolicyScenario {
    fn policy(self) -> Policy {
        Policy::from_yaml(self.yaml).expect("backend evidence policy scenario must parse")
    }
}

impl PolicyOutcomeCounts {
    fn record(&mut self, outcome: PolicyOutcomeKind) {
        match outcome {
            PolicyOutcomeKind::Exact => self.exact += 1,
            PolicyOutcomeKind::ExactWithHostDependency => self.exact_with_host_dependency += 1,
            PolicyOutcomeKind::WeakerOnly => self.weaker_only += 1,
            PolicyOutcomeKind::Unsupported => self.unsupported += 1,
        }
    }
}

impl SupportCounts {
    fn add(&mut self, other: &Self) {
        self.exact += other.exact;
        self.axis_owned += other.axis_owned;
        self.exact_with_host_dependency += other.exact_with_host_dependency;
        self.weaker_only += other.weaker_only;
        self.unsupported += other.unsupported;
    }
}

impl PolicyOutcomeKind {
    fn from_plan_outcome(outcome: &BackendPlanOutcome) -> Self {
        match outcome {
            BackendPlanOutcome::Exact => Self::Exact,
            BackendPlanOutcome::ExactWithHostDependency { .. } => Self::ExactWithHostDependency,
            BackendPlanOutcome::WeakerOnly { .. } => Self::WeakerOnly,
            BackendPlanOutcome::Unsupported { .. } => Self::Unsupported,
        }
    }
}

fn runtime_with_declared_dependencies_present(
    backend: &crate::capability::BackendCapabilities,
) -> RuntimeProbeSnapshot {
    backend
        .host_dependencies
        .iter()
        .fold(RuntimeProbeSnapshot::new(), |runtime, dependency| {
            runtime.with_dependency(dependency.name.clone(), DependencyState::Present)
        })
}

fn support_counts_for_decisions(decisions: &[SurfaceDecision]) -> SupportCounts {
    let mut counts = SupportCounts::default();
    for decision in decisions {
        match &decision.support {
            CapabilitySupport::Exact => counts.exact += 1,
            CapabilitySupport::AxisOwned => counts.axis_owned += 1,
            CapabilitySupport::ExactWithHostDependency { .. } => {
                counts.exact_with_host_dependency += 1;
            }
            CapabilitySupport::WeakerOnly { .. } => counts.weaker_only += 1,
            CapabilitySupport::Unsupported { .. } => counts.unsupported += 1,
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend_defaults::backend_default_records;

    #[test]
    fn evidence_reports_cover_every_backend_default_record() {
        let reports = backend_evidence_reports();

        assert_eq!(reports.len(), backend_default_records().len());
        for report in reports {
            assert_eq!(report.scenario_count, POLICY_SCENARIOS.len());
            assert_eq!(report.scenarios.len(), report.scenario_count);
            assert!(
                report.benchmark_gate.is_some(),
                "{} must identify benchmark evidence gate",
                report.backend
            );
        }
    }

    #[test]
    fn scenario_suite_exercises_security_sensitive_outcomes() {
        let reports = backend_evidence_reports();
        let unsupported_total = reports
            .iter()
            .map(|report| report.outcome_counts.unsupported)
            .sum::<usize>();
        let weaker_total = reports
            .iter()
            .map(|report| report.outcome_counts.weaker_only)
            .sum::<usize>();
        let host_dependency_total = reports
            .iter()
            .map(|report| report.support_counts.exact_with_host_dependency)
            .sum::<usize>();
        let axis_owned_total = reports
            .iter()
            .map(|report| report.support_counts.axis_owned)
            .sum::<usize>();

        assert!(
            unsupported_total > 0,
            "scenario suite must expose unsupported policy/backend pairs"
        );
        assert!(
            weaker_total > 0,
            "scenario suite must expose weaker-only policy/backend pairs"
        );
        assert!(
            host_dependency_total > 0,
            "scenario suite must expose host dependency counts"
        );
        assert!(
            axis_owned_total > 0,
            "scenario suite must expose AXIS-owned policy layers"
        );
    }

    #[test]
    fn declared_dependencies_never_reduce_spawn_allowed_counts() {
        for id in [
            BackendCapabilityMapId::AxisNativeLinux,
            BackendCapabilityMapId::AxisNativeMacosSeatbelt,
            BackendCapabilityMapId::AxisNativeWindows,
        ] {
            let report = backend_evidence_report(id);

            assert!(
                report
                    .outcome_counts
                    .spawn_allowed_without_host_dependencies
                    <= report
                        .outcome_counts
                        .spawn_allowed_with_declared_dependencies,
                "{} cannot allow fewer scenarios when declared dependencies are present",
                report.backend
            );
        }
    }
}
