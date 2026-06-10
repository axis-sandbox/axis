// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Benchmark helpers for policy evaluation throughput.

use crate::opa::PolicyEngine;
use crate::policy::Policy;
use crate::types::{NetworkAction, SandboxId};
use serde::Serialize;

/// One network policy evaluation case used by OPA throughput benchmarks.
#[derive(Debug, Clone)]
pub struct NetworkEvalCase {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub binary_path: String,
    pub binary_sha256: String,
    pub expected_allowed: bool,
}

/// Summary for a network policy evaluation benchmark.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NetworkEvalBenchSummary {
    pub iterations: u64,
    pub case_count: usize,
    pub total_ns: u64,
    pub evals_per_sec: f64,
    pub ns_per_eval: f64,
    pub allowed_decisions: u64,
    pub denied_decisions: u64,
}

/// Run N network policy evaluations for an already parsed policy and a fixed
/// case set. Every evaluated decision is checked against the case expectation.
pub fn bench_network_eval_cases(
    policy: &Policy,
    cases: &[NetworkEvalCase],
    n: u64,
) -> Result<NetworkEvalBenchSummary, String> {
    if n == 0 {
        return Err("benchmark iteration count must be greater than zero".into());
    }
    if cases.is_empty() {
        return Err("benchmark case set must not be empty".into());
    }

    let mut engine = PolicyEngine::new().map_err(|err| err.to_string())?;
    engine.load_policy(policy).map_err(|err| err.to_string())?;
    let sandbox_id = SandboxId::new();

    for case in cases {
        let action = network_action_for_case(case, sandbox_id);
        let decision = engine
            .eval_network(&action)
            .map_err(|err| format!("warmup case '{}' failed: {err}", case.name))?;
        if decision.allowed != case.expected_allowed {
            return Err(format!(
                "warmup case '{}' expected allowed={}, got allowed={} ({:?})",
                case.name, case.expected_allowed, decision.allowed, decision
            ));
        }
    }

    let mut allowed_decisions = 0;
    let mut denied_decisions = 0;
    let start = std::time::Instant::now();
    for index in 0..n {
        let case = &cases[index as usize % cases.len()];
        let action = network_action_for_case(case, sandbox_id);
        let decision = engine
            .eval_network(&action)
            .map_err(|err| format!("case '{}' failed: {err}", case.name))?;
        if decision.allowed != case.expected_allowed {
            return Err(format!(
                "case '{}' expected allowed={}, got allowed={} ({:?})",
                case.name, case.expected_allowed, decision.allowed, decision
            ));
        }
        if decision.allowed {
            allowed_decisions += 1;
        } else {
            denied_decisions += 1;
        }
    }
    let elapsed = start.elapsed();

    let total_ns = elapsed.as_nanos() as u64;
    let evals_per_sec = n as f64 / elapsed.as_secs_f64();
    let ns_per_eval = total_ns as f64 / n as f64;
    Ok(NetworkEvalBenchSummary {
        iterations: n,
        case_count: cases.len(),
        total_ns,
        evals_per_sec,
        ns_per_eval,
        allowed_decisions,
        denied_decisions,
    })
}

/// Run N network policy evaluations and return (total_ns, evals_per_sec).
pub fn bench_network_eval(n: u64) -> (u64, f64) {
    let policy_yaml = r#"
version: 1
name: bench-policy
network:
  mode: proxy
  policies:
    - name: api-1
      endpoints:
        - host: "api.example.com"
          port: 443
    - name: api-2
      endpoints:
        - host: "data.example.com"
          port: 443
    - name: api-3
      endpoints:
        - host: "auth.example.com"
          port: 443
"#;
    let policy = Policy::from_yaml(policy_yaml).unwrap();
    let cases = vec![
        NetworkEvalCase {
            name: "allowed-api".into(),
            host: "api.example.com".into(),
            port: 443,
            binary_path: "/usr/bin/curl".into(),
            binary_sha256: "abc".into(),
            expected_allowed: true,
        },
        NetworkEvalCase {
            name: "denied-host".into(),
            host: "evil.example.com".into(),
            port: 443,
            binary_path: "/usr/bin/curl".into(),
            binary_sha256: "abc".into(),
            expected_allowed: false,
        },
    ];
    let summary = bench_network_eval_cases(&policy, &cases, n).unwrap();
    (summary.total_ns, summary.evals_per_sec)
}

fn network_action_for_case(case: &NetworkEvalCase, sandbox_id: SandboxId) -> NetworkAction {
    NetworkAction {
        host: case.host.clone(),
        port: case.port,
        binary_path: case.binary_path.clone(),
        binary_sha256: case.binary_sha256.clone(),
        sandbox_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_eval_case_benchmark_counts_allow_and_deny() {
        let policy = Policy::from_yaml(
            r#"
version: 1
name: bench-case-test
network:
  mode: proxy
  policies:
    - name: api
      endpoints:
        - host: "api.example.com"
          port: 443
"#,
        )
        .unwrap();
        let summary = bench_network_eval_cases(
            &policy,
            &[
                NetworkEvalCase {
                    name: "allow".into(),
                    host: "api.example.com".into(),
                    port: 443,
                    binary_path: "/usr/bin/curl".into(),
                    binary_sha256: "abc".into(),
                    expected_allowed: true,
                },
                NetworkEvalCase {
                    name: "deny".into(),
                    host: "evil.example.com".into(),
                    port: 443,
                    binary_path: "/usr/bin/curl".into(),
                    binary_sha256: "abc".into(),
                    expected_allowed: false,
                },
            ],
            10,
        )
        .unwrap();

        assert_eq!(summary.iterations, 10);
        assert_eq!(summary.case_count, 2);
        assert_eq!(summary.allowed_decisions, 5);
        assert_eq!(summary.denied_decisions, 5);
        assert!(summary.evals_per_sec > 0.0);
        assert!(summary.ns_per_eval > 0.0);
    }

    #[test]
    fn network_eval_case_benchmark_rejects_unexpected_decision() {
        let policy = Policy::from_yaml(
            r#"
version: 1
name: bench-case-test
network:
  mode: proxy
  policies:
    - name: api
      endpoints:
        - host: "api.example.com"
          port: 443
"#,
        )
        .unwrap();
        let err = bench_network_eval_cases(
            &policy,
            &[NetworkEvalCase {
                name: "mismatch".into(),
                host: "api.example.com".into(),
                port: 443,
                binary_path: "/usr/bin/curl".into(),
                binary_sha256: "abc".into(),
                expected_allowed: false,
            }],
            1,
        )
        .unwrap_err();

        assert!(err.contains("mismatch"));
        assert!(err.contains("expected allowed=false"));
    }
}
