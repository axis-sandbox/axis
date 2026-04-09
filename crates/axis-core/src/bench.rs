// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Benchmark helpers for policy evaluation throughput.

use crate::opa::PolicyEngine;
use crate::policy::Policy;
use crate::types::{NetworkAction, SandboxId};

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
    let mut engine = PolicyEngine::new().unwrap();
    engine.load_policy(&policy).unwrap();

    let sandbox_id = SandboxId::new();

    // Warm up.
    for _ in 0..100 {
        let action = NetworkAction {
            host: "api.example.com".into(),
            port: 443,
            binary_path: "/usr/bin/curl".into(),
            binary_sha256: "abc".into(),
            sandbox_id,
        };
        let _ = engine.eval_network(&action);
    }

    // Benchmark: alternate between allow and deny cases.
    let start = std::time::Instant::now();
    for i in 0..n {
        let host = if i % 2 == 0 {
            "api.example.com"
        } else {
            "evil.example.com"
        };
        let action = NetworkAction {
            host: host.into(),
            port: 443,
            binary_path: "/usr/bin/curl".into(),
            binary_sha256: "abc".into(),
            sandbox_id,
        };
        let _ = engine.eval_network(&action);
    }
    let elapsed = start.elapsed();

    let total_ns = elapsed.as_nanos() as u64;
    let per_sec = n as f64 / elapsed.as_secs_f64();
    (total_ns, per_sec)
}
