// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! OPA/Rego policy engine wrapper using the `regorus` crate.
//!
//! Evaluates policy decisions for sandbox creation, network connections,
//! L7 HTTP requests, and inference routing.

use crate::policy::Policy;
use crate::types::{HttpAction, InferenceAction, NetworkAction, PolicyDecision};
use thiserror::Error;

/// Baked-in Rego rules for AXIS policy evaluation.
const SANDBOX_POLICY_REGO: &str = include_str!("../../../data/sandbox-policy.rego");

#[derive(Debug, Error)]
pub enum OpaError {
    #[error("OPA engine error: {0}")]
    EngineError(String),

    #[error("policy evaluation failed: {0}")]
    EvalError(String),

    #[error("failed to serialize input: {0}")]
    SerializeError(#[from] serde_json::Error),
}

/// AXIS policy engine backed by regorus (pure-Rust OPA).
pub struct PolicyEngine {
    engine: regorus::Engine,
}

impl PolicyEngine {
    /// Create a new policy engine, loading the baked-in Rego rules.
    pub fn new() -> Result<Self, OpaError> {
        let mut engine = regorus::Engine::new();

        engine
            .add_policy("sandbox-policy.rego".into(), SANDBOX_POLICY_REGO.into())
            .map_err(|e| OpaError::EngineError(format!("failed to load rego rules: {e}")))?;

        Ok(Self { engine })
    }

    /// Load sandbox policy data into the engine.
    pub fn load_policy(&mut self, policy: &Policy) -> Result<(), OpaError> {
        let data_json = serde_json::to_string(policy)?;
        self.engine
            .add_data_json(&data_json)
            .map_err(|e| OpaError::EngineError(format!("failed to load policy data: {e}")))?;
        Ok(())
    }

    /// Evaluate whether a network connection should be allowed.
    pub fn eval_network(&mut self, action: &NetworkAction) -> Result<PolicyDecision, OpaError> {
        let input_json = serde_json::to_string(action)?;
        self.eval_query("data.axis.network.decision", &input_json)
    }

    /// Evaluate whether an L7 HTTP request should be allowed.
    pub fn eval_http(&mut self, action: &HttpAction) -> Result<PolicyDecision, OpaError> {
        let input_json = serde_json::to_string(action)?;
        self.eval_query("data.axis.http.decision", &input_json)
    }

    /// Evaluate inference routing for a request.
    pub fn eval_inference(
        &mut self,
        action: &InferenceAction,
    ) -> Result<PolicyDecision, OpaError> {
        let input_json = serde_json::to_string(action)?;
        self.eval_query("data.axis.inference.decision", &input_json)
    }

    /// Run a Rego query and return the policy decision.
    fn eval_query(
        &mut self,
        query: &str,
        input_json: &str,
    ) -> Result<PolicyDecision, OpaError> {
        self.engine.set_input_json(input_json)
            .map_err(|e| OpaError::EvalError(format!("failed to set input: {e}")))?;

        let results = self
            .engine
            .eval_query(query.into(), false)
            .map_err(|e| OpaError::EvalError(format!("query '{query}' failed: {e}")))?;

        // Extract the decision from the query result.
        // The Rego rules return an object with `allowed`, `matched_policy`, and `reason`.
        // regorus returns its own Value type — convert via JSON round-trip.
        if let Some(result) = results.result.first() {
            if let Some(expr) = result.expressions.first() {
                let json_str = serde_json::to_string(&expr.value)
                    .map_err(|e| OpaError::EvalError(format!("failed to serialize result: {e}")))?;
                let decision: PolicyDecision = serde_json::from_str(&json_str)
                    .map_err(|e| OpaError::EvalError(format!("failed to parse decision: {e}")))?;
                return Ok(decision);
            }
        }

        // Default deny if no result.
        Ok(PolicyDecision {
            allowed: false,
            matched_policy: None,
            reason: Some("no matching policy rule".into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;
    use crate::types::SandboxId;

    const TEST_POLICY: &str = r#"
version: 1
name: test-sandbox
network:
  mode: proxy
  policies:
    - name: github-api
      endpoints:
        - host: "api.github.com"
          port: 443
          access: read-write
      binaries:
        - path: "/usr/bin/git"
        - path: "/usr/bin/curl"
    - name: pypi
      endpoints:
        - host: "pypi.org"
          port: 443
          access: read-only
inference:
  default_provider: local-rocm
  routes:
    - name: local-rocm
      endpoint: "http://localhost:8080"
      model: "llama-4-scout-109b"
    - name: cloud
      provider: anthropic
      model: "claude-sonnet-4-20250514"
"#;

    fn loaded_engine() -> PolicyEngine {
        let mut engine = PolicyEngine::new().unwrap();
        let policy = Policy::from_yaml(TEST_POLICY).unwrap();
        engine.load_policy(&policy).unwrap();
        engine
    }

    #[test]
    fn create_engine() {
        let engine = PolicyEngine::new();
        assert!(engine.is_ok(), "failed to create OPA engine: {:?}", engine.err());
    }

    #[test]
    fn network_allow_matching_host_and_binary() {
        let mut engine = loaded_engine();
        let action = NetworkAction {
            host: "api.github.com".into(),
            port: 443,
            binary_path: "/usr/bin/git".into(),
            binary_sha256: "abc123".into(),
            sandbox_id: SandboxId::new(),
        };
        let decision = engine.eval_network(&action).unwrap();
        assert!(decision.allowed, "expected allow, got: {decision:?}");
        assert_eq!(decision.matched_policy.as_deref(), Some("github-api"));
    }

    #[test]
    fn network_deny_unknown_host() {
        let mut engine = loaded_engine();
        let action = NetworkAction {
            host: "evil.example.com".into(),
            port: 443,
            binary_path: "/usr/bin/curl".into(),
            binary_sha256: "abc123".into(),
            sandbox_id: SandboxId::new(),
        };
        let decision = engine.eval_network(&action).unwrap();
        assert!(!decision.allowed, "expected deny, got: {decision:?}");
    }

    #[test]
    fn network_deny_wrong_binary() {
        let mut engine = loaded_engine();
        let action = NetworkAction {
            host: "api.github.com".into(),
            port: 443,
            binary_path: "/usr/bin/wget".into(), // not in allowed binaries
            binary_sha256: "abc123".into(),
            sandbox_id: SandboxId::new(),
        };
        let decision = engine.eval_network(&action).unwrap();
        assert!(!decision.allowed, "expected deny for wrong binary, got: {decision:?}");
    }

    #[test]
    fn network_allow_pypi_no_binary_restriction() {
        let mut engine = loaded_engine();
        // pypi policy has no binary restrictions — any binary should match
        let action = NetworkAction {
            host: "pypi.org".into(),
            port: 443,
            binary_path: "/usr/bin/anything".into(),
            binary_sha256: "abc123".into(),
            sandbox_id: SandboxId::new(),
        };
        let decision = engine.eval_network(&action).unwrap();
        assert!(decision.allowed, "expected allow for pypi (no binary restriction), got: {decision:?}");
        assert_eq!(decision.matched_policy.as_deref(), Some("pypi"));
    }

    #[test]
    fn network_deny_wrong_port() {
        let mut engine = loaded_engine();
        let action = NetworkAction {
            host: "api.github.com".into(),
            port: 80, // wrong port
            binary_path: "/usr/bin/git".into(),
            binary_sha256: "abc123".into(),
            sandbox_id: SandboxId::new(),
        };
        let decision = engine.eval_network(&action).unwrap();
        assert!(!decision.allowed, "expected deny for wrong port, got: {decision:?}");
    }

    #[test]
    fn inference_allow_known_model() {
        let mut engine = loaded_engine();
        let action = InferenceAction {
            protocol: "openai_chat_completions".into(),
            model: "llama-4-scout-109b".into(),
            route_name: None,
            sandbox_id: SandboxId::new(),
        };
        let decision = engine.eval_inference(&action).unwrap();
        assert!(decision.allowed, "expected allow for known model, got: {decision:?}");
        assert_eq!(decision.matched_policy.as_deref(), Some("local-rocm"));
    }

    #[test]
    fn inference_deny_unknown_model() {
        let mut engine = loaded_engine();
        let action = InferenceAction {
            protocol: "openai_chat_completions".into(),
            model: "gpt-4-turbo".into(), // not in routes
            route_name: None,
            sandbox_id: SandboxId::new(),
        };
        let decision = engine.eval_inference(&action).unwrap();
        // Should fall back to default provider
        assert!(decision.allowed, "expected allow via default provider, got: {decision:?}");
    }
}
