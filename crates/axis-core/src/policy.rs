// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! YAML policy schema parsing and validation.
//!
//! The policy model mirrors the AXIS YAML policy schema described in the
//! implementation plan. Policies govern filesystem access, process limits,
//! network connectivity, inference routing, and AMD-specific features.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to parse policy YAML: {0}")]
    ParseError(#[from] serde_yaml::Error),

    #[error("policy validation failed: {0}")]
    ValidationError(String),

    #[error("unsupported policy version: {0}")]
    UnsupportedVersion(u32),
}

/// Top-level AXIS policy document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub version: u32,
    pub name: String,

    #[serde(default)]
    pub filesystem: FilesystemPolicy,

    #[serde(default)]
    pub process: ProcessPolicy,

    #[serde(default)]
    pub network: NetworkPolicy,

    #[serde(default)]
    pub inference: InferencePolicy,

    #[serde(default)]
    pub gpu: GpuPolicy,

    #[serde(default)]
    pub amd: Option<AmdPolicy>,
}

impl Policy {
    /// Parse a policy from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, PolicyError> {
        let policy: Self = serde_yaml::from_str(yaml)?;
        policy.validate()?;
        Ok(policy)
    }

    /// Parse a policy from a YAML file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, PolicyError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| PolicyError::ValidationError(format!("cannot read {}: {e}", path.display())))?;
        Self::from_yaml(&contents)
    }

    /// Validate policy constraints.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.version != 1 {
            return Err(PolicyError::UnsupportedVersion(self.version));
        }
        if self.name.is_empty() {
            return Err(PolicyError::ValidationError("policy name must not be empty".into()));
        }
        self.process.validate()?;
        self.network.validate()?;
        Ok(())
    }
}

/// Filesystem access policy — controls what paths the sandboxed process can read/write.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    #[serde(default)]
    pub read_only: Vec<String>,

    #[serde(default)]
    pub read_write: Vec<String>,

    #[serde(default)]
    pub deny: Vec<String>,

    #[serde(default = "default_compatibility")]
    pub compatibility: Compatibility,
}

fn default_compatibility() -> Compatibility {
    Compatibility::BestEffort
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Compatibility {
    #[default]
    BestEffort,
    HardRequirement,
}

/// Process containment policy — limits on the sandboxed process tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessPolicy {
    #[serde(default = "default_max_processes")]
    pub max_processes: u32,

    #[serde(default = "default_max_memory_mb")]
    pub max_memory_mb: u64,

    #[serde(default = "default_cpu_rate")]
    pub cpu_rate_percent: u32,

    #[serde(default)]
    pub run_as_user: Option<String>,

    #[serde(default)]
    pub blocked_syscalls: Vec<String>,

    /// Maximum wall-clock time in seconds before auto-destroy. None = no timeout.
    #[serde(default)]
    pub timeout_sec: Option<u64>,
}

impl Default for ProcessPolicy {
    fn default() -> Self {
        Self {
            max_processes: default_max_processes(),
            max_memory_mb: default_max_memory_mb(),
            cpu_rate_percent: default_cpu_rate(),
            run_as_user: None,
            blocked_syscalls: Vec::new(),
            timeout_sec: None,
        }
    }
}

impl ProcessPolicy {
    fn validate(&self) -> Result<(), PolicyError> {
        if self.cpu_rate_percent == 0 || self.cpu_rate_percent > 100 {
            return Err(PolicyError::ValidationError(format!(
                "cpu_rate_percent must be 1..=100, got {}",
                self.cpu_rate_percent
            )));
        }
        if self.max_processes == 0 {
            return Err(PolicyError::ValidationError("max_processes must be > 0".into()));
        }
        Ok(())
    }
}

fn default_max_processes() -> u32 {
    32
}
fn default_max_memory_mb() -> u64 {
    8192
}
fn default_cpu_rate() -> u32 {
    80
}

/// Network connectivity policy — controls how the sandbox reaches the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    #[serde(default = "default_network_mode")]
    pub mode: NetworkMode,

    #[serde(default)]
    pub policies: Vec<EndpointPolicy>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            mode: default_network_mode(),
            policies: Vec::new(),
        }
    }
}

impl NetworkPolicy {
    fn validate(&self) -> Result<(), PolicyError> {
        for ep in &self.policies {
            if ep.name.is_empty() {
                return Err(PolicyError::ValidationError(
                    "network policy entries must have a name".into(),
                ));
            }
            if ep.endpoints.is_empty() {
                return Err(PolicyError::ValidationError(format!(
                    "network policy '{}' has no endpoints",
                    ep.name
                )));
            }
        }
        Ok(())
    }
}

fn default_network_mode() -> NetworkMode {
    NetworkMode::Proxy
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    #[default]
    Proxy,
    Block,
    Allow,
}

/// A named group of endpoint rules with optional binary restrictions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointPolicy {
    pub name: String,
    pub endpoints: Vec<Endpoint>,

    #[serde(default)]
    pub binaries: Vec<BinaryMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,

    #[serde(default = "default_access")]
    pub access: Access,

    #[serde(default)]
    pub protocol: Option<String>,

    #[serde(default)]
    pub rules: Vec<L7Rule>,
}

fn default_access() -> Access {
    Access::ReadOnly
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Access {
    #[default]
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L7Rule {
    pub allow: Option<L7Allow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L7Allow {
    pub method: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryMatch {
    pub path: String,
}

/// Inference routing policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InferencePolicy {
    #[serde(default)]
    pub default_provider: Option<String>,

    #[serde(default)]
    pub routes: Vec<InferenceRoute>,

    #[serde(default)]
    pub scheduling: Option<SchedulingPolicy>,

    #[serde(default)]
    pub token_budget: Option<TokenBudget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceRoute {
    pub name: String,

    #[serde(default)]
    pub endpoint: Option<String>,

    #[serde(default)]
    pub provider: Option<String>,

    #[serde(default)]
    pub model: Option<String>,

    #[serde(default)]
    pub api_key_env: Option<String>,

    #[serde(default)]
    pub protocols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulingPolicy {
    #[serde(default = "default_weight")]
    pub weight: u32,

    #[serde(default = "default_priority")]
    pub priority: Priority,

    #[serde(default)]
    pub max_concurrent_requests: Option<u32>,
}

fn default_weight() -> u32 {
    1
}
fn default_priority() -> Priority {
    Priority::Background
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Interactive,
    #[default]
    Background,
    Batch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBudget {
    pub max_tokens_per_hour: u64,

    #[serde(default = "default_max_tokens_per_request")]
    pub max_tokens_per_request: u64,

    #[serde(default = "default_exhaust_action")]
    pub action_on_exhaust: ExhaustAction,

    #[serde(default)]
    pub fallback_route: Option<String>,
}

fn default_max_tokens_per_request() -> u64 {
    32768
}

fn default_exhaust_action() -> ExhaustAction {
    ExhaustAction::Reject
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExhaustAction {
    Queue,
    #[default]
    Reject,
    FallbackCloud,
}

/// AMD hardware-specific policy extensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmdPolicy {
    #[serde(default)]
    pub gpu_passthrough: bool,

    #[serde(default)]
    pub npu_policy_offload: bool,

    #[serde(default)]
    pub apex_memory_policy: Option<ApexMemoryPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApexMemoryPolicy {
    #[serde(default)]
    pub allow_overcommit: bool,

    #[serde(default)]
    pub max_vram_mb: Option<u64>,
}

/// GPU isolation policy — controls HIP Remote para-virtual GPU access.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GpuPolicy {
    /// Enable GPU access for this sandbox.
    #[serde(default)]
    pub enabled: bool,

    /// Physical GPU device ordinal (default: 0).
    #[serde(default)]
    pub device: u32,

    /// Transport for HIP Remote: "uds" (Unix domain socket) or "tcp".
    #[serde(default = "default_gpu_transport")]
    pub transport: GpuTransport,

    /// Maximum GPU memory allocation in MB. None = unlimited.
    #[serde(default)]
    pub vram_limit_mb: Option<u64>,

    /// Maximum wall-clock time per kernel launch in seconds. None = unlimited.
    #[serde(default)]
    pub compute_timeout_sec: Option<u64>,

    /// Allowed API categories. Empty = default set (all except IPC/context).
    #[serde(default)]
    pub allowed_apis: Vec<String>,

    /// Denied API categories. Explicit denials override allowed.
    #[serde(default)]
    pub denied_apis: Vec<String>,
}

fn default_gpu_transport() -> GpuTransport {
    GpuTransport::Uds
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GpuTransport {
    #[default]
    Uds,
    Tcp,
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_POLICY: &str = r#"
version: 1
name: test-sandbox
"#;

    const FULL_POLICY: &str = r#"
version: 1
name: coding-agent-sandbox

filesystem:
  read_only:
    - /usr
    - /lib
    - /etc/ssl/certs
  read_write:
    - "{workspace}"
    - "{tmpdir}"
  deny:
    - "~/.ssh"
    - "~/.gnupg"

process:
  max_processes: 32
  max_memory_mb: 8192
  cpu_rate_percent: 80
  blocked_syscalls:
    - ptrace
    - mount
    - bpf

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

inference:
  default_provider: local-rocm
  routes:
    - name: local-rocm
      endpoint: "http://localhost:8080"
      protocols: [openai_chat_completions]
      model: "llama-4-scout-109b"
    - name: cloud-fallback
      provider: anthropic
      model: "claude-sonnet-4-20250514"
      api_key_env: ANTHROPIC_API_KEY
  token_budget:
    max_tokens_per_hour: 500000
    max_tokens_per_request: 32768
    action_on_exhaust: fallback_cloud
    fallback_route: cloud-fallback

amd:
  gpu_passthrough: true
  npu_policy_offload: false
  apex_memory_policy:
    allow_overcommit: true
    max_vram_mb: 16384
"#;

    #[test]
    fn parse_minimal_policy() {
        let policy = Policy::from_yaml(MINIMAL_POLICY).unwrap();
        assert_eq!(policy.version, 1);
        assert_eq!(policy.name, "test-sandbox");
        assert_eq!(policy.process.max_processes, 32);
        assert_eq!(policy.process.cpu_rate_percent, 80);
    }

    #[test]
    fn parse_full_policy() {
        let policy = Policy::from_yaml(FULL_POLICY).unwrap();
        assert_eq!(policy.name, "coding-agent-sandbox");
        assert_eq!(policy.filesystem.read_only.len(), 3);
        assert_eq!(policy.filesystem.deny.len(), 2);
        assert_eq!(policy.network.policies.len(), 1);
        assert_eq!(policy.network.policies[0].name, "github-api");
        assert_eq!(policy.inference.routes.len(), 2);

        let budget = policy.inference.token_budget.as_ref().unwrap();
        assert_eq!(budget.max_tokens_per_hour, 500_000);
        assert!(matches!(budget.action_on_exhaust, ExhaustAction::FallbackCloud));

        let amd = policy.amd.as_ref().unwrap();
        assert!(amd.gpu_passthrough);
        assert!(!amd.npu_policy_offload);
        assert_eq!(amd.apex_memory_policy.as_ref().unwrap().max_vram_mb, Some(16384));
    }

    #[test]
    fn reject_invalid_version() {
        let yaml = "version: 99\nname: bad\n";
        let err = Policy::from_yaml(yaml).unwrap_err();
        assert!(matches!(err, PolicyError::UnsupportedVersion(99)));
    }

    #[test]
    fn reject_empty_name() {
        let yaml = "version: 1\nname: \"\"\n";
        let err = Policy::from_yaml(yaml).unwrap_err();
        assert!(matches!(err, PolicyError::ValidationError(_)));
    }

    #[test]
    fn reject_invalid_cpu_rate() {
        let yaml = "version: 1\nname: test\nprocess:\n  cpu_rate_percent: 0\n";
        let err = Policy::from_yaml(yaml).unwrap_err();
        assert!(matches!(err, PolicyError::ValidationError(_)));
    }
}
