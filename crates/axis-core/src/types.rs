// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Core types shared across AXIS crates.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a sandbox instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SandboxId(pub Uuid);

impl SandboxId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl std::fmt::Display for SandboxId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Status of a sandbox instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxStatus {
    Creating,
    Running,
    Stopping,
    Stopped,
    Failed,
}

/// A network action being evaluated by the policy engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAction {
    pub host: String,
    pub port: u16,
    pub binary_path: String,
    pub binary_sha256: String,
    pub sandbox_id: SandboxId,
}

/// Result of a policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub matched_policy: Option<String>,
    pub reason: Option<String>,
}

/// An HTTP request being evaluated for L7 policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpAction {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub matched_network_policy: String,
}

/// An inference request being routed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceAction {
    pub protocol: String,
    pub model: String,
    pub route_name: Option<String>,
    pub sandbox_id: SandboxId,
}
