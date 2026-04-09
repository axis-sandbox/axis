// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! OCSF-structured audit event emitter.
//!
//! Events follow the Open Cybersecurity Schema Framework for structured
//! security telemetry. Each event is self-contained and can be emitted
//! to file, syslog, or a structured log sink.

use crate::types::{PolicyDecision, SandboxId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// OCSF activity categories used by AXIS.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    SandboxLifecycle,
    NetworkActivity,
    PolicyDecision,
    InferenceActivity,
    SecurityFinding,
}

/// Severity levels for audit events.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// A structured OCSF audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub category: EventCategory,
    pub severity: Severity,
    pub sandbox_id: Option<SandboxId>,
    pub message: String,
    pub details: serde_json::Value,
}

impl AuditEvent {
    pub fn new(
        category: EventCategory,
        severity: Severity,
        sandbox_id: Option<SandboxId>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            category,
            severity,
            sandbox_id,
            message: message.into(),
            details: serde_json::Value::Null,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }
}

/// Emits audit events to configured sinks.
pub struct AuditLog {
    sinks: Vec<Box<dyn AuditSink>>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self { sinks: Vec::new() }
    }

    pub fn add_sink(&mut self, sink: Box<dyn AuditSink>) {
        self.sinks.push(sink);
    }

    pub fn emit(&self, event: &AuditEvent) {
        for sink in &self.sinks {
            if let Err(e) = sink.write(event) {
                tracing::error!("audit sink error: {e}");
            }
        }
    }

    // Convenience constructors for common events.

    pub fn sandbox_created(&self, sandbox_id: SandboxId, policy_name: &str) {
        self.emit(&AuditEvent::new(
            EventCategory::SandboxLifecycle,
            Severity::Info,
            Some(sandbox_id),
            format!("sandbox created with policy '{policy_name}'"),
        ));
    }

    pub fn sandbox_destroyed(&self, sandbox_id: SandboxId) {
        self.emit(&AuditEvent::new(
            EventCategory::SandboxLifecycle,
            Severity::Info,
            Some(sandbox_id),
            "sandbox destroyed",
        ));
    }

    pub fn network_decision(
        &self,
        sandbox_id: SandboxId,
        host: &str,
        port: u16,
        decision: &PolicyDecision,
    ) {
        let severity = if decision.allowed {
            Severity::Info
        } else {
            Severity::Medium
        };
        let action = if decision.allowed { "allowed" } else { "denied" };
        self.emit(
            &AuditEvent::new(
                EventCategory::NetworkActivity,
                severity,
                Some(sandbox_id),
                format!("network connection to {host}:{port} {action}"),
            )
            .with_details(serde_json::to_value(decision).unwrap_or_default()),
        );
    }

    pub fn credential_leak_detected(&self, sandbox_id: SandboxId, pattern: &str) {
        self.emit(&AuditEvent::new(
            EventCategory::SecurityFinding,
            Severity::High,
            Some(sandbox_id),
            format!("credential leak detected: {pattern}"),
        ));
    }
}

/// Trait for audit event output sinks.
pub trait AuditSink: Send + Sync {
    fn write(&self, event: &AuditEvent) -> Result<(), Box<dyn std::error::Error>>;
}

/// Writes audit events as JSON lines to a tracing span.
pub struct TracingSink;

impl AuditSink for TracingSink {
    fn write(&self, event: &AuditEvent) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(event)?;
        tracing::info!(target: "axis::audit", "{json}");
        Ok(())
    }
}

/// Writes audit events as JSON lines to a file.
pub struct FileSink {
    path: std::path::PathBuf,
}

impl FileSink {
    pub fn new(path: std::path::PathBuf) -> Self {
        Self { path }
    }
}

impl AuditSink for FileSink {
    fn write(&self, event: &AuditEvent) -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let json = serde_json::to_string(event)?;
        writeln!(file, "{json}")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_serialize_event() {
        let event = AuditEvent::new(
            EventCategory::SandboxLifecycle,
            Severity::Info,
            Some(SandboxId::new()),
            "test event",
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("test event"));
        assert!(json.contains("sandbox_lifecycle"));
    }

    #[test]
    fn audit_log_with_tracing_sink() {
        let mut log = AuditLog::new();
        log.add_sink(Box::new(TracingSink));
        log.sandbox_created(SandboxId::new(), "test-policy");
        // No panic = success (tracing subscriber not installed in test, that's fine)
    }
}
