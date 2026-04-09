// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Credential placeholder resolution and injection.
//!
//! Rewrites HTTP request headers to inject real credentials from environment
//! variables or a secure store. The sandbox process never sees the actual
//! credential values — it uses placeholders like `axis:resolve:env:API_KEY`.

use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("unresolved placeholder: {0}")]
    Unresolved(String),

    #[error("environment variable not found: {0}")]
    EnvNotFound(String),
}

/// Resolves credential placeholders in HTTP headers.
pub struct SecretResolver {
    /// Static secret mappings (name → value).
    secrets: HashMap<String, String>,
}

impl SecretResolver {
    pub fn new() -> Self {
        Self {
            secrets: HashMap::new(),
        }
    }

    /// Add a static secret.
    pub fn add_secret(&mut self, name: String, value: String) {
        self.secrets.insert(name, value);
    }

    /// Resolve a placeholder string.
    ///
    /// Supported formats:
    /// - `axis:resolve:env:VAR_NAME` — resolve from environment variable
    /// - `axis:resolve:secret:NAME` — resolve from static secret store
    pub fn resolve(&self, placeholder: &str) -> Result<String, SecretError> {
        if let Some(var_name) = placeholder.strip_prefix("axis:resolve:env:") {
            std::env::var(var_name).map_err(|_| SecretError::EnvNotFound(var_name.into()))
        } else if let Some(secret_name) = placeholder.strip_prefix("axis:resolve:secret:") {
            self.secrets
                .get(secret_name)
                .cloned()
                .ok_or_else(|| SecretError::Unresolved(secret_name.into()))
        } else {
            // Not a placeholder — return as-is.
            Ok(placeholder.to_string())
        }
    }

    /// Scan a header value for placeholders and resolve them.
    pub fn resolve_header_value(&self, value: &str) -> Result<String, SecretError> {
        if value.starts_with("axis:resolve:") {
            self.resolve(value)
        } else {
            Ok(value.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_env_placeholder() {
        // Set a test env var.
        unsafe { std::env::set_var("AXIS_TEST_KEY", "test-value-12345"); }
        let resolver = SecretResolver::new();
        let val = resolver.resolve("axis:resolve:env:AXIS_TEST_KEY").unwrap();
        assert_eq!(val, "test-value-12345");
        unsafe { std::env::remove_var("AXIS_TEST_KEY"); }
    }

    #[test]
    fn resolve_static_secret() {
        let mut resolver = SecretResolver::new();
        resolver.add_secret("my-api-key".into(), "secret-value".into());
        let val = resolver.resolve("axis:resolve:secret:my-api-key").unwrap();
        assert_eq!(val, "secret-value");
    }

    #[test]
    fn passthrough_non_placeholder() {
        let resolver = SecretResolver::new();
        let val = resolver.resolve("just-a-normal-value").unwrap();
        assert_eq!(val, "just-a-normal-value");
    }

    #[test]
    fn error_on_missing_env() {
        let resolver = SecretResolver::new();
        let err = resolver.resolve("axis:resolve:env:NONEXISTENT_VAR_12345").unwrap_err();
        assert!(matches!(err, SecretError::EnvNotFound(_)));
    }
}
