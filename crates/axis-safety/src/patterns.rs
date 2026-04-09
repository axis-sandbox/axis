// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Known credential patterns for leak detection.
//!
//! Patterns cover common API key formats, PEM keys, bearer tokens, and
//! other secret material that should never leave a sandbox.

use regex::Regex;

/// A named credential pattern with a regex and description.
pub struct CredentialPattern {
    pub name: &'static str,
    pub regex: Regex,
    pub description: &'static str,
}

/// Build the default set of credential patterns.
pub fn default_patterns() -> Vec<CredentialPattern> {
    vec![
        CredentialPattern {
            name: "openai_api_key",
            regex: Regex::new(r"sk-[A-Za-z0-9_-]{20,}").unwrap(),
            description: "OpenAI API key",
        },
        CredentialPattern {
            name: "anthropic_api_key",
            regex: Regex::new(r"sk-ant-[A-Za-z0-9_-]{20,}").unwrap(),
            description: "Anthropic API key",
        },
        CredentialPattern {
            name: "aws_access_key",
            regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            description: "AWS access key ID",
        },
        CredentialPattern {
            name: "aws_secret_key",
            regex: Regex::new(r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}").unwrap(),
            description: "AWS secret access key",
        },
        CredentialPattern {
            name: "github_pat",
            regex: Regex::new(r"ghp_[A-Za-z0-9]{36,}").unwrap(),
            description: "GitHub personal access token",
        },
        CredentialPattern {
            name: "github_fine_grained",
            regex: Regex::new(r"github_pat_[A-Za-z0-9_]{22,}").unwrap(),
            description: "GitHub fine-grained PAT",
        },
        CredentialPattern {
            name: "slack_token",
            regex: Regex::new(r"xox[bpras]-[0-9A-Za-z-]{10,}").unwrap(),
            description: "Slack API token",
        },
        CredentialPattern {
            name: "stripe_key",
            regex: Regex::new(r"sk_(?:live|test)_[A-Za-z0-9]{24,}").unwrap(),
            description: "Stripe secret key",
        },
        CredentialPattern {
            name: "pem_private_key",
            regex: Regex::new(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----").unwrap(),
            description: "PEM-encoded private key",
        },
        CredentialPattern {
            name: "bearer_token",
            regex: Regex::new(r"(?i)bearer\s+[A-Za-z0-9_.~+/=-]{20,}").unwrap(),
            description: "Bearer authentication token",
        },
        CredentialPattern {
            name: "generic_api_key_header",
            regex: Regex::new(r"(?i)(?:x-api-key|api[_-]?key)\s*[=:]\s*[A-Za-z0-9_-]{16,}").unwrap(),
            description: "Generic API key in header/config",
        },
    ]
}
