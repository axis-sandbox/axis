// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Credential leak detection using Aho-Corasick fast prefix matching + regex.
//!
//! Scans request and response bodies for known credential patterns.
//! Two-phase: fast prefix scan with Aho-Corasick, then regex confirmation.

use crate::patterns::{default_patterns, CredentialPattern};
use aho_corasick::AhoCorasick;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LeakDetectError {
    #[error("failed to build pattern matcher: {0}")]
    BuildError(String),
}

/// Action to take when a credential leak is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeakAction {
    Block,
    Redact,
    Warn,
}

/// A detected credential leak.
#[derive(Debug, Clone)]
pub struct LeakFinding {
    pub pattern_name: &'static str,
    pub description: &'static str,
    pub byte_offset: usize,
    pub matched_text: String,
}

/// Fast credential leak detector.
///
/// Uses Aho-Corasick for fast prefix scanning, then confirms with full regex.
pub struct LeakDetector {
    /// Fast prefix scanner — matches short prefixes of known credential formats.
    prefix_scanner: AhoCorasick,
    /// Full regex patterns for confirmation.
    patterns: Vec<CredentialPattern>,
    /// Prefixes used for fast scan (index-aligned with patterns).
    prefixes: Vec<String>,
}

impl LeakDetector {
    pub fn new() -> Result<Self, LeakDetectError> {
        let patterns = default_patterns();

        // Extract short prefixes from each pattern for fast Aho-Corasick scanning.
        let prefixes: Vec<String> = vec![
            "sk-".into(),       // openai
            "sk-ant-".into(),   // anthropic
            "AKIA".into(),      // aws access key
            "aws_secret".into(),// aws secret
            "ghp_".into(),      // github pat
            "github_pat_".into(),// github fine-grained
            "xox".into(),       // slack
            "sk_live_".into(),  // stripe live
            "sk_test_".into(),  // stripe test
            "-----BEGIN".into(),// pem
            "bearer ".into(),   // bearer token (lowercase)
            "Bearer ".into(),   // bearer token (capitalized)
            "x-api-key".into(), // generic api key header
            "api_key".into(),   // generic api key
            "api-key".into(),   // generic api key variant
        ];

        let prefix_scanner = AhoCorasick::builder()
            .ascii_case_insensitive(false)
            .build(&prefixes)
            .map_err(|e| LeakDetectError::BuildError(e.to_string()))?;

        Ok(Self {
            prefix_scanner,
            patterns,
            prefixes,
        })
    }

    /// Scan a byte buffer for credential leaks.
    ///
    /// Returns all findings. An empty vec means no leaks detected.
    pub fn scan(&self, data: &[u8]) -> Vec<LeakFinding> {
        let mut findings = Vec::new();
        let text = match std::str::from_utf8(data) {
            Ok(t) => t,
            Err(_) => return findings,
        };

        // Phase 1: fast Aho-Corasick prefix scan.
        let mut candidate_regions = Vec::new();
        for mat in self.prefix_scanner.find_iter(data) {
            // Expand the match region for regex confirmation.
            let start = mat.start();
            let end = (start + 200).min(data.len());
            candidate_regions.push(start..end);
        }

        if candidate_regions.is_empty() {
            return findings;
        }

        // Phase 2: regex confirmation on candidate regions.
        for region in &candidate_regions {
            let slice = &text[region.clone()];
            for pattern in &self.patterns {
                if let Some(m) = pattern.regex.find(slice) {
                    let absolute_offset = region.start + m.start();
                    // Avoid duplicate findings at the same offset for the same pattern.
                    if findings.iter().any(|f: &LeakFinding| {
                        f.pattern_name == pattern.name && f.byte_offset == absolute_offset
                    }) {
                        continue;
                    }
                    findings.push(LeakFinding {
                        pattern_name: pattern.name,
                        description: pattern.description,
                        byte_offset: absolute_offset,
                        matched_text: Self::redact_match(m.as_str()),
                    });
                }
            }
        }

        findings
    }

    /// Redact a matched credential, showing only the prefix.
    fn redact_match(matched: &str) -> String {
        let show = matched.len().min(8);
        format!("{}...REDACTED", &matched[..show])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_openai_key() {
        let detector = LeakDetector::new().unwrap();
        let data = b"Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz1234567890";
        let findings = detector.scan(data);
        assert!(!findings.is_empty(), "should detect OpenAI key");
        assert!(findings.iter().any(|f| f.pattern_name == "openai_api_key" || f.pattern_name == "bearer_token"));
    }

    #[test]
    fn detect_anthropic_key() {
        let detector = LeakDetector::new().unwrap();
        let data = b"key: sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let findings = detector.scan(data);
        assert!(findings.iter().any(|f| f.pattern_name == "anthropic_api_key"));
    }

    #[test]
    fn detect_github_pat() {
        let detector = LeakDetector::new().unwrap();
        let data = b"token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let findings = detector.scan(data);
        assert!(findings.iter().any(|f| f.pattern_name == "github_pat"));
    }

    #[test]
    fn detect_pem_key() {
        let detector = LeakDetector::new().unwrap();
        let data = b"-----BEGIN RSA PRIVATE KEY-----\nMIIE...";
        let findings = detector.scan(data);
        assert!(findings.iter().any(|f| f.pattern_name == "pem_private_key"));
    }

    #[test]
    fn no_false_positive_on_normal_text() {
        let detector = LeakDetector::new().unwrap();
        let data = b"Hello, this is a normal HTTP response with no secrets.";
        let findings = detector.scan(data);
        assert!(findings.is_empty(), "should not flag normal text");
    }

    #[test]
    fn redact_hides_credential() {
        let redacted = LeakDetector::redact_match("sk-ant-api03-AAAAAAAAAAAAAAAA");
        assert!(redacted.starts_with("sk-ant-a"));
        assert!(redacted.ends_with("...REDACTED"));
    }
}
