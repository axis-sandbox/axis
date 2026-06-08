// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Inference pattern detection.
//!
//! Identifies inference API requests (OpenAI, Anthropic, local) by URL
//! patterns and routes them through the inference policy layer.

/// Known inference API patterns.
pub enum InferencePattern {
    OpenAiChatCompletions,
    OpenAiCompletions,
    OpenAiModels,
    AnthropicMessages,
    LocalInference,
}

/// Detect if an HTTP request matches a known inference API pattern.
pub fn detect_inference_pattern(method: &str, path: &str, host: &str) -> Option<InferencePattern> {
    if path_has_dot_segment(path) {
        return None;
    }

    // Local inference virtual host.
    if host == "inference.local" || host.starts_with("inference.local:") {
        if method.eq_ignore_ascii_case("POST")
            && inference_path_matches(path, "/v1/chat/completions")
        {
            return Some(InferencePattern::OpenAiChatCompletions);
        }
        if method.eq_ignore_ascii_case("POST") && inference_path_matches(path, "/v1/completions") {
            return Some(InferencePattern::OpenAiCompletions);
        }
        if method.eq_ignore_ascii_case("GET") && inference_path_matches(path, "/v1/models") {
            return Some(InferencePattern::OpenAiModels);
        }
        return None;
    }

    // OpenAI API.
    if host == "api.openai.com" {
        if method.eq_ignore_ascii_case("POST")
            && inference_path_matches(path, "/v1/chat/completions")
        {
            return Some(InferencePattern::OpenAiChatCompletions);
        }
        if method.eq_ignore_ascii_case("POST") && inference_path_matches(path, "/v1/completions") {
            return Some(InferencePattern::OpenAiCompletions);
        }
        if method.eq_ignore_ascii_case("GET") && inference_path_matches(path, "/v1/models") {
            return Some(InferencePattern::OpenAiModels);
        }
    }

    // Anthropic API.
    if host == "api.anthropic.com"
        && method.eq_ignore_ascii_case("POST")
        && inference_path_matches(path, "/v1/messages")
    {
        return Some(InferencePattern::AnthropicMessages);
    }

    None
}

fn inference_path_matches(path: &str, pattern: &str) -> bool {
    path == pattern
        || path
            .strip_prefix(pattern)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn path_has_dot_segment(path: &str) -> bool {
    path.split('/')
        .any(|segment| segment == "." || segment == "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_local_inference() {
        let pattern = detect_inference_pattern("POST", "/v1/chat/completions", "inference.local");
        assert!(matches!(
            pattern,
            Some(InferencePattern::OpenAiChatCompletions)
        ));
    }

    #[test]
    fn detect_openai() {
        let pattern = detect_inference_pattern("POST", "/v1/chat/completions", "api.openai.com");
        assert!(matches!(
            pattern,
            Some(InferencePattern::OpenAiChatCompletions)
        ));
    }

    #[test]
    fn detect_anthropic() {
        let pattern = detect_inference_pattern("POST", "/v1/messages", "api.anthropic.com");
        assert!(matches!(pattern, Some(InferencePattern::AnthropicMessages)));
    }

    #[test]
    fn provider_patterns_require_segment_boundary() {
        let pattern =
            detect_inference_pattern("POST", "/v1/chat/completions-extra", "api.openai.com");
        assert!(pattern.is_none());

        let pattern = detect_inference_pattern("GET", "/v1/modelscopy", "api.openai.com");
        assert!(pattern.is_none());
    }

    #[test]
    fn provider_patterns_reject_dot_segments() {
        let pattern =
            detect_inference_pattern("POST", "/v1/chat/completions/../files", "api.openai.com");
        assert!(pattern.is_none());
    }

    #[test]
    fn provider_patterns_require_expected_method() {
        let pattern = detect_inference_pattern("GET", "/v1/chat/completions", "api.openai.com");
        assert!(pattern.is_none());

        let pattern = detect_inference_pattern("POST", "/v1/models", "api.openai.com");
        assert!(pattern.is_none());
    }

    #[test]
    fn local_inference_does_not_match_unknown_paths_for_credentials() {
        let pattern = detect_inference_pattern("GET", "/health", "inference.local");
        assert!(pattern.is_none());
    }

    #[test]
    fn no_match_for_random_host() {
        let pattern = detect_inference_pattern("GET", "/", "example.com");
        assert!(pattern.is_none());
    }
}
