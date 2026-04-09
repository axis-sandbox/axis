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
    // Local inference virtual host.
    if host == "inference.local" || host.starts_with("inference.local:") {
        if path == "/v1/chat/completions" && method == "POST" {
            return Some(InferencePattern::OpenAiChatCompletions);
        }
        if path == "/v1/completions" && method == "POST" {
            return Some(InferencePattern::OpenAiCompletions);
        }
        if path == "/v1/models" && method == "GET" {
            return Some(InferencePattern::OpenAiModels);
        }
        return Some(InferencePattern::LocalInference);
    }

    // OpenAI API.
    if host == "api.openai.com" {
        if path.starts_with("/v1/chat/completions") {
            return Some(InferencePattern::OpenAiChatCompletions);
        }
        if path.starts_with("/v1/models") {
            return Some(InferencePattern::OpenAiModels);
        }
    }

    // Anthropic API.
    if host == "api.anthropic.com" && path.starts_with("/v1/messages") {
        return Some(InferencePattern::AnthropicMessages);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_local_inference() {
        let pattern = detect_inference_pattern("POST", "/v1/chat/completions", "inference.local");
        assert!(matches!(pattern, Some(InferencePattern::OpenAiChatCompletions)));
    }

    #[test]
    fn detect_openai() {
        let pattern = detect_inference_pattern("POST", "/v1/chat/completions", "api.openai.com");
        assert!(matches!(pattern, Some(InferencePattern::OpenAiChatCompletions)));
    }

    #[test]
    fn detect_anthropic() {
        let pattern = detect_inference_pattern("POST", "/v1/messages", "api.anthropic.com");
        assert!(matches!(pattern, Some(InferencePattern::AnthropicMessages)));
    }

    #[test]
    fn no_match_for_random_host() {
        let pattern = detect_inference_pattern("GET", "/", "example.com");
        assert!(pattern.is_none());
    }
}
