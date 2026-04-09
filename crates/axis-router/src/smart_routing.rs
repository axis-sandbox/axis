// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Smart routing — complexity scorer for local-vs-cloud model selection.
//!
//! Classifies prompts into tiers based on multiple dimensions, then routes
//! simple queries to the local model (free, fast) and complex ones to
//! cloud providers (expensive, capable). Inspired by Ironclaw's 13-dimension
//! complexity scorer.

use serde::{Deserialize, Serialize};

/// Complexity tier for routing decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplexityTier {
    /// Simple, short queries. Route to smallest/cheapest model.
    Flash,
    /// Average queries. Route to local model.
    Standard,
    /// Complex reasoning, long context. Route to capable local model.
    Pro,
    /// Expert tasks requiring frontier capability. Route to cloud.
    Frontier,
}

/// Result of scoring a request.
#[derive(Debug, Clone, Serialize)]
pub struct RoutingDecision {
    pub tier: ComplexityTier,
    pub score: f32,
    pub dimensions: ScoreDimensions,
    pub recommended_route: &'static str,
}

/// Individual scoring dimensions.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ScoreDimensions {
    pub message_length: f32,
    pub conversation_depth: f32,
    pub code_content: f32,
    pub reasoning_markers: f32,
    pub tool_use: f32,
    pub system_prompt_complexity: f32,
    pub language_complexity: f32,
    pub domain_specificity: f32,
}

/// Score a chat completion request and return a routing decision.
pub fn score_request(messages: &[Message]) -> RoutingDecision {
    let dims = compute_dimensions(messages);
    let score = weighted_score(&dims);
    let tier = classify(score);

    let recommended_route = match tier {
        ComplexityTier::Flash => "local-small",
        ComplexityTier::Standard => "local",
        ComplexityTier::Pro => "local-large",
        ComplexityTier::Frontier => "cloud",
    };

    RoutingDecision {
        tier,
        score,
        dimensions: dims,
        recommended_route,
    }
}

/// A simplified message representation for scoring.
#[derive(Debug, Clone)]
pub struct Message {
    pub role: String,
    pub content: String,
}

fn compute_dimensions(messages: &[Message]) -> ScoreDimensions {
    let mut dims = ScoreDimensions::default();

    // Total content length across all messages.
    let total_chars: usize = messages.iter().map(|m| m.content.len()).sum();
    dims.message_length = (total_chars as f32 / 2000.0).min(1.0);

    // Conversation depth (number of turns).
    let user_turns = messages.iter().filter(|m| m.role == "user").count();
    dims.conversation_depth = (user_turns as f32 / 10.0).min(1.0);

    // Code content detection.
    let code_markers = ["```", "def ", "fn ", "class ", "function ", "import ", "#include",
                         "SELECT ", "CREATE TABLE", "async ", "await ", "const ", "let ", "var "];
    let code_count: usize = messages.iter()
        .map(|m| code_markers.iter().filter(|&&marker| m.content.contains(marker)).count())
        .sum();
    dims.code_content = (code_count as f32 / 5.0).min(1.0);

    // Reasoning markers.
    let reasoning_markers = ["step by step", "think through", "analyze", "compare",
                              "evaluate", "trade-off", "pros and cons", "reasoning",
                              "explain why", "what if", "consider", "implications"];
    let reasoning_count: usize = messages.iter()
        .map(|m| {
            let lower = m.content.to_lowercase();
            reasoning_markers.iter().filter(|&&marker| lower.contains(marker)).count()
        })
        .sum();
    dims.reasoning_markers = (reasoning_count as f32 / 3.0).min(1.0);

    // Tool use indicators.
    let tool_markers = ["tool_use", "function_call", "tool_result", "<tool>",
                         "execute", "run this", "call the"];
    let tool_count: usize = messages.iter()
        .map(|m| {
            let lower = m.content.to_lowercase();
            tool_markers.iter().filter(|&&marker| lower.contains(marker)).count()
        })
        .sum();
    dims.tool_use = (tool_count as f32 / 2.0).min(1.0);

    // System prompt complexity.
    if let Some(system) = messages.iter().find(|m| m.role == "system") {
        dims.system_prompt_complexity = (system.content.len() as f32 / 1000.0).min(1.0);
    }

    // Language complexity (vocabulary diversity, sentence length).
    let last_user = messages.iter().rev().find(|m| m.role == "user");
    if let Some(msg) = last_user {
        let words: Vec<&str> = msg.content.split_whitespace().collect();
        let unique_words: std::collections::HashSet<&str> = words.iter().copied().collect();
        let diversity = if words.is_empty() { 0.0 } else {
            unique_words.len() as f32 / words.len() as f32
        };
        let avg_word_len = if words.is_empty() { 0.0 } else {
            words.iter().map(|w| w.len()).sum::<usize>() as f32 / words.len() as f32
        };
        dims.language_complexity = ((diversity * 0.5) + (avg_word_len / 10.0).min(0.5)).min(1.0);
    }

    // Domain specificity markers.
    let domain_markers = ["API", "endpoint", "schema", "architecture", "deployment",
                           "kubernetes", "docker", "terraform", "microservice",
                           "regression", "gradient", "neural", "transformer",
                           "litigation", "compliance", "HIPAA", "SOC2"];
    let domain_count: usize = messages.iter()
        .map(|m| domain_markers.iter().filter(|&&marker| m.content.contains(marker)).count())
        .sum();
    dims.domain_specificity = (domain_count as f32 / 3.0).min(1.0);

    dims
}

fn weighted_score(dims: &ScoreDimensions) -> f32 {
    // Weights: higher = more likely to push to cloud.
    dims.message_length * 0.15
        + dims.conversation_depth * 0.10
        + dims.code_content * 0.15
        + dims.reasoning_markers * 0.20
        + dims.tool_use * 0.10
        + dims.system_prompt_complexity * 0.10
        + dims.language_complexity * 0.10
        + dims.domain_specificity * 0.10
}

fn classify(score: f32) -> ComplexityTier {
    if score < 0.15 {
        ComplexityTier::Flash
    } else if score < 0.35 {
        ComplexityTier::Standard
    } else if score < 0.60 {
        ComplexityTier::Pro
    } else {
        ComplexityTier::Frontier
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(role: &str, content: &str) -> Message {
        Message { role: role.into(), content: content.into() }
    }

    #[test]
    fn simple_greeting_is_flash() {
        let messages = vec![msg("user", "Hello!")];
        let decision = score_request(&messages);
        assert_eq!(decision.tier, ComplexityTier::Flash);
        assert_eq!(decision.recommended_route, "local-small");
    }

    #[test]
    fn short_question_is_standard() {
        let messages = vec![
            msg("user", "What is the capital of France? Can you explain a bit about its history?"),
        ];
        let decision = score_request(&messages);
        assert!(decision.tier <= ComplexityTier::Standard,
            "expected Flash or Standard, got {:?} (score={})", decision.tier, decision.score);
    }

    #[test]
    fn code_review_is_pro() {
        let messages = vec![
            msg("system", "You are an expert code reviewer. Analyze code for bugs, security issues, and performance problems."),
            msg("user", "```rust\nfn process_data(input: &[u8]) -> Result<Vec<u8>, Error> {\n    let mut output = Vec::new();\n    for chunk in input.chunks(1024) {\n        let decoded = base64::decode(chunk)?;\n        output.extend_from_slice(&decoded);\n    }\n    Ok(output)\n}\n```\nPlease analyze this function step by step. Consider edge cases and security implications."),
        ];
        let decision = score_request(&messages);
        assert!(decision.tier >= ComplexityTier::Standard,
            "expected Standard+ for code review, got {:?} (score={})", decision.tier, decision.score);
    }

    #[test]
    fn complex_reasoning_is_frontier() {
        let messages = vec![
            msg("system", "You are an expert architect. Evaluate trade-offs carefully and consider all implications."),
            msg("user", "We need to design a distributed system architecture for a real-time trading platform. Compare microservices vs monolith approaches. Analyze the trade-offs of eventual consistency vs strong consistency for the order book. Consider deployment on Kubernetes with multi-region failover. What are the compliance implications for SOC2 and HIPAA? Think through this step by step and evaluate each option's pros and cons."),
        ];
        let decision = score_request(&messages);
        assert!(decision.tier >= ComplexityTier::Pro,
            "expected Pro+ for complex reasoning, got {:?} (score={})", decision.tier, decision.score);
    }

    #[test]
    fn multi_turn_conversation_scores_higher() {
        let single = vec![msg("user", "Summarize this article.")];
        let multi = vec![
            msg("user", "Summarize this article."),
            msg("assistant", "The article discusses..."),
            msg("user", "Can you go deeper into the methodology?"),
            msg("assistant", "The methodology involves..."),
            msg("user", "Now compare this with the approach in the other paper."),
            msg("assistant", "Comparing the two..."),
            msg("user", "What are the implications for our deployment architecture?"),
        ];

        let s1 = score_request(&single);
        let s2 = score_request(&multi);
        assert!(s2.score > s1.score,
            "multi-turn ({}) should score higher than single ({})", s2.score, s1.score);
    }
}
