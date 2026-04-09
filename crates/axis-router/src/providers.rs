// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Inference provider profiles — OpenAI, Anthropic, ROCm local.

/// Known inference provider types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderType {
    OpenAi,
    Anthropic,
    LocalRocm,
    Custom,
}

impl ProviderType {
    pub fn from_name(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "openai" => Self::OpenAi,
            "anthropic" => Self::Anthropic,
            "local-rocm" | "rocm" | "local" => Self::LocalRocm,
            _ => Self::Custom,
        }
    }

    /// The environment variable conventionally holding the API key for this provider.
    pub fn default_api_key_env(&self) -> Option<&'static str> {
        match self {
            Self::OpenAi => Some("OPENAI_API_KEY"),
            Self::Anthropic => Some("ANTHROPIC_API_KEY"),
            Self::LocalRocm => None,
            Self::Custom => None,
        }
    }
}
