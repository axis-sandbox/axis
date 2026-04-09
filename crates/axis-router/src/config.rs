// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Route resolution — maps model requests to inference backends.

use axis_core::policy::InferenceRoute;

/// Resolve which inference route to use for a given model name.
pub fn resolve_route<'a>(
    routes: &'a [InferenceRoute],
    default_provider: Option<&str>,
    model: &str,
) -> Option<&'a InferenceRoute> {
    // First: exact model match.
    if let Some(route) = routes.iter().find(|r| r.model.as_deref() == Some(model)) {
        return Some(route);
    }

    // Second: default provider.
    if let Some(default) = default_provider {
        if let Some(route) = routes.iter().find(|r| r.name == default) {
            return Some(route);
        }
    }

    // Third: first available route.
    routes.first()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axis_core::policy::InferenceRoute;

    fn test_routes() -> Vec<InferenceRoute> {
        vec![
            InferenceRoute {
                name: "local-rocm".into(),
                endpoint: Some("http://localhost:8080".into()),
                provider: None,
                model: Some("llama-4-scout-109b".into()),
                api_key_env: None,
                protocols: vec!["openai_chat_completions".into()],
            },
            InferenceRoute {
                name: "cloud-fallback".into(),
                endpoint: None,
                provider: Some("anthropic".into()),
                model: Some("claude-sonnet-4-20250514".into()),
                api_key_env: Some("ANTHROPIC_API_KEY".into()),
                protocols: vec![],
            },
        ]
    }

    #[test]
    fn resolve_exact_model() {
        let routes = test_routes();
        let route = resolve_route(&routes, Some("local-rocm"), "llama-4-scout-109b").unwrap();
        assert_eq!(route.name, "local-rocm");
    }

    #[test]
    fn resolve_cloud_model() {
        let routes = test_routes();
        let route = resolve_route(&routes, Some("local-rocm"), "claude-sonnet-4-20250514").unwrap();
        assert_eq!(route.name, "cloud-fallback");
    }

    #[test]
    fn resolve_unknown_falls_to_default() {
        let routes = test_routes();
        let route = resolve_route(&routes, Some("local-rocm"), "unknown-model").unwrap();
        assert_eq!(route.name, "local-rocm");
    }
}
