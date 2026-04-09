// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Backend proxying — forwards inference requests to resolved endpoints.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("request failed: {0}")]
    RequestFailed(String),

    #[error("backend unavailable: {0}")]
    Unavailable(String),
}

/// Forward a chat completion request to a backend endpoint.
pub async fn forward_chat_completion(
    endpoint: &str,
    body: &serde_json::Value,
    api_key: Option<&str>,
) -> Result<serde_json::Value, BackendError> {
    let client = reqwest::Client::new();
    let mut req = client.post(format!("{endpoint}/v1/chat/completions"));

    if let Some(key) = api_key {
        req = req.bearer_auth(key);
    }

    let resp = req
        .json(body)
        .send()
        .await
        .map_err(|e| BackendError::RequestFailed(e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(BackendError::RequestFailed(format!(
            "HTTP {status}: {text}"
        )));
    }

    resp.json()
        .await
        .map_err(|e| BackendError::RequestFailed(e.to_string()))
}
