// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Model registry — tracks available models and their resource requirements.
//! Includes HuggingFace model download support.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A registered model in the local registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelEntry {
    pub name: String,
    pub source: Option<String>,
    pub format: ModelFormat,
    pub local_path: Option<PathBuf>,
    pub vram_required_mb: Option<u64>,
    pub context_length: Option<u64>,
    pub capabilities: Vec<String>,
    pub preferred_backend: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelFormat {
    Safetensors,
    Gguf,
    Onnx,
}

/// Model swap policy when VRAM is insufficient for multiple models.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapPolicy {
    Queue,
    Reject,
    EvictLru,
}

/// Local model registry.
#[derive(Debug, Default)]
pub struct ModelRegistry {
    models: Vec<ModelEntry>,
    cache_dir: PathBuf,
}

impl ModelRegistry {
    pub fn new() -> Self {
        let cache_dir = default_cache_dir();
        std::fs::create_dir_all(&cache_dir).ok();
        Self {
            models: Vec::new(),
            cache_dir,
        }
    }

    /// Register a model.
    pub fn add(&mut self, entry: ModelEntry) {
        self.models.retain(|m| m.name != entry.name);
        self.models.push(entry);
    }

    /// Find a model by name.
    pub fn get(&self, name: &str) -> Option<&ModelEntry> {
        self.models.iter().find(|m| m.name == name)
    }

    /// List all registered models.
    pub fn list(&self) -> &[ModelEntry] {
        &self.models
    }

    /// Remove a model by name.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.models.len();
        self.models.retain(|m| m.name != name);
        self.models.len() < before
    }

    /// Check if a model's local path exists and is accessible.
    pub fn is_available(&self, name: &str) -> bool {
        self.get(name)
            .and_then(|m| m.local_path.as_ref())
            .is_some_and(|p| p.exists())
    }

    /// Get the cache directory.
    pub fn cache_dir(&self) -> &PathBuf {
        &self.cache_dir
    }

    /// Pull a model from HuggingFace. Returns the local path on success.
    pub async fn pull(&mut self, source: &str) -> Result<PathBuf, String> {
        let (repo_id, filename) = parse_hf_source(source)?;

        let model_dir = self.cache_dir.join(&repo_id.replace('/', "--"));
        std::fs::create_dir_all(&model_dir).map_err(|e| e.to_string())?;

        let local_path = model_dir.join(&filename);

        if local_path.exists() {
            tracing::info!("model: {} already cached at {}", source, local_path.display());
            return Ok(local_path);
        }

        let url = format!(
            "https://huggingface.co/{}/resolve/main/{}",
            repo_id, filename,
        );

        tracing::info!("model: downloading {} -> {}", url, local_path.display());
        download_file(&url, &local_path).await?;

        // Verify the file is non-empty.
        let meta = std::fs::metadata(&local_path).map_err(|e| e.to_string())?;
        if meta.len() == 0 {
            std::fs::remove_file(&local_path).ok();
            return Err("downloaded file is empty".into());
        }

        tracing::info!(
            "model: downloaded {} ({:.1} MB)",
            filename,
            meta.len() as f64 / (1024.0 * 1024.0),
        );

        // Auto-register the model.
        let name = filename
            .strip_suffix(".gguf")
            .or(filename.strip_suffix(".safetensors"))
            .unwrap_or(&filename)
            .to_string();

        let format = if filename.ends_with(".gguf") {
            ModelFormat::Gguf
        } else if filename.ends_with(".safetensors") {
            ModelFormat::Safetensors
        } else {
            ModelFormat::Onnx
        };

        self.add(ModelEntry {
            name: name.clone(),
            source: Some(source.to_string()),
            format,
            local_path: Some(local_path.clone()),
            vram_required_mb: None,
            context_length: None,
            capabilities: vec!["chat".into()],
            preferred_backend: if filename.ends_with(".gguf") {
                Some("llamacpp".into())
            } else {
                None
            },
        });

        Ok(local_path)
    }
}

/// Parse a HuggingFace source string into (repo_id, filename).
///
/// Formats:
/// - `huggingface://owner/repo/filename.gguf`
/// - `hf://owner/repo/filename.gguf`
/// - `owner/repo/filename.gguf` (bare)
fn parse_hf_source(source: &str) -> Result<(String, String), String> {
    let path = source
        .strip_prefix("huggingface://")
        .or(source.strip_prefix("hf://"))
        .unwrap_or(source);

    let parts: Vec<&str> = path.splitn(3, '/').collect();
    if parts.len() < 3 {
        return Err(format!(
            "invalid HuggingFace source: '{source}'. Expected: owner/repo/filename.gguf"
        ));
    }

    let repo_id = format!("{}/{}", parts[0], parts[1]);
    let filename = parts[2].to_string();
    Ok((repo_id, filename))
}

/// Download a file from URL to local path with progress.
async fn download_file(url: &str, dest: &std::path::Path) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
        .timeout(std::time::Duration::from_secs(3600))
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;

    let resp = client.get(url).send().await
        .map_err(|e| format!("download failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}: {url}", resp.status()));
    }

    let total_size = resp.content_length().unwrap_or(0);

    let mut file = tokio::fs::File::create(dest).await
        .map_err(|e| format!("create file: {e}"))?;

    let mut downloaded: u64 = 0;
    let mut stream = resp.bytes_stream();

    use tokio::io::AsyncWriteExt;
    use futures_util::StreamExt;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("download: {e}"))?;
        file.write_all(&chunk).await.map_err(|e| format!("write: {e}"))?;
        downloaded += chunk.len() as u64;

        if total_size > 0 && downloaded % (10 * 1024 * 1024) < chunk.len() as u64 {
            let pct = (downloaded as f64 / total_size as f64) * 100.0;
            tracing::info!(
                "model: {:.0}% ({:.1}/{:.1} MB)",
                pct,
                downloaded as f64 / 1048576.0,
                total_size as f64 / 1048576.0,
            );
        }
    }

    file.flush().await.map_err(|e| format!("flush: {e}"))?;
    Ok(())
}

fn default_cache_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".cache").join("axis").join("models")
    } else if let Ok(home) = std::env::var("USERPROFILE") {
        PathBuf::from(home).join(".cache").join("axis").join("models")
    } else {
        PathBuf::from("/tmp/axis/models")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hf_source_full() {
        let (repo, file) = parse_hf_source("huggingface://Qwen/Qwen3-0.6B-GGUF/qwen3-0.6b-q4_k_m.gguf").unwrap();
        assert_eq!(repo, "Qwen/Qwen3-0.6B-GGUF");
        assert_eq!(file, "qwen3-0.6b-q4_k_m.gguf");
    }

    #[test]
    fn parse_hf_source_bare() {
        let (repo, file) = parse_hf_source("microsoft/phi-4-mini-instruct-gguf/phi-4-mini.Q4_K_M.gguf").unwrap();
        assert_eq!(repo, "microsoft/phi-4-mini-instruct-gguf");
        assert_eq!(file, "phi-4-mini.Q4_K_M.gguf");
    }

    #[test]
    fn parse_hf_source_invalid() {
        assert!(parse_hf_source("just-a-name").is_err());
    }

    #[test]
    fn registry_add_and_get() {
        let mut reg = ModelRegistry::new();
        reg.add(ModelEntry {
            name: "test-model".into(),
            source: None,
            format: ModelFormat::Gguf,
            local_path: None,
            vram_required_mb: Some(4096),
            context_length: Some(8192),
            capabilities: vec!["chat".into()],
            preferred_backend: Some("llamacpp".into()),
        });
        assert!(reg.get("test-model").is_some());
        assert_eq!(reg.get("test-model").unwrap().vram_required_mb, Some(4096));
    }
}
