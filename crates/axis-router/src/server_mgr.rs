// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Inference server lifecycle management.
//!
//! Three modes:
//! - **Managed**: axsd spawns `llama-server` or `vllm` as a child process
//! - **External**: connects to a user-specified endpoint
//! - **Embedded**: loads a GGUF model directly via llama-cpp-rs (in-process)

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("server failed to start: {0}")]
    StartFailed(String),

    #[error("health check failed: {0}")]
    HealthCheckFailed(String),

    #[error("server not running")]
    NotRunning,

    #[error("model not found: {0}")]
    ModelNotFound(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Server operation mode.
#[derive(Debug, Clone)]
pub enum ServerMode {
    /// axsd spawns and manages a llama-server or vLLM process.
    Managed {
        backend: ManagedBackend,
        binary: PathBuf,
        extra_args: Vec<String>,
    },
    /// Connect to user-specified endpoint.
    External { endpoint: String },
    /// Load model directly via llama-cpp-rs (in-process).
    Embedded { n_gpu_layers: i32, context_size: u32 },
}

#[derive(Debug, Clone)]
pub enum ManagedBackend {
    LlamaServer,
    Vllm,
}

/// Tracks the state of an inference server.
pub struct InferenceServer {
    pub mode: ServerMode,
    pub endpoint: Option<SocketAddr>,
    pub model_path: Option<PathBuf>,
    pub healthy: bool,
    child: Option<Child>,
    #[cfg(feature = "embedded-llm")]
    embedded: Option<EmbeddedLlm>,
}

impl InferenceServer {
    pub fn new(mode: ServerMode) -> Self {
        let endpoint = match &mode {
            ServerMode::External { endpoint } => endpoint.parse().ok(),
            _ => None,
        };
        Self {
            mode,
            endpoint,
            model_path: None,
            healthy: false,
            child: None,
            #[cfg(feature = "embedded-llm")]
            embedded: None,
        }
    }

    /// Start the inference server with a given model.
    pub async fn start(&mut self, model_path: &std::path::Path) -> Result<SocketAddr, ServerError> {
        self.model_path = Some(model_path.to_path_buf());

        let mode = self.mode.clone();
        match mode {
            ServerMode::Managed { backend, binary, extra_args } => {
                self.start_managed(backend, &binary, &extra_args, model_path).await
            }
            ServerMode::External { endpoint } => {
                let addr: SocketAddr = endpoint.parse()
                    .map_err(|e| ServerError::StartFailed(format!("bad endpoint: {e}")))?;
                self.endpoint = Some(addr);
                self.health_check().await?;
                self.healthy = true;
                Ok(addr)
            }
            ServerMode::Embedded { n_gpu_layers, context_size } => {
                self.start_embedded(model_path, n_gpu_layers, context_size).await
            }
        }
    }

    /// Start a managed llama-server / vLLM process.
    async fn start_managed(
        &mut self,
        backend: ManagedBackend,
        binary: &std::path::Path,
        extra_args: &[String],
        model_path: &std::path::Path,
    ) -> Result<SocketAddr, ServerError> {
        // Find a free port.
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|e| ServerError::StartFailed(format!("bind: {e}")))?;
        let addr = listener.local_addr()?;
        let port = addr.port();
        drop(listener);

        let mut cmd = Command::new(binary);

        match backend {
            ManagedBackend::LlamaServer => {
                cmd.args([
                    "-m", &model_path.to_string_lossy(),
                    "--port", &port.to_string(),
                    "--host", "127.0.0.1",
                    "-cb", // continuous batching
                ]);
            }
            ManagedBackend::Vllm => {
                cmd.args([
                    "--model", &model_path.to_string_lossy(),
                    "--port", &port.to_string(),
                    "--host", "127.0.0.1",
                ]);
            }
        }
        cmd.args(extra_args);

        // Redirect output to avoid blocking.
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::piped());

        let child = cmd.spawn()
            .map_err(|e| ServerError::StartFailed(format!("{}: {e}", binary.display())))?;

        let pid = child.id();
        self.child = Some(child);

        tracing::info!("inference: started {backend:?} on port {port} (pid={pid})");

        // Wait for health check (poll /health or /v1/models).
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        self.endpoint = Some(bind_addr);

        for attempt in 0..60 {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            if self.health_check().await.is_ok() {
                self.healthy = true;
                tracing::info!("inference: healthy after {attempt}s");
                return Ok(bind_addr);
            }
        }

        Err(ServerError::StartFailed("health check timeout after 60s".into()))
    }

    /// Start embedded inference via llama-cpp-rs.
    async fn start_embedded(
        &mut self,
        model_path: &std::path::Path,
        n_gpu_layers: i32,
        context_size: u32,
    ) -> Result<SocketAddr, ServerError> {
        if !model_path.exists() {
            return Err(ServerError::ModelNotFound(
                model_path.to_string_lossy().into(),
            ));
        }

        #[cfg(feature = "embedded-llm")]
        {
            let embedded = EmbeddedLlm::new(model_path, n_gpu_layers, context_size)?;

            // Start an HTTP server for the embedded model.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            self.endpoint = Some(addr);

            tracing::info!("inference: embedded model loaded, serving on {addr}");

            let model_name = model_path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or("unknown".into());

            // Spawn the HTTP server in background.
            tokio::spawn(async move {
                embedded_http_server(listener, embedded, model_name).await;
            });

            self.healthy = true;
            return Ok(addr);
        }

        #[cfg(not(feature = "embedded-llm"))]
        {
            let _ = (model_path, n_gpu_layers, context_size);
            Err(ServerError::StartFailed(
                "embedded LLM requires the 'embedded-llm' feature flag".into(),
            ))
        }
    }

    /// Check if the server is healthy via HTTP.
    pub async fn health_check(&self) -> Result<(), ServerError> {
        let addr = self.endpoint.ok_or(ServerError::NotRunning)?;
        let url = format!("http://{addr}/v1/models");

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .map_err(|e| ServerError::HealthCheckFailed(e.to_string()))?;

        client.get(&url).send().await
            .map_err(|e| ServerError::HealthCheckFailed(e.to_string()))?;
        Ok(())
    }

    /// Stop the server.
    pub fn stop(&mut self) {
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;
        self.healthy = false;
        tracing::info!("inference: server stopped");
    }

    /// Get the endpoint address.
    pub fn addr(&self) -> Option<SocketAddr> {
        self.endpoint
    }
}

impl Drop for InferenceServer {
    fn drop(&mut self) {
        self.stop();
    }
}

// ── Embedded LLM via llama-cpp-rs ───────────────────────────────────────────

#[cfg(feature = "embedded-llm")]
struct EmbeddedLlm {
    backend: llama_cpp_2::llama_backend::LlamaBackend,
    model: std::sync::Arc<llama_cpp_2::model::LlamaModel>,
    context_size: u32,
}

#[cfg(feature = "embedded-llm")]
unsafe impl Send for EmbeddedLlm {}
#[cfg(feature = "embedded-llm")]
unsafe impl Sync for EmbeddedLlm {}

#[cfg(feature = "embedded-llm")]
impl EmbeddedLlm {
    fn new(
        model_path: &std::path::Path,
        n_gpu_layers: i32,
        context_size: u32,
    ) -> Result<Self, ServerError> {
        use llama_cpp_2::llama_backend::LlamaBackend;
        use llama_cpp_2::model::params::LlamaModelParams;
        use llama_cpp_2::model::LlamaModel;
        use std::pin::pin;

        let backend = LlamaBackend::init()
            .map_err(|e| ServerError::StartFailed(format!("llama backend init: {e}")))?;

        let model_params = LlamaModelParams::default()
            .with_n_gpu_layers(n_gpu_layers as u32);
        let model_params = pin!(model_params);

        let model = LlamaModel::load_from_file(&backend, model_path, &model_params)
            .map_err(|e| ServerError::StartFailed(format!("model load: {e}")))?;

        tracing::info!(
            "inference: loaded {} ({} params)",
            model_path.display(),
            "embedded",
        );

        Ok(Self {
            backend,
            model: std::sync::Arc::new(model),
            context_size,
        })
    }

    fn generate(&self, prompt: &str, max_tokens: u32) -> Result<String, ServerError> {
        use llama_cpp_2::context::params::LlamaContextParams;
        use llama_cpp_2::llama_batch::LlamaBatch;
        use llama_cpp_2::model::AddBos;
        use llama_cpp_2::sampling::LlamaSampler;
        use std::num::NonZeroU32;

        let ctx_params = LlamaContextParams::default()
            .with_n_ctx(NonZeroU32::new(self.context_size));
        let mut ctx = self.model.new_context(&self.backend, ctx_params)
            .map_err(|e| ServerError::StartFailed(format!("context: {e}")))?;

        let tokens = self.model.str_to_token(prompt, AddBos::Always)
            .map_err(|e| ServerError::StartFailed(format!("tokenize: {e}")))?;

        let mut batch = LlamaBatch::new(self.context_size as usize, 1);
        let last_idx = tokens.len() - 1;
        for (i, tok) in tokens.iter().enumerate() {
            batch.add(*tok, i as i32, &[0], i == last_idx)
                .map_err(|e| ServerError::StartFailed(format!("batch: {e}")))?;
        }

        ctx.decode(&mut batch)
            .map_err(|e| ServerError::StartFailed(format!("decode prompt: {e}")))?;

        let mut sampler = LlamaSampler::chain_simple([
            LlamaSampler::dist(42),
            LlamaSampler::greedy(),
        ]);

        let mut output = String::new();
        let mut n_cur = tokens.len() as i32;
        let mut decoder = encoding_rs::UTF_8.new_decoder();

        for _ in 0..max_tokens {
            let token = sampler.sample(&ctx, batch.n_tokens() - 1);
            sampler.accept(token);

            if self.model.is_eog_token(token) {
                break;
            }

            if let Ok(piece) = self.model.token_to_piece(token, &mut decoder, true, None) {
                output.push_str(&piece);
            }

            batch.clear();
            batch.add(token, n_cur, &[0], true)
                .map_err(|e| ServerError::StartFailed(format!("batch add: {e}")))?;
            ctx.decode(&mut batch)
                .map_err(|e| ServerError::StartFailed(format!("decode: {e}")))?;
            n_cur += 1;
        }

        Ok(output)
    }
}

/// Run a minimal OpenAI-compatible HTTP server for the embedded model.
#[cfg(feature = "embedded-llm")]
async fn embedded_http_server(
    listener: tokio::net::TcpListener,
    llm: EmbeddedLlm,
    model_name: String,
) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let llm = std::sync::Arc::new(std::sync::Mutex::new(llm));

    loop {
        let Ok((stream, _)) = listener.accept().await else { break };
        let llm = llm.clone();
        let model_name = model_name.clone();

        tokio::spawn(async move {
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);

            // Read HTTP request.
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).await.is_err() { return; }

            // Read headers.
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).await.is_err() { return; }
                if line.trim().is_empty() { break; }
                if let Some(cl) = line.strip_prefix("Content-Length: ") {
                    content_length = cl.trim().parse().unwrap_or(0);
                }
                if let Some(cl) = line.strip_prefix("content-length: ") {
                    content_length = cl.trim().parse().unwrap_or(0);
                }
            }

            // Read body.
            let mut body = vec![0u8; content_length];
            if content_length > 0 {
                let _ = tokio::io::AsyncReadExt::read_exact(&mut reader, &mut body).await;
            }

            let parts: Vec<&str> = request_line.split_whitespace().collect();
            let (method, path) = if parts.len() >= 2 {
                (parts[0], parts[1])
            } else {
                return;
            };

            let response_body = match (method, path) {
                ("GET", "/v1/models") => {
                    serde_json::json!({
                        "object": "list",
                        "data": [{
                            "id": model_name,
                            "object": "model",
                            "owned_by": "axis-local",
                        }]
                    }).to_string()
                }
                ("POST", "/v1/chat/completions") => {
                    let req: serde_json::Value = serde_json::from_slice(&body)
                        .unwrap_or_default();

                    // Build prompt from messages.
                    let messages = req["messages"].as_array();
                    let mut prompt = String::new();
                    if let Some(msgs) = messages {
                        for msg in msgs {
                            let role = msg["role"].as_str().unwrap_or("user");
                            let content = msg["content"].as_str().unwrap_or("");
                            prompt.push_str(&format!("<|{role}|>\n{content}\n"));
                        }
                        prompt.push_str("<|assistant|>\n");
                    }

                    let max_tokens = req["max_tokens"].as_u64().unwrap_or(256) as u32;

                    // Generate.
                    let result = {
                        let llm = llm.lock().unwrap();
                        llm.generate(&prompt, max_tokens)
                    };

                    match result {
                        Ok(text) => {
                            serde_json::json!({
                                "id": format!("chatcmpl-{}", uuid::Uuid::new_v4()),
                                "object": "chat.completion",
                                "model": model_name,
                                "choices": [{
                                    "index": 0,
                                    "message": {
                                        "role": "assistant",
                                        "content": text,
                                    },
                                    "finish_reason": "stop",
                                }],
                                "usage": {
                                    "prompt_tokens": prompt.len() / 4,
                                    "completion_tokens": text.len() / 4,
                                    "total_tokens": (prompt.len() + text.len()) / 4,
                                }
                            }).to_string()
                        }
                        Err(e) => {
                            serde_json::json!({
                                "error": {
                                    "message": format!("{e}"),
                                    "type": "server_error",
                                }
                            }).to_string()
                        }
                    }
                }
                ("GET", "/health") => {
                    r#"{"status":"ok"}"#.to_string()
                }
                _ => {
                    let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                    let _ = writer.write_all(resp.as_bytes()).await;
                    return;
                }
            };

            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                response_body.len(),
                response_body,
            );
            let _ = writer.write_all(resp.as_bytes()).await;
        });
    }
}
