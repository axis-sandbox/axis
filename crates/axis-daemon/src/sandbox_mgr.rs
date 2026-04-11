// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox lifecycle manager — create, list, destroy sandboxes.
//!
//! Each sandbox gets:
//! 1. A workspace directory
//! 2. A dedicated proxy (AxisProxy) on a dynamic port
//! 3. An isolated child process with OS-native sandboxing
//! 4. Optionally, a HIP Remote GPU worker (when gpu.enabled)
//!
//! The proxy enforces OPA network policy and leak detection.
//! The sandbox process has HTTP_PROXY/HTTPS_PROXY pointing to its proxy.

use axis_core::audit::{AuditEvent, AuditLog, BroadcastSink, TracingSink};
use axis_gateway::SandboxBackend;
use axis_core::policy::Policy;
use axis_core::types::{SandboxId, SandboxStatus};
use axis_gpu::api_filter::GpuPolicy as GpuFilterPolicy;
use axis_gpu::worker_mgr::WorkerManager;
use axis_proxy::proxy::{AxisProxy, ProxyConfig};
use axis_router::server_mgr::{InferenceServer, ManagedBackend, ServerMode};
use axis_sandbox::{Sandbox, SandboxConfig};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};

/// Base port for dynamic proxy allocation.
const PROXY_PORT_BASE: u16 = 13100;

/// Atomic counter for allocating unique proxy ports.
static NEXT_PORT: AtomicU16 = AtomicU16::new(PROXY_PORT_BASE);

/// State for a running sandbox (sandbox process + proxy + optional GPU worker).
struct ManagedSandbox {
    sandbox: Sandbox,
    proxy_addr: SocketAddr,
    proxy_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    gpu_enabled: bool,
    policy_name: String,
    /// Broadcast channel for streaming sandbox stdout to WebSocket clients.
    output_tx: Option<tokio::sync::broadcast::Sender<Vec<u8>>>,
}

pub struct SandboxManager {
    sandboxes: HashMap<SandboxId, ManagedSandbox>,
    gpu_manager: WorkerManager,
    inference_server: Option<InferenceServer>,
    audit: AuditLog,
    sandbox_base_dir: PathBuf,
}

impl SandboxManager {
    pub fn new() -> Self {
        Self::with_event_broadcast(None)
    }

    /// Create a SandboxManager with an optional broadcast channel for streaming
    /// audit events to the gateway (GUI/WebSocket clients).
    pub fn with_event_broadcast(
        event_tx: Option<tokio::sync::broadcast::Sender<AuditEvent>>,
    ) -> Self {
        let mut audit = AuditLog::new();
        audit.add_sink(Box::new(TracingSink));
        if let Some(tx) = event_tx {
            audit.add_sink(Box::new(BroadcastSink::new(tx)));
        }

        let sandbox_base_dir = dirs_base();
        std::fs::create_dir_all(&sandbox_base_dir).ok();

        // Look for hip-worker binary in standard locations.
        let worker_binary = find_hip_worker();

        Self {
            sandboxes: HashMap::new(),
            gpu_manager: WorkerManager::new(worker_binary),
            inference_server: None,
            audit,
            sandbox_base_dir,
        }
    }

    /// Create and start a new sandbox with its own proxy (and optional GPU worker).
    pub async fn create(
        &mut self,
        policy: Policy,
        command: String,
        args: Vec<String>,
        env: Vec<(String, String)>,
    ) -> Result<SandboxId, String> {
        let id = SandboxId::new();
        let workspace_dir = self.sandbox_base_dir.join(id.to_string());
        std::fs::create_dir_all(&workspace_dir).map_err(|e| e.to_string())?;

        let policy_name = policy.name.clone();
        let gpu_enabled = policy.gpu.enabled;

        // 1. Start inference server if policy has routes with a local endpoint.
        let inference_endpoint = self.ensure_inference_server(&policy).await;

        // 2. Start the proxy.
        let proxy_port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();

        let proxy_config = ProxyConfig {
            sandbox_id: id,
            bind_addr,
            policy: policy.clone(),
            enable_l7: false,
            enable_leak_detection: true,
            inference_endpoint,
        };

        let mut proxy = AxisProxy::new(proxy_config)
            .map_err(|e| format!("proxy init: {e}"))?;
        let proxy_addr = proxy.bind().await
            .map_err(|e| format!("proxy bind: {e}"))?;

        tracing::info!("sandbox {id}: proxy on {proxy_addr}");

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            tokio::select! {
                result = proxy.run() => {
                    if let Err(e) = result {
                        tracing::error!("proxy for sandbox exited: {e}");
                    }
                }
                _ = &mut shutdown_rx => {
                    tracing::info!("proxy shutdown signal received");
                }
            }
        });

        // 2. Optionally start a GPU worker.
        let mut extra_env: Vec<(String, String)> = Vec::new();

        if gpu_enabled {
            let gpu_filter_policy = GpuFilterPolicy {
                enabled: true,
                device: policy.gpu.device,
                transport: match policy.gpu.transport {
                    axis_core::policy::GpuTransport::Uds => axis_gpu::api_filter::GpuTransport::Uds,
                    axis_core::policy::GpuTransport::Tcp => axis_gpu::api_filter::GpuTransport::Tcp,
                },
                vram_limit_mb: policy.gpu.vram_limit_mb,
                compute_timeout_sec: policy.gpu.compute_timeout_sec,
                allowed_apis: Vec::new(), // use defaults
                denied_apis: Vec::new(),  // use defaults
            };

            match self.gpu_manager.spawn_worker(id, &gpu_filter_policy, &workspace_dir).await {
                Ok(endpoint) => {
                    tracing::info!("sandbox {id}: GPU worker on {endpoint}");
                    extra_env.extend(endpoint.to_env_vars());
                    // Add hip-remote client library to LD_LIBRARY_PATH so the sandbox
                    // picks up our libamdhip64.so instead of the real one.
                    let client_lib_dir = find_hip_client_lib();
                    if let Some(dir) = client_lib_dir {
                        extra_env.push(("LD_LIBRARY_PATH".into(), dir));
                    }
                }
                Err(e) => {
                    tracing::warn!("sandbox {id}: GPU worker failed: {e} (sandbox will run without GPU)");
                }
            }
        }

        // 3. Create and start the sandbox process.
        let mut all_env = env;
        all_env.extend(extra_env);

        let timeout_sec = policy.process.timeout_sec;
        let config = SandboxConfig {
            id,
            policy,
            command,
            args,
            working_dir: None,
            workspace_dir,
            env: all_env,
            proxy_port: proxy_addr.port(),
            capture_output: true,
            timeout_sec,
        };

        let mut sandbox = Sandbox::create(config).map_err(|e| e.to_string())?;
        sandbox.start().map_err(|e| format!("sandbox start: {e}"))?;

        let gpu_label = if gpu_enabled { ", gpu=on" } else { "" };
        tracing::info!(
            "sandbox {id}: started (pid={}, proxy={proxy_addr}, policy='{policy_name}'{gpu_label})",
            sandbox.pid.unwrap_or(0),
        );
        self.audit.sandbox_created(id, &policy_name);

        // Spawn background task to read stdout and broadcast to WebSocket clients.
        let (output_tx, _) = tokio::sync::broadcast::channel::<Vec<u8>>(256);
        if let Some(stdout) = sandbox.stdout.take() {
            let tx = output_tx.clone();
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut stdout = tokio::process::ChildStdout::from_std(stdout).unwrap();
                let mut buf = [0u8; 4096];
                loop {
                    match stdout.read(&mut buf).await {
                        Ok(0) => break, // EOF
                        Ok(n) => { let _ = tx.send(buf[..n].to_vec()); }
                        Err(_) => break,
                    }
                }
            });
        }
        if let Some(stderr) = sandbox.stderr.take() {
            let tx = output_tx.clone();
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut stderr = tokio::process::ChildStderr::from_std(stderr).unwrap();
                let mut buf = [0u8; 4096];
                loop {
                    match stderr.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => { let _ = tx.send(buf[..n].to_vec()); }
                        Err(_) => break,
                    }
                }
            });
        }

        self.sandboxes.insert(id, ManagedSandbox {
            sandbox,
            proxy_addr,
            proxy_shutdown: Some(shutdown_tx),
            gpu_enabled,
            policy_name: policy_name.clone(),
            output_tx: Some(output_tx),
        });

        Ok(id)
    }

    /// Start or reuse an inference server based on the policy's inference config.
    async fn ensure_inference_server(&mut self, policy: &Policy) -> Option<SocketAddr> {
        // If we already have a running inference server, reuse it.
        if let Some(ref server) = self.inference_server {
            if server.healthy {
                return server.addr();
            }
        }

        // Check if the policy has a local inference route.
        let local_route = policy.inference.routes.iter().find(|r| {
            r.endpoint.is_some() && r.endpoint.as_ref().is_some_and(|e| e.starts_with("http://localhost") || e.starts_with("http://127.0.0.1"))
        });

        if local_route.is_none() && policy.inference.routes.is_empty() {
            return None;
        }

        // Try to find a model to serve.
        let registry = axis_router::models::ModelRegistry::new();
        let model_path = policy.inference.routes.iter().find_map(|r| {
            r.model.as_ref().and_then(|name| {
                registry.get(name).and_then(|entry| entry.local_path.clone())
            })
        });

        let Some(model_path) = model_path else {
            tracing::info!("inference: no local model available, skipping server start");
            return None;
        };

        // Start a managed llama-server or embedded server.
        let mode = if which_exists("llama-server") {
            ServerMode::Managed {
                backend: ManagedBackend::LlamaServer,
                binary: PathBuf::from("llama-server"),
                extra_args: vec![],
            }
        } else {
            ServerMode::Embedded {
                n_gpu_layers: 0, // CPU-only by default
                context_size: 4096,
            }
        };

        let mut server = InferenceServer::new(mode);
        match server.start(&model_path).await {
            Ok(addr) => {
                tracing::info!("inference: server started on {addr} (model={})", model_path.display());
                self.inference_server = Some(server);
                Some(addr)
            }
            Err(e) => {
                tracing::warn!("inference: server start failed: {e}");
                None
            }
        }
    }

    /// Execute a command inside an existing sandbox's workspace.
    ///
    /// The command runs with the same proxy env vars and working directory
    /// as the original sandbox process. On Linux, it inherits the sandbox's
    /// Landlock and seccomp restrictions via a fresh pre_exec application.
    pub fn exec_in_sandbox(
        &self,
        id: &SandboxId,
        command: String,
        args: Vec<String>,
    ) -> Result<i32, String> {
        let managed = self
            .sandboxes
            .get(id)
            .ok_or_else(|| format!("sandbox not found: {id}"))?;

        let workspace = &managed.sandbox.workspace_dir;
        let proxy_port = managed.proxy_addr.port();
        let proxy_url = format!("http://127.0.0.1:{proxy_port}");

        tracing::info!("sandbox {id}: exec '{command}' in {}", workspace.display());

        let output = std::process::Command::new(&command)
            .args(&args)
            .current_dir(workspace)
            .env("HTTP_PROXY", &proxy_url)
            .env("HTTPS_PROXY", &proxy_url)
            .env("http_proxy", &proxy_url)
            .env("https_proxy", &proxy_url)
            .output()
            .map_err(|e| format!("exec failed: {e}"))?;

        let code = output.status.code().unwrap_or(-1);
        tracing::info!("sandbox {id}: exec '{command}' exited with code {code}");
        Ok(code)
    }

    /// Destroy a sandbox, its proxy, and its GPU worker.
    pub fn destroy(&mut self, id: &SandboxId) -> Result<(), String> {
        let managed = self
            .sandboxes
            .get_mut(id)
            .ok_or_else(|| format!("sandbox not found: {id}"))?;

        managed.sandbox.destroy().map_err(|e| e.to_string())?;

        if let Some(tx) = managed.proxy_shutdown.take() {
            let _ = tx.send(());
        }

        if managed.gpu_enabled {
            if let Err(e) = self.gpu_manager.stop_worker(id) {
                tracing::warn!("sandbox {id}: GPU worker cleanup: {e}");
            }
        }

        self.audit.sandbox_destroyed(*id);
        self.sandboxes.remove(id);

        tracing::info!("sandbox {id}: destroyed");
        Ok(())
    }

    /// List all sandboxes.
    pub fn list(&self) -> Vec<SandboxInfo> {
        self.sandboxes
            .values()
            .map(|m| {
                let gpu_info = if m.gpu_enabled {
                    self.gpu_manager
                        .endpoint(&m.sandbox.id)
                        .map(|e| e.to_string())
                } else {
                    None
                };

                SandboxInfo {
                    id: m.sandbox.id,
                    status: m.sandbox.status,
                    policy_name: m.policy_name.clone(),
                    pid: m.sandbox.pid,
                    workspace: m.sandbox.workspace_dir.clone(),
                    proxy_addr: m.proxy_addr.to_string(),
                    gpu_worker: gpu_info,
                }
            })
            .collect()
    }

    /// Subscribe to a sandbox's stdout/stderr output stream.
    pub fn subscribe_output(&self, id: &SandboxId) -> Option<tokio::sync::broadcast::Receiver<Vec<u8>>> {
        self.sandboxes
            .get(id)
            .and_then(|m| m.output_tx.as_ref())
            .map(|tx| tx.subscribe())
    }
}

#[derive(Debug, serde::Serialize)]
pub struct SandboxInfo {
    pub id: SandboxId,
    pub status: SandboxStatus,
    pub policy_name: String,
    pub pid: Option<u32>,
    pub workspace: PathBuf,
    pub proxy_addr: String,
    pub gpu_worker: Option<String>,
}

fn allocate_port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::Relaxed)
}

fn which_exists(binary: &str) -> bool {
    std::process::Command::new("which")
        .arg(binary)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn find_hip_client_lib() -> Option<String> {
    // Find the directory containing the hip-remote client library (libamdhip64.so).
    for candidate in &[
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../hip-remote/build-client"),
        "/usr/local/lib",
        "/usr/lib",
    ] {
        let dir = PathBuf::from(candidate);
        if dir.join("libamdhip64.so").exists() {
            return Some(dir.to_string_lossy().into());
        }
    }
    None
}

fn find_hip_worker() -> PathBuf {
    // Check common locations for the hip-worker binary.
    for candidate in &[
        // AXIS build directory (development)
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../hip-remote/build-worker/hip-worker"),
        "/usr/local/bin/hip-worker",
        "/usr/bin/hip-worker",
    ] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return p;
        }
    }
    // Default: expect it in PATH.
    PathBuf::from("hip-worker")
}

fn dirs_base() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        PathBuf::from(xdg).join("axis").join("sandboxes")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("axis")
            .join("sandboxes")
    } else {
        PathBuf::from("/tmp/axis/sandboxes")
    }
}

// ── Gateway Backend ─────────────────────────────────────────────────────

/// Wraps `SandboxManager` behind `Arc<Mutex<>>` to implement `SandboxBackend`
/// for the gateway. All methods acquire the mutex for each operation.
pub struct SandboxManagerBackend {
    mgr: std::sync::Arc<tokio::sync::Mutex<SandboxManager>>,
}

impl SandboxManagerBackend {
    pub fn new(mgr: std::sync::Arc<tokio::sync::Mutex<SandboxManager>>) -> Self {
        Self { mgr }
    }
}

impl SandboxBackend for SandboxManagerBackend {
    fn create_sandbox(
        &self,
        policy_yaml: &str,
        command: String,
        args: Vec<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + '_>> {
        let policy_yaml = policy_yaml.to_string();
        Box::pin(async move {
            let policy = axis_core::policy::Policy::from_yaml(&policy_yaml)
                .map_err(|e| format!("invalid policy: {e}"))?;
            let mut mgr = self.mgr.lock().await;
            let id = mgr.create(policy, command, args, vec![]).await?;
            Ok(id.to_string())
        })
    }

    fn destroy_sandbox(
        &self,
        id: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        let id = id.to_string();
        Box::pin(async move {
            let sandbox_id: axis_core::types::SandboxId = id
                .parse()
                .map_err(|_| format!("invalid sandbox id: {id}"))?;
            let mut mgr = self.mgr.lock().await;
            mgr.destroy(&sandbox_id)
        })
    }

    fn list_sandboxes(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<serde_json::Value>> + Send + '_>>
    {
        Box::pin(async move {
            let mgr = self.mgr.lock().await;
            mgr.list()
                .into_iter()
                .map(|s| {
                    serde_json::json!({
                        "id": s.id.to_string(),
                        "status": format!("{:?}", s.status),
                        "policy_name": s.policy_name,
                        "pid": s.pid,
                        "proxy_addr": s.proxy_addr,
                        "gpu_worker": s.gpu_worker,
                    })
                })
                .collect()
        })
    }

    fn subscribe_output(
        &self,
        id: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<tokio::sync::broadcast::Receiver<Vec<u8>>>> + Send + '_>>
    {
        let id = id.to_string();
        Box::pin(async move {
            let sandbox_id: axis_core::types::SandboxId = id.parse().ok()?;
            let mgr = self.mgr.lock().await;
            mgr.subscribe_output(&sandbox_id)
        })
    }
}
