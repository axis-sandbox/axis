// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox lifecycle manager — create, list, destroy sandboxes.
//!
//! Each sandbox gets:
//! 1. A workspace directory
//! 2. A dedicated proxy (AxisProxy) on a dynamic port when policy uses proxy mode
//! 3. An isolated child process with OS-native sandboxing
//! 4. Optionally, a HIP Remote GPU worker (when gpu.enabled)
//!
//! The proxy enforces OPA network policy and leak detection for proxy-mode sandboxes.

use axis_core::audit::{AuditEvent, AuditLog, BroadcastSink, TracingSink};
use axis_core::policy::{NetworkMode, Policy};
use axis_core::types::{SandboxId, SandboxStatus};
use axis_gateway::SandboxBackend;
use axis_gpu::api_filter::GpuPolicy as GpuFilterPolicy;
use axis_gpu::worker_mgr::WorkerManager;
use axis_proxy::proxy::{AxisProxy, ProxyConfig};
use axis_router::server_mgr::{InferenceServer, ManagedBackend, ServerMode};
use axis_sandbox::{Sandbox, SandboxConfig};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU16, Ordering};

/// Base port for dynamic proxy allocation.
const PROXY_PORT_BASE: u16 = 13100;
const EXEC_OUTPUT_DIR: &str = ".axis-exec";

/// Atomic counter for allocating unique proxy ports.
static NEXT_PORT: AtomicU16 = AtomicU16::new(PROXY_PORT_BASE);

/// State for a running sandbox (sandbox process + proxy + optional GPU worker).
struct ManagedSandbox {
    sandbox: Sandbox,
    policy: Policy,
    env: Vec<(String, String)>,
    proxy_addr: Option<SocketAddr>,
    proxy_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    gpu_enabled: bool,
    policy_name: String,
    /// Broadcast channel for streaming sandbox stdout to WebSocket clients.
    output_tx: Option<tokio::sync::broadcast::Sender<Vec<u8>>>,
    /// Buffered output for replay to late-connecting WebSocket clients.
    output_buffer: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    /// Channel for writing input to the sandbox's stdin.
    input_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
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

        // 2. Start the proxy only for proxy-mode policies.
        let (proxy_addr, proxy_shutdown) = if policy_uses_proxy(&policy) {
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

            let mut proxy = AxisProxy::new(proxy_config).map_err(|e| format!("proxy init: {e}"))?;
            let proxy_addr = proxy.bind().await.map_err(|e| format!("proxy bind: {e}"))?;

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

            (Some(proxy_addr), Some(shutdown_tx))
        } else {
            tracing::info!(
                "sandbox {id}: network proxy disabled for {:?} mode",
                policy.network.mode
            );
            (None, None)
        };

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

            match self
                .gpu_manager
                .spawn_worker(id, &gpu_filter_policy, &workspace_dir)
                .await
            {
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
                    tracing::warn!(
                        "sandbox {id}: GPU worker failed: {e} (sandbox will run without GPU)"
                    );
                }
            }
        }

        // 3. Create and start the sandbox process.
        let mut all_env = env;
        all_env.extend(extra_env);

        let timeout_sec = policy.process.timeout_sec;
        tracing::info!("sandbox {id}: spawning: {command} {}", args.join(" "));
        let config = SandboxConfig {
            id,
            policy: policy.clone(),
            command,
            args,
            working_dir: None,
            workspace_dir,
            env: all_env.clone(),
            proxy_port: proxy_addr.map(|addr| addr.port()).unwrap_or(0),
            proxy_addr,
            capture_output: true,
            timeout_sec,
        };

        let mut sandbox = match Sandbox::create(config) {
            Ok(sandbox) => sandbox,
            Err(e) => {
                shutdown_proxy(proxy_shutdown);
                return Err(e.to_string());
            }
        };
        if let Err(e) = sandbox.start() {
            shutdown_proxy(proxy_shutdown);
            return Err(format!("sandbox start: {e}"));
        }

        let gpu_label = if gpu_enabled { ", gpu=on" } else { "" };
        let proxy_label = proxy_addr
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "none".into());
        tracing::info!(
            "sandbox {id}: started (pid={}, proxy={proxy_label}, policy='{policy_name}'{gpu_label})",
            sandbox.pid.unwrap_or(0),
        );
        self.audit.sandbox_created(id, &policy_name);

        // Spawn background task to read output and broadcast to WebSocket clients.
        // Prefer ConPTY read handle (real terminal output with ANSI) over piped stdout.
        let (output_tx, _) = tokio::sync::broadcast::channel::<Vec<u8>>(256);
        let output_buffer = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        tracing::info!(
            "sandbox {id}: stdout={}, stderr={}, stdin={}, pty_read={}",
            sandbox.stdout.is_some(),
            sandbox.stderr.is_some(),
            sandbox.stdin.is_some(),
            sandbox.pty_read.is_some()
        );

        // Check for file-based output (Windows uses stdout.log in workspace).
        let stdout_log = sandbox.workspace_dir.join("stdout.log");
        if stdout_log.exists() && sandbox.stdout.is_none() {
            let tx = output_tx.clone();
            let buf_clone = output_buffer.clone();
            tokio::task::spawn_blocking(move || {
                use std::io::{BufRead, BufReader};
                let file = match std::fs::File::open(&stdout_log) {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::warn!("can't open stdout.log: {e}");
                        return;
                    }
                };
                let mut reader = BufReader::new(file);
                let mut eof_count = 0;
                loop {
                    let mut line = String::new();
                    match reader.read_line(&mut line) {
                        Ok(0) => {
                            // EOF — sleep and retry (tail -f).
                            eof_count += 1;
                            if eof_count > 600 {
                                break;
                            } // Stop after 60s of no data.
                            std::thread::sleep(std::time::Duration::from_millis(100));
                        }
                        Ok(_) => {
                            eof_count = 0;
                            let data = line.into_bytes();
                            if let Ok(mut b) = buf_clone.lock() {
                                b.push(data.clone());
                                if b.len() > 1000 {
                                    b.drain(..500);
                                }
                            }
                            if tx.send(data).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }

        if let Some(pty_read) = sandbox.pty_read.take() {
            // ConPTY pipe: use a blocking thread since Windows pipe handles
            // can't be used with tokio's async file I/O.
            let tx = output_tx.clone();
            tokio::task::spawn_blocking(move || {
                use std::io::Read;
                let mut reader = pty_read;
                let mut buf = [0u8; 4096];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let _ = tx.send(buf[..n].to_vec());
                        }
                        Err(_) => break,
                    }
                }
            });
        } else {
            // Fallback: piped stdout/stderr (non-TTY).
            if let Some(stdout) = sandbox.stdout.take() {
                let tx = output_tx.clone();
                let buf_clone = output_buffer.clone();
                tokio::task::spawn_blocking(move || {
                    use std::io::Read;
                    let mut stdout = stdout;
                    let mut buf = [0u8; 4096];
                    loop {
                        match stdout.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                let data = buf[..n].to_vec();
                                // Buffer for late-connecting clients.
                                if let Ok(mut b) = buf_clone.lock() {
                                    b.push(data.clone());
                                    // Cap buffer at 1000 chunks (~4MB).
                                    if b.len() > 1000 {
                                        b.drain(..500);
                                    }
                                }
                                let _ = tx.send(data);
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
            if let Some(stderr) = sandbox.stderr.take() {
                let tx = output_tx.clone();
                let buf_clone = output_buffer.clone();
                tokio::task::spawn_blocking(move || {
                    use std::io::Read;
                    let mut stderr = stderr;
                    let mut buf = [0u8; 4096];
                    loop {
                        match stderr.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                let data = buf[..n].to_vec();
                                if let Ok(mut b) = buf_clone.lock() {
                                    b.push(data.clone());
                                    if b.len() > 1000 {
                                        b.drain(..500);
                                    }
                                }
                                let _ = tx.send(data);
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        }

        // Set up stdin writer — spawn task that reads from channel and writes to child stdin.
        let (input_tx, mut input_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        if let Some(stdin) = sandbox.stdin.take() {
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                let mut stdin = tokio::process::ChildStdin::from_std(stdin).unwrap();
                while let Some(data) = input_rx.recv().await {
                    if stdin.write_all(&data).await.is_err() {
                        break;
                    }
                    if stdin.flush().await.is_err() {
                        break;
                    }
                }
            });
        }

        self.sandboxes.insert(
            id,
            ManagedSandbox {
                sandbox,
                policy,
                env: all_env,
                proxy_addr,
                proxy_shutdown,
                gpu_enabled,
                policy_name: policy_name.clone(),
                output_tx: Some(output_tx),
                output_buffer,
                input_tx: Some(input_tx),
            },
        );

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
            r.endpoint.is_some()
                && r.endpoint.as_ref().is_some_and(|e| {
                    e.starts_with("http://localhost") || e.starts_with("http://127.0.0.1")
                })
        });

        if local_route.is_none() && policy.inference.routes.is_empty() {
            return None;
        }

        // Try to find a model to serve.
        let registry = axis_router::models::ModelRegistry::new();
        let model_path = policy.inference.routes.iter().find_map(|r| {
            r.model.as_ref().and_then(|name| {
                registry
                    .get(name)
                    .and_then(|entry| entry.local_path.clone())
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
                tracing::info!(
                    "inference: server started on {addr} (model={})",
                    model_path.display()
                );
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
    /// The command runs with the same optional proxy env vars and working directory
    /// as the original sandbox process. On Linux, it inherits the sandbox's
    /// Landlock and seccomp restrictions via a fresh pre_exec application.
    pub async fn exec_in_sandbox(
        &self,
        id: &SandboxId,
        command: String,
        args: Vec<String>,
    ) -> Result<i32, String> {
        let managed = self
            .sandboxes
            .get(id)
            .ok_or_else(|| format!("sandbox not found: {id}"))?;

        let workspace = managed.sandbox.workspace_dir.clone();
        let config = contained_exec_config(managed, command.clone(), args.clone());
        let exec_workspace = config.workspace_dir.clone();

        tracing::info!("sandbox {id}: exec '{command}' in {}", workspace.display());

        let mut exec_sandbox = match Sandbox::create_for_exec(config) {
            Ok(sandbox) => sandbox,
            Err(e) => {
                cleanup_contained_exec_workspace(&exec_workspace);
                return Err(format!("exec sandbox create: {e}"));
            }
        };
        if let Err(e) = exec_sandbox.start() {
            let _ = exec_sandbox.destroy();
            cleanup_contained_exec_workspace(&exec_workspace);
            return Err(format!("exec sandbox start: {e}"));
        }
        let code = match exec_sandbox.wait().await {
            Ok(code) => code,
            Err(e) => {
                let _ = exec_sandbox.destroy();
                cleanup_contained_exec_workspace(&exec_workspace);
                return Err(format!("exec sandbox wait: {e}"));
            }
        };
        if let Err(e) = exec_sandbox.destroy() {
            cleanup_contained_exec_workspace(&exec_workspace);
            return Err(format!("exec sandbox cleanup: {e}"));
        }
        cleanup_contained_exec_workspace(&exec_workspace);

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
                    proxy_addr: m
                        .proxy_addr
                        .map(|addr| addr.to_string())
                        .unwrap_or_default(),
                    gpu_worker: gpu_info,
                }
            })
            .collect()
    }

    /// Get a sender for writing to a sandbox's stdin.
    pub fn get_input_sender(&self, id: &SandboxId) -> Option<tokio::sync::mpsc::Sender<Vec<u8>>> {
        self.sandboxes.get(id).and_then(|m| m.input_tx.clone())
    }

    /// Subscribe to a sandbox's stdout/stderr output stream.
    /// Returns (buffered_output, live_receiver) — caller should send the buffer first,
    /// then stream from the receiver for new data.
    pub fn subscribe_output(
        &self,
        id: &SandboxId,
    ) -> Option<(Vec<Vec<u8>>, tokio::sync::broadcast::Receiver<Vec<u8>>)> {
        self.sandboxes.get(id).and_then(|m| {
            let rx = m.output_tx.as_ref()?.subscribe();
            let buffer = m.output_buffer.lock().ok()?.clone();
            Some((buffer, rx))
        })
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

/// Collect essential environment variables for sandbox child processes.
/// Mirrors the logic from axis-cli's env passthrough.
fn collect_sandbox_env() -> Vec<(String, String)> {
    let mut env = Vec::new();
    for (key, val) in std::env::vars() {
        let key_cmp = if cfg!(windows) {
            key.to_uppercase()
        } else {
            key.clone()
        };
        // Skip internal session tracking vars but keep all auth vars
        // (CLAUDE_CODE_OAUTH_TOKEN, CLAUDE_CODE_ENTRYPOINT, etc.)
        if matches!(key_cmp.as_str(), "CLAUDECODE" | "CLAUDE_AGENT_SDK_VERSION") {
            continue;
        }

        if key_cmp.starts_with("ANTHROPIC_")
            || key_cmp.starts_with("OPENAI_")
            || key_cmp.starts_with("CLAUDE_")
            || matches!(
                key_cmp.as_str(),
                "HOME"
                    | "USER"
                    | "PATH"
                    | "LANG"
                    | "TERM"
                    | "SHELL"
                    | "TMPDIR"
                    | "XDG_RUNTIME_DIR"
                    | "XDG_CONFIG_HOME"
                    | "XDG_DATA_HOME"
                    | "XDG_CACHE_HOME"
                    | "SYSTEMROOT"
                    | "SYSTEMDRIVE"
                    | "WINDIR"
                    | "TEMP"
                    | "TMP"
                    | "USERPROFILE"
                    | "APPDATA"
                    | "LOCALAPPDATA"
                    | "PROGRAMDATA"
                    | "PROGRAMFILES"
                    | "PROGRAMFILES(X86)"
                    | "COMPUTERNAME"
                    | "USERNAME"
                    | "NUMBER_OF_PROCESSORS"
                    | "PROCESSOR_ARCHITECTURE"
                    | "PATHEXT"
                    | "COMSPEC"
                    | "OS"
                    | "HOMEDRIVE"
                    | "HOMEPATH"
            )
        {
            env.push((key, val));
        }
    }
    // Remove empty ANTHROPIC_API_KEY — it overrides valid OAuth auth.
    env.retain(|(k, v)| !(k.eq_ignore_ascii_case("ANTHROPIC_API_KEY") && v.is_empty()));

    env
}

fn allocate_port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::Relaxed)
}

fn policy_uses_proxy(policy: &Policy) -> bool {
    matches!(policy.network.mode, NetworkMode::Proxy)
}

fn shutdown_proxy(tx: Option<tokio::sync::oneshot::Sender<()>>) {
    if let Some(tx) = tx {
        let _ = tx.send(());
    }
}

fn apply_proxy_env(cmd: &mut std::process::Command, proxy_addr: Option<SocketAddr>) {
    let Some(proxy_addr) = proxy_addr else {
        return;
    };
    let proxy_url = format!("http://127.0.0.1:{}", proxy_addr.port());
    cmd.env("HTTP_PROXY", &proxy_url)
        .env("HTTPS_PROXY", &proxy_url)
        .env("http_proxy", &proxy_url)
        .env("https_proxy", &proxy_url);
}

fn contained_exec_config(
    managed: &ManagedSandbox,
    command: String,
    args: Vec<String>,
) -> SandboxConfig {
    contained_exec_config_from(
        &managed.policy,
        &managed.sandbox.workspace_dir,
        &managed.env,
        managed.proxy_addr,
        command,
        args,
    )
}

fn contained_exec_config_from(
    policy: &Policy,
    workspace_dir: &Path,
    env: &[(String, String)],
    proxy_addr: Option<SocketAddr>,
    command: String,
    args: Vec<String>,
) -> SandboxConfig {
    let exec_id = SandboxId::new();
    let exec_workspace = contained_exec_workspace_dir(workspace_dir, exec_id);
    let mut policy = policy.clone();
    let workspace_policy_path = workspace_dir.to_string_lossy().into_owned();
    if !policy
        .filesystem
        .read_write
        .iter()
        .any(|path| path == &workspace_policy_path)
    {
        policy.filesystem.read_write.push(workspace_policy_path);
    }
    let timeout_sec = policy.process.timeout_sec;

    SandboxConfig {
        id: exec_id,
        policy,
        command,
        args,
        working_dir: Some(workspace_dir.to_path_buf()),
        workspace_dir: exec_workspace,
        env: env.to_vec(),
        proxy_port: proxy_addr.map(|addr| addr.port()).unwrap_or(0),
        proxy_addr,
        capture_output: true,
        timeout_sec,
    }
}

fn contained_exec_workspace_dir(workspace_dir: &Path, exec_id: SandboxId) -> PathBuf {
    workspace_dir
        .join(EXEC_OUTPUT_DIR)
        .join(exec_id.to_string())
}

fn cleanup_contained_exec_workspace(path: &Path) {
    match std::fs::remove_dir_all(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!("failed to remove exec workspace {}: {e}", path.display()),
    }
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
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../hip-remote/build-worker/hip-worker"
        ),
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
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + '_>>
    {
        let policy_yaml = policy_yaml.to_string();
        // Collect essential env vars for the sandbox (same logic as axis-cli).
        let env = collect_sandbox_env();
        let claude_vars: Vec<_> = env
            .iter()
            .filter(|(k, _)| {
                k.to_uppercase().contains("CLAUDE") || k.to_uppercase().contains("ANTHROPIC")
            })
            .map(|(k, v)| format!("{}={}...", k, &v[..v.len().min(20)]))
            .collect();
        tracing::info!(
            "gateway create_sandbox: {} env vars, auth: {:?}",
            env.len(),
            claude_vars
        );
        Box::pin(async move {
            let policy = axis_core::policy::Policy::from_yaml(&policy_yaml)
                .map_err(|e| format!("invalid policy: {e}"))?;
            let mut mgr = self.mgr.lock().await;
            let id = mgr.create(policy, command, args, env).await?;
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
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Option<(Vec<Vec<u8>>, tokio::sync::broadcast::Receiver<Vec<u8>>)>,
                > + Send
                + '_,
        >,
    > {
        let id = id.to_string();
        Box::pin(async move {
            let sandbox_id: axis_core::types::SandboxId = id.parse().ok()?;
            let mgr = self.mgr.lock().await;
            mgr.subscribe_output(&sandbox_id)
        })
    }

    fn send_input(
        &self,
        id: &str,
        data: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        let id = id.to_string();
        Box::pin(async move {
            let sandbox_id: axis_core::types::SandboxId = id
                .parse()
                .map_err(|_| format!("invalid sandbox id: {id}"))?;
            let mgr = self.mgr.lock().await;
            let tx = mgr
                .get_input_sender(&sandbox_id)
                .ok_or_else(|| "sandbox not found or stdin not available".to_string())?;
            tx.send(data).await.map_err(|e| format!("stdin send: {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axis_core::policy::{
        FilesystemPolicy, GpuPolicy, InferencePolicy, NetworkPolicy, ProcessPolicy, SshPolicy,
    };

    #[test]
    fn block_mode_does_not_use_daemon_proxy() {
        let policy = test_policy(NetworkMode::Block);

        assert!(!policy_uses_proxy(&policy));
    }

    #[test]
    fn proxy_mode_uses_daemon_proxy() {
        let policy = test_policy(NetworkMode::Proxy);

        assert!(policy_uses_proxy(&policy));
    }

    #[test]
    fn apply_proxy_env_is_noop_without_proxy_addr() {
        let mut cmd = std::process::Command::new("true");

        apply_proxy_env(&mut cmd, None);

        assert!(
            cmd.get_envs()
                .all(|(key, _)| !key.to_string_lossy().eq_ignore_ascii_case("http_proxy"))
        );
    }

    #[test]
    fn apply_proxy_env_sets_proxy_vars_when_proxy_addr_exists() {
        let mut cmd = std::process::Command::new("true");
        let proxy_addr: SocketAddr = "127.0.0.1:3128".parse().unwrap();

        apply_proxy_env(&mut cmd, Some(proxy_addr));

        let envs: Vec<_> = cmd
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            assert_eq!(
                envs.iter()
                    .find(|(env_key, _)| env_key == key)
                    .and_then(|(_, value)| value.as_deref()),
                Some("http://127.0.0.1:3128")
            );
        }
    }

    #[test]
    fn contained_exec_config_for_block_mode_omits_proxy_state() {
        let workspace = std::env::temp_dir().join("axis-daemon-block-exec-test");
        let policy = test_policy(NetworkMode::Block);

        let config = contained_exec_config_from(
            &policy,
            &workspace,
            &[("PATH".into(), "/bin".into())],
            None,
            "true".into(),
            Vec::new(),
        );

        assert!(matches!(config.policy.network.mode, NetworkMode::Block));
        assert_eq!(config.proxy_port, 0);
        assert!(config.proxy_addr.is_none());
        assert_eq!(config.working_dir.as_deref(), Some(workspace.as_path()));
        assert_ne!(config.workspace_dir, workspace);
        assert!(
            config
                .workspace_dir
                .starts_with(workspace.join(EXEC_OUTPUT_DIR))
        );
        assert!(
            config
                .policy
                .filesystem
                .read_write
                .contains(&workspace.to_string_lossy().into_owned())
        );
        assert!(config.capture_output);
    }

    #[test]
    fn contained_exec_config_for_proxy_mode_retains_proxy_state() {
        let workspace = std::env::temp_dir().join("axis-daemon-proxy-exec-test");
        let policy = test_policy(NetworkMode::Proxy);
        let proxy_addr: SocketAddr = "127.0.0.1:3128".parse().unwrap();

        let config = contained_exec_config_from(
            &policy,
            &workspace,
            &[("PATH".into(), "/bin".into())],
            Some(proxy_addr),
            "true".into(),
            Vec::new(),
        );

        assert!(matches!(config.policy.network.mode, NetworkMode::Proxy));
        assert_eq!(config.proxy_port, 3128);
        assert_eq!(config.proxy_addr, Some(proxy_addr));
        assert_eq!(config.working_dir.as_deref(), Some(workspace.as_path()));
        assert_ne!(config.workspace_dir, workspace);
        assert!(
            config
                .workspace_dir
                .starts_with(workspace.join(EXEC_OUTPUT_DIR))
        );
    }

    #[test]
    fn contained_exec_config_does_not_duplicate_workspace_policy_path() {
        let workspace = std::env::temp_dir().join("axis-daemon-exec-policy-test");
        let workspace_policy_path = workspace.to_string_lossy().into_owned();
        let mut policy = test_policy(NetworkMode::Block);
        policy
            .filesystem
            .read_write
            .push(workspace_policy_path.clone());

        let config =
            contained_exec_config_from(&policy, &workspace, &[], None, "true".into(), Vec::new());

        assert_eq!(
            config
                .policy
                .filesystem
                .read_write
                .iter()
                .filter(|path| *path == &workspace_policy_path)
                .count(),
            1
        );
    }

    #[test]
    fn cleanup_contained_exec_workspace_removes_only_exec_workspace() {
        let workspace = std::env::temp_dir().join(format!(
            "axis-daemon-exec-cleanup-test-{}",
            SandboxId::new()
        ));
        let _ = std::fs::remove_dir_all(&workspace);
        let exec_workspace = contained_exec_workspace_dir(&workspace, SandboxId::new());
        std::fs::create_dir_all(&exec_workspace).unwrap();
        std::fs::write(exec_workspace.join("stdout.log"), b"exec output").unwrap();

        cleanup_contained_exec_workspace(&exec_workspace);

        assert!(workspace.exists());
        assert!(!exec_workspace.exists());
        std::fs::remove_dir_all(&workspace).unwrap();
    }

    fn test_policy(network_mode: NetworkMode) -> Policy {
        Policy {
            version: 1,
            name: "test-policy".into(),
            filesystem: FilesystemPolicy::default(),
            process: ProcessPolicy::default(),
            network: NetworkPolicy {
                mode: network_mode,
                policies: Vec::new(),
            },
            inference: InferencePolicy::default(),
            gpu: GpuPolicy::default(),
            ssh: SshPolicy::default(),
            amd: None,
        }
    }
}
