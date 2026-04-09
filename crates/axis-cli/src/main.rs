// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! AXIS CLI — command-line interface for managing sandboxed agent execution.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "axis", about = "AXIS: Agent eXecution Isolation Substrate")]
#[command(version)]
struct Cli {
    /// Path to axsd Unix socket.
    #[arg(long, global = true)]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create and start a new sandbox.
    Create {
        /// Path to the policy YAML file.
        #[arg(long)]
        policy: PathBuf,

        /// Command to execute inside the sandbox.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Execute a command in an existing sandbox.
    Exec {
        /// Sandbox ID.
        #[arg(long)]
        sandbox: String,

        /// Command to execute.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Destroy a running sandbox.
    Destroy {
        /// Sandbox ID.
        sandbox: String,
    },

    /// List running sandboxes.
    List,

    /// Policy management subcommands.
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },

    /// Model management subcommands.
    Model {
        #[command(subcommand)]
        action: ModelAction,
    },

    /// View sandbox logs (stdout/stderr and audit events).
    Logs {
        /// Sandbox ID.
        sandbox: String,

        /// Follow log output (tail -f style).
        #[arg(long, short)]
        follow: bool,

        /// Show only the last N lines.
        #[arg(long, short = 'n', default_value = "50")]
        tail: usize,
    },

    /// Run a command in a new sandbox (auto-starts daemon).
    /// Equivalent to: axis create + attach stdio + destroy on exit.
    Run {
        /// Path to the policy YAML file.
        #[arg(long, default_value = "minimal")]
        policy: String,

        /// Command to execute inside the sandbox.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Show inference server status.
    Inference {
        #[command(subcommand)]
        action: InferenceAction,
    },
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Validate a policy YAML file.
    Validate {
        /// Path to the policy file.
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum ModelAction {
    /// List registered models.
    List,
    /// Pull a model from HuggingFace.
    Pull { name: String },
    /// Remove a model.
    Remove { name: String },
}

#[derive(Subcommand)]
enum InferenceAction {
    /// Show live inference server status.
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("axis=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Create { policy, command } => {
            let policy_yaml = std::fs::read_to_string(&policy)?;

            // Validate policy before sending to daemon.
            let parsed = axis_core::policy::Policy::from_yaml(&policy_yaml)?;
            eprintln!("Policy '{}' validated successfully.", parsed.name);

            let (cmd, args) = command.split_first().expect("command required");

            let request = serde_json::json!({
                "type": "create",
                "policy_yaml": policy_yaml,
                "command": cmd,
                "args": args,
                "env": [],
            });

            let response = send_ipc(&cli.socket, &request).await?;
            if response["success"].as_bool() == Some(true) {
                let id = response["data"]["sandbox_id"].as_str().unwrap_or("unknown");
                println!("Sandbox created: {id}");
            } else {
                let err = response["error"].as_str().unwrap_or("unknown error");
                eprintln!("Error: {err}");
                std::process::exit(1);
            }
        }

        Commands::Logs { sandbox, follow, tail } => {
            // Read stdout/stderr logs from the sandbox workspace.
            let request = serde_json::json!({ "type": "list" });
            let response = send_ipc(&cli.socket, &request).await?;

            // Find sandbox workspace from the list.
            let workspace = response["data"].as_array()
                .and_then(|arr| arr.iter().find(|s| {
                    s["id"].as_str().map(|id| id.starts_with(&sandbox)).unwrap_or(false)
                }))
                .and_then(|s| s["workspace"].as_str())
                .map(|s| PathBuf::from(s));

            let workspace = match workspace {
                Some(ws) => ws,
                None => {
                    // Try the default workspace path.
                    let base = if let Ok(home) = std::env::var("HOME") {
                        PathBuf::from(home).join(".local/share/axis/sandboxes")
                    } else {
                        PathBuf::from("/tmp/axis/sandboxes")
                    };
                    base.join(&sandbox)
                }
            };

            let stdout_path = workspace.join("stdout.log");
            let stderr_path = workspace.join("stderr.log");

            if !stdout_path.exists() && !stderr_path.exists() {
                eprintln!("No logs found for sandbox '{sandbox}'");
                eprintln!("  Checked: {}", workspace.display());
                std::process::exit(1);
            }

            // Read and display logs.
            for (label, path) in [("stdout", &stdout_path), ("stderr", &stderr_path)] {
                if path.exists() {
                    let content = std::fs::read_to_string(path)?;
                    let lines: Vec<&str> = content.lines().collect();
                    let start = lines.len().saturating_sub(tail);
                    if !lines[start..].is_empty() {
                        println!("--- {label} ---");
                        for line in &lines[start..] {
                            println!("{line}");
                        }
                    }
                }
            }

            if follow {
                eprintln!("(following — press Ctrl+C to stop)");
                // Tail the stdout file.
                if stdout_path.exists() {
                    let mut last_size = std::fs::metadata(&stdout_path)?.len();
                    loop {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        let meta = std::fs::metadata(&stdout_path)?;
                        if meta.len() > last_size {
                            let file = std::fs::File::open(&stdout_path)?;
                            use std::io::{Read, Seek, SeekFrom};
                            let mut file = file;
                            file.seek(SeekFrom::Start(last_size))?;
                            let mut buf = String::new();
                            file.read_to_string(&mut buf)?;
                            print!("{buf}");
                            last_size = meta.len();
                        }
                    }
                }
            }
        }

        Commands::Exec { sandbox, command } => {
            let (cmd, args) = command.split_first().expect("command required");
            let request = serde_json::json!({
                "type": "exec",
                "sandbox_id": sandbox,
                "command": cmd,
                "args": args,
            });

            let response = send_ipc(&cli.socket, &request).await?;
            if response["success"].as_bool() == Some(true) {
                let code = response["data"]["exit_code"].as_i64().unwrap_or(0);
                if code != 0 {
                    eprintln!("Command exited with code {code}");
                }
                std::process::exit(code as i32);
            } else {
                let err = response["error"].as_str().unwrap_or("unknown error");
                eprintln!("Error: {err}");
                std::process::exit(1);
            }
        }

        Commands::Destroy { sandbox } => {
            let request = serde_json::json!({
                "type": "destroy",
                "sandbox_id": sandbox,
            });

            let response = send_ipc(&cli.socket, &request).await?;
            if response["success"].as_bool() == Some(true) {
                println!("Sandbox {sandbox} destroyed.");
            } else {
                let err = response["error"].as_str().unwrap_or("unknown error");
                eprintln!("Error: {err}");
                std::process::exit(1);
            }
        }

        Commands::List => {
            let request = serde_json::json!({ "type": "list" });
            let response = send_ipc(&cli.socket, &request).await?;

            if response["success"].as_bool() == Some(true) {
                let data = &response["data"];
                if let Some(arr) = data.as_array() {
                    if arr.is_empty() {
                        println!("No running sandboxes.");
                    } else {
                        println!("{:<38} {:<10} {:<8} {}", "ID", "STATUS", "PID", "WORKSPACE");
                        for s in arr {
                            println!(
                                "{:<38} {:<10} {:<8} {}",
                                s["id"].as_str().unwrap_or("-"),
                                s["status"].as_str().unwrap_or("-"),
                                s["pid"].as_u64().map(|p| p.to_string()).unwrap_or("-".into()),
                                s["workspace"].as_str().unwrap_or("-"),
                            );
                        }
                    }
                }
            }
        }

        Commands::Policy { action } => match action {
            PolicyAction::Validate { path } => {
                let yaml = std::fs::read_to_string(&path)?;
                match axis_core::policy::Policy::from_yaml(&yaml) {
                    Ok(policy) => {
                        println!("Policy '{}' is valid.", policy.name);
                        println!("  Filesystem: {} read-only, {} read-write, {} deny paths",
                            policy.filesystem.read_only.len(),
                            policy.filesystem.read_write.len(),
                            policy.filesystem.deny.len(),
                        );
                        println!("  Process: max {} processes, {}MB memory, {}% CPU",
                            policy.process.max_processes,
                            policy.process.max_memory_mb,
                            policy.process.cpu_rate_percent,
                        );
                        println!("  Network: {:?} mode, {} endpoint policies",
                            policy.network.mode,
                            policy.network.policies.len(),
                        );
                        println!("  Inference: {} routes", policy.inference.routes.len());
                        if policy.gpu.enabled {
                            println!("  GPU: device={}, transport={:?}, vram_limit={}",
                                policy.gpu.device,
                                policy.gpu.transport,
                                policy.gpu.vram_limit_mb
                                    .map(|m| format!("{m}MB"))
                                    .unwrap_or("unlimited".into()),
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("Policy validation failed: {e}");
                        std::process::exit(1);
                    }
                }
            }
        },

        Commands::Model { action } => match action {
            ModelAction::List => {
                let reg = axis_router::models::ModelRegistry::new();
                let models = reg.list();
                if models.is_empty() {
                    println!("No models registered. Use `axis model pull` to download one.");
                } else {
                    println!("{:<30} {:<12} {:<10} {}", "NAME", "FORMAT", "VRAM", "PATH");
                    for m in models {
                        println!("{:<30} {:<12} {:<10} {}",
                            m.name,
                            format!("{:?}", m.format).to_lowercase(),
                            m.vram_required_mb.map(|v| format!("{v}MB")).unwrap_or("-".into()),
                            m.local_path.as_ref().map(|p| p.display().to_string()).unwrap_or("-".into()),
                        );
                    }
                }
            }
            ModelAction::Pull { name } => {
                let mut reg = axis_router::models::ModelRegistry::new();
                eprintln!("Pulling model: {name}");
                match reg.pull(&name).await {
                    Ok(path) => {
                        println!("Model downloaded: {}", path.display());
                    }
                    Err(e) => {
                        eprintln!("Error: {e}");
                        std::process::exit(1);
                    }
                }
            }
            ModelAction::Remove { name } => {
                let mut reg = axis_router::models::ModelRegistry::new();
                if reg.remove(&name) {
                    println!("Model '{name}' removed from registry.");
                } else {
                    eprintln!("Model '{name}' not found in registry.");
                }
            }
        },

        Commands::Run { policy, command } => {
            // Resolve policy: check if it's a built-in name or a file path.
            let policy_yaml = if std::path::Path::new(&policy).exists() {
                std::fs::read_to_string(&policy)?
            } else {
                // Built-in policies.
                match policy.as_str() {
                    "minimal" => include_str!("../../../policies/minimal.yaml").to_string(),
                    "coding-agent" => include_str!("../../../policies/coding-agent.yaml").to_string(),
                    "gpu-agent" => include_str!("../../../policies/gpu-agent.yaml").to_string(),
                    _ => {
                        eprintln!("Policy '{policy}' not found. Use a file path or: minimal, coding-agent, gpu-agent");
                        std::process::exit(1);
                    }
                }
            };

            // Validate.
            let parsed = axis_core::policy::Policy::from_yaml(&policy_yaml)?;
            eprintln!("AXIS: sandbox '{}' starting...", parsed.name);

            // Try to connect to existing daemon, or start one inline.
            let (cmd, args) = command.split_first().expect("command required");

            let request = serde_json::json!({
                "type": "create",
                "policy_yaml": policy_yaml,
                "command": cmd,
                "args": args,
                "env": [],
            });

            match send_ipc(&cli.socket, &request).await {
                Ok(response) => {
                    if response["success"].as_bool() == Some(true) {
                        let id = response["data"]["sandbox_id"].as_str().unwrap_or("?");
                        eprintln!("AXIS: sandbox {id} running");
                        eprintln!("AXIS: press Ctrl+C to stop");

                        // Wait for Ctrl+C, then destroy.
                        tokio::signal::ctrl_c().await.ok();

                        eprintln!("\nAXIS: shutting down sandbox {id}...");
                        let destroy_req = serde_json::json!({
                            "type": "destroy",
                            "sandbox_id": id,
                        });
                        let _ = send_ipc(&cli.socket, &destroy_req).await;
                        eprintln!("AXIS: done.");
                    } else {
                        let err = response["error"].as_str().unwrap_or("unknown");
                        eprintln!("Error: {err}");
                        std::process::exit(1);
                    }
                }
                Err(_) => {
                    // Daemon not running — run sandbox directly (standalone mode).
                    eprintln!("AXIS: daemon not running, using standalone mode");

                    let policy = axis_core::policy::Policy::from_yaml(&policy_yaml)?;
                    let workspace = tempfile::tempdir()?;
                    let config = axis_sandbox::SandboxConfig {
                        id: axis_core::types::SandboxId::new(),
                        policy,
                        command: cmd.to_string(),
                        args: args.to_vec(),
                        working_dir: None,
                        workspace_dir: workspace.path().to_path_buf(),
                        env: vec![],
                        proxy_port: 13128,
                        capture_output: false, // standalone: inherit parent stdio
                        timeout_sec: None,
                    };

                    let mut sandbox = axis_sandbox::Sandbox::create(config)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    sandbox.start().map_err(|e| anyhow::anyhow!("{e}"))?;

                    eprintln!("AXIS: sandbox running (pid={}), Ctrl+C to stop",
                        sandbox.pid.unwrap_or(0));

                    // Wait for process or Ctrl+C.
                    tokio::select! {
                        code = sandbox.wait() => {
                            let code = code.map_err(|e| anyhow::anyhow!("{e}"))?;
                            std::process::exit(code);
                        }
                        _ = tokio::signal::ctrl_c() => {
                            eprintln!("\nAXIS: stopping...");
                            sandbox.destroy().map_err(|e| anyhow::anyhow!("{e}"))?;
                        }
                    }
                }
            }
        }

        Commands::Inference { action } => match action {
            InferenceAction::Status => {
                println!("Inference status not yet implemented.");
            }
        },
    }

    Ok(())
}

/// Send a JSON request to the axsd daemon via IPC.
/// Uses Unix sockets on Linux/macOS, TCP on Windows.
async fn send_ipc(
    socket_override: &Option<PathBuf>,
    request: &serde_json::Value,
) -> Result<serde_json::Value> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut json = serde_json::to_string(request)?;
    json.push('\n');

    #[cfg(unix)]
    {
        use tokio::net::UnixStream;

        let socket_path = socket_override.clone().unwrap_or_else(|| {
            if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
                PathBuf::from(xdg).join("axis").join("axsd.sock")
            } else {
                PathBuf::from("/tmp/axis-axsd.sock")
            }
        });

        let stream = UnixStream::connect(&socket_path).await.map_err(|e| {
            anyhow::anyhow!(
                "cannot connect to axsd at {}: {e}\nIs the daemon running? Start it with: axsd",
                socket_path.display()
            )
        })?;

        let (reader, mut writer) = stream.into_split();
        writer.write_all(json.as_bytes()).await?;

        let mut reader = BufReader::new(reader);
        let mut response = String::new();
        reader.read_line(&mut response).await?;
        Ok(serde_json::from_str(&response)?)
    }

    #[cfg(windows)]
    {
        use tokio::net::TcpStream;

        // On Windows, axsd listens on a TCP port (default 18516).
        let addr = socket_override
            .as_ref()
            .and_then(|p| p.to_str())
            .unwrap_or("127.0.0.1:18516");

        let stream = TcpStream::connect(addr).await.map_err(|e| {
            anyhow::anyhow!(
                "cannot connect to axsd at {addr}: {e}\nIs the daemon running? Start it with: axsd"
            )
        })?;

        let (reader, mut writer) = stream.into_split();
        writer.write_all(json.as_bytes()).await?;

        let mut reader = BufReader::new(reader);
        let mut response = String::new();
        reader.read_line(&mut response).await?;
        Ok(serde_json::from_str(&response)?)
    }
}
