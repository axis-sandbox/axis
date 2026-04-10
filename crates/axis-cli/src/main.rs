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
    /// Path to axisd Unix socket.
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

    /// Install agent runtimes into contained ~/.axis/tools/ directory.
    Install {
        /// Agents to install (or --all).
        #[arg(trailing_var_arg = true)]
        agents: Vec<String>,

        /// Install all supported agents.
        #[arg(long)]
        all: bool,

        /// List available agents.
        #[arg(long)]
        list: bool,

        /// Wrap system-installed binaries instead of downloading new copies.
        #[arg(long)]
        use_system: bool,
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
    // Git-style subcommand extension: if the first arg matches a wrapper
    // in ~/.axis/bin/, execute it directly. This lets `axis claude ...`
    // work as `claude ...` through the AXIS sandbox.
    if let Some(result) = try_agent_subcommand() {
        std::process::exit(result);
    }

    // Suppress logging when stdin is a TTY and we're running an agent
    // (the TUI agent would be confused by JSON log lines on stderr).
    let is_interactive = std::io::IsTerminal::is_terminal(&std::io::stdin());
    let is_run_cmd = std::env::args().nth(1).as_deref() == Some("run");
    let quiet = is_interactive && is_run_cmd && std::env::var("AXIS_LOG").is_err();

    if quiet {
        // Minimal logging — only errors.
        tracing_subscriber::fmt()
            .with_env_filter("axis=error")
            .with_writer(std::io::stderr)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive("axis=info".parse()?),
            )
            .init();
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Install { agents, all, list, use_system } => {
            // Install bundled policies.
            // On Windows: %LOCALAPPDATA%\axis (matches PS1 installer).
            // On Unix: ~/.axis
            let axis_root = if cfg!(windows) {
                PathBuf::from(
                    std::env::var("LOCALAPPDATA").unwrap_or_else(|_|
                        std::env::var("USERPROFILE").unwrap_or("C:\\Users\\Public".into())
                    )
                ).join("axis")
            } else {
                PathBuf::from(
                    std::env::var("HOME").unwrap_or("/tmp".into())
                ).join(".axis")
            };
            let pol_dir = axis_root.join("policies").join("agents");
            std::fs::create_dir_all(&pol_dir)?;
            for (name, content) in [
                ("base-deny.yaml", include_str!("../../../policies/agents/base-deny.yaml")),
                ("claude-code.yaml", include_str!("../../../policies/agents/claude-code.yaml")),
                ("claude-code-ssh.yaml", include_str!("../../../policies/agents/claude-code-ssh.yaml")),
                ("codex.yaml", include_str!("../../../policies/agents/codex.yaml")),
                ("openclaw.yaml", include_str!("../../../policies/agents/openclaw.yaml")),
                ("ironclaw.yaml", include_str!("../../../policies/agents/ironclaw.yaml")),
                ("nanoclaw.yaml", include_str!("../../../policies/agents/nanoclaw.yaml")),
                ("zeroclaw.yaml", include_str!("../../../policies/agents/zeroclaw.yaml")),
                ("hermes.yaml", include_str!("../../../policies/agents/hermes.yaml")),
            ] {
                let _ = std::fs::write(pol_dir.join(name), content);
            }

            #[cfg(unix)]
            {
                let install_script = include_str!("../../../e2e/agents/install_agents.sh");
                let script_path = std::env::temp_dir().join("axis-install-agents.sh");
                std::fs::write(&script_path, install_script)?;

                let mut cmd = std::process::Command::new("bash");
                cmd.arg(&script_path);
                if use_system { cmd.arg("--use-system"); }
                if list { cmd.arg("--list"); }
                else if all { cmd.arg("--all"); }
                else if agents.is_empty() { cmd.arg("--help"); }
                else { cmd.args(&agents); }

                let status = cmd.status()?;
                let _ = std::fs::remove_file(&script_path);
                std::process::exit(status.code().unwrap_or(1));
            }

            #[cfg(windows)]
            {
                let install_script = include_str!("../../../e2e/agents/install_agents.ps1");
                let script_path = std::env::temp_dir().join("axis-install-agents.ps1");
                std::fs::write(&script_path, install_script)?;

                let mut cmd = std::process::Command::new("powershell");
                cmd.args(["-ExecutionPolicy", "Bypass", "-Command"]);

                // Build the PowerShell command string.
                let mut ps_cmd = format!("& '{}'", script_path.display());
                if list { ps_cmd.push_str(" -List"); }
                else if all { ps_cmd.push_str(" -All"); }
                else if !agents.is_empty() {
                    ps_cmd.push_str(&format!(" -Agents @('{}')", agents.join("','")));
                }
                cmd.arg(&ps_cmd);

                let status = cmd.status()?;
                let _ = std::fs::remove_file(&script_path);
                std::process::exit(status.code().unwrap_or(1));
            }
        }

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
            if !is_interactive {
                eprintln!("AXIS: sandbox '{}' starting...", parsed.name);
            }

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
                    let quiet = std::io::IsTerminal::is_terminal(&std::io::stdin());
                    if !quiet { eprintln!("AXIS: daemon not running, using standalone mode"); }

                    let policy = axis_core::policy::Policy::from_yaml(&policy_yaml)?;
                    let sandbox_id = axis_core::types::SandboxId::new();
                    let workspace = tempfile::tempdir()?;

                    // Start an inline proxy if policy uses proxy mode.
                    let proxy_port = match policy.network.mode {
                        axis_core::policy::NetworkMode::Proxy => {
                            let proxy_config = axis_proxy::proxy::ProxyConfig {
                                sandbox_id,
                                bind_addr: "127.0.0.1:0".parse().unwrap(),
                                policy: policy.clone(),
                                enable_l7: false,
                                enable_leak_detection: true,
                                inference_endpoint: None,
                            };
                            let mut proxy = axis_proxy::proxy::AxisProxy::new(proxy_config)
                                .map_err(|e| anyhow::anyhow!("proxy: {e}"))?;
                            let addr = proxy.bind().await
                                .map_err(|e| anyhow::anyhow!("proxy bind: {e}"))?;
                            if !quiet { eprintln!("AXIS: proxy on {addr}"); }
                            tokio::spawn(async move { let _ = proxy.run().await; });
                            addr.port()
                        }
                        _ => 0,
                    };

                    // Pass through env vars from parent.
                    // All ANTHROPIC_* vars (API key, base URL, etc.) and essential system vars.
                    let mut env: Vec<(String, String)> = Vec::new();
                    for (key, val) in std::env::vars() {
                        if key.starts_with("ANTHROPIC_")
                            || key.starts_with("OPENAI_")
                            || matches!(key.as_str(), "HOME" | "USER" | "PATH" | "LANG"
                                | "TERM" | "SHELL" | "TMPDIR" | "XDG_RUNTIME_DIR"
                                | "XDG_CONFIG_HOME" | "XDG_DATA_HOME" | "XDG_CACHE_HOME")
                        {
                            env.push((key, val));
                        }
                    }

                    let config = axis_sandbox::SandboxConfig {
                        id: sandbox_id,
                        policy,
                        command: cmd.to_string(),
                        args: args.to_vec(),
                        working_dir: None,
                        workspace_dir: workspace.path().to_path_buf(),
                        env,
                        proxy_port,
                        capture_output: false,
                        timeout_sec: None,
                    };

                    let mut sandbox = axis_sandbox::Sandbox::create(config)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    sandbox.start().map_err(|e| anyhow::anyhow!("{e}"))?;

                    if !quiet {
                        eprintln!("AXIS: sandbox running (pid={}), Ctrl+C to stop",
                            sandbox.pid.unwrap_or(0));
                    }

                    if quiet {
                        // Interactive mode: just wait for the child to exit.
                        // Don't install tokio signal handlers — they steal the
                        // TTY from the child process and break TUI apps like
                        // Claude Code (setRawMode fails).
                        let code = sandbox.wait().await
                            .map_err(|e| anyhow::anyhow!("{e}"))?;
                        sandbox.destroy().ok();
                        std::process::exit(code);
                    } else {
                        // Non-interactive: wait for process or Ctrl+C.
                        tokio::select! {
                            code = sandbox.wait() => {
                                let code = code.map_err(|e| anyhow::anyhow!("{e}"))?;
                                std::process::exit(code);
                            }
                            _ = tokio::signal::ctrl_c() => {
                                sandbox.destroy().map_err(|e| anyhow::anyhow!("{e}"))?;
                            }
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

/// Git-style subcommand extension.
///
/// If `axis claude -p "hello"` is run and "claude" is not a built-in
/// subcommand, check ~/.axis/bin/claude for a wrapper. If found, exec it
/// with the remaining args. This lets `axis <agent> [args]` work for any
/// installed agent.
fn try_agent_subcommand() -> Option<i32> {
    let args: Vec<String> = std::env::args().collect();

    // Need at least: axis <subcommand>
    if args.len() < 2 {
        return None;
    }

    let subcmd = &args[1];

    // Skip if it's a built-in command, a flag, or --help/--version.
    if subcmd.starts_with('-') {
        return None;
    }
    let builtins = [
        "create", "exec", "destroy", "list", "logs", "run", "install",
        "policy", "model", "inference", "help",
    ];
    if builtins.contains(&subcmd.as_str()) {
        return None;
    }

    // Look for wrapper in ~/.axis/bin/<subcmd>.
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()?;
    let wrapper = std::path::PathBuf::from(&home)
        .join(".axis")
        .join("bin")
        .join(subcmd);

    if !wrapper.exists() || !wrapper.is_file() {
        // Wrapper not found — check if this is a known agent and offer to install.
        return try_prompt_install(subcmd);
    }

    // Found a wrapper — exec it with remaining args.
    let agent_args: Vec<&str> = args[2..].iter().map(|s| s.as_str()).collect();

    let status = std::process::Command::new(&wrapper)
        .args(&agent_args)
        .env("AXIS_BIN", std::env::current_exe().unwrap_or_default())
        .status()
        .ok()?;

    Some(status.code().unwrap_or(1))
}

/// Known agent binary names → install names.
fn known_agent(binary_name: &str) -> Option<&'static str> {
    match binary_name {
        "claude"   => Some("claude-code"),
        "codex"    => Some("codex"),
        "openclaw" => Some("openclaw"),
        "ironclaw" => Some("ironclaw"),
        "aider"    => Some("aider"),
        "goose"    => Some("goose"),
        _ => None,
    }
}

/// Prompt to install a known but not-yet-installed agent.
fn try_prompt_install(subcmd: &str) -> Option<i32> {
    let install_name = known_agent(subcmd)?;

    eprintln!("'{subcmd}' is not installed. Install it with AXIS sandbox protection?\n");
    eprintln!("  This will:");
    eprintln!("    - Install {subcmd} to ~/.axis/tools/{install_name}/");
    eprintln!("    - Create a sandboxed wrapper at ~/.axis/bin/{subcmd}");
    eprintln!("    - Apply default-deny network + filesystem policy");
    eprintln!();
    eprint!("Install {subcmd}? [Y/n] ");

    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return Some(1);
    }

    let answer = input.trim().to_lowercase();
    if answer.is_empty() || answer == "y" || answer == "yes" {
        // Run axis install <agent>.
        let axis_bin = std::env::current_exe().unwrap_or_else(|_| "axis".into());
        let status = std::process::Command::new(&axis_bin)
            .args(["install", install_name])
            .status()
            .ok()?;

        if !status.success() {
            return Some(status.code().unwrap_or(1));
        }

        // After install, retry the original command.
        eprintln!("\nRunning: {subcmd} {}", std::env::args().skip(2).collect::<Vec<_>>().join(" "));
        let args: Vec<String> = std::env::args().collect();
        let agent_args: Vec<&str> = args[2..].iter().map(|s| s.as_str()).collect();

        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .ok()?;
        let wrapper = std::path::PathBuf::from(&home)
            .join(".axis")
            .join("bin")
            .join(subcmd);

        if wrapper.exists() {
            let status = std::process::Command::new(&wrapper)
                .args(&agent_args)
                .env("AXIS_BIN", &axis_bin)
                .status()
                .ok()?;
            Some(status.code().unwrap_or(1))
        } else {
            eprintln!("Install succeeded but wrapper not found at {}", wrapper.display());
            Some(1)
        }
    } else {
        eprintln!("Not installing. To install manually: axis install {install_name}");
        Some(0)
    }
}

/// Send a JSON request to the axisd daemon via IPC.
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
                PathBuf::from(xdg).join("axis").join("axisd.sock")
            } else {
                PathBuf::from("/tmp/axis-axisd.sock")
            }
        });

        let stream = UnixStream::connect(&socket_path).await.map_err(|e| {
            anyhow::anyhow!(
                "cannot connect to axisd at {}: {e}\nIs the daemon running? Start it with: axisd",
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

        // On Windows, axisd listens on a TCP port (default 18516).
        let addr = socket_override
            .as_ref()
            .and_then(|p| p.to_str())
            .unwrap_or("127.0.0.1:18516");

        let stream = TcpStream::connect(addr).await.map_err(|e| {
            anyhow::anyhow!(
                "cannot connect to axisd at {addr}: {e}\nIs the daemon running? Start it with: axisd"
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
