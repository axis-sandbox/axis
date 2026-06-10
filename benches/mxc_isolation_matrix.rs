// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Exercise MXC backend/network-mode combinations on the current host.

use axis_core::policy::Policy;
use axis_core::types::SandboxId;
use axis_sandbox::{Sandbox, SandboxConfig};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

const DEFAULT_ITERATIONS: u64 = 3;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const ALLOW_HOST: &str = "api.github.com";
const DENIED_HOST: &str = "example.com";
const DENIED_PORT: u16 = 443;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iterations = std::env::var("AXIS_MXC_MATRIX_ITERS")
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(DEFAULT_ITERATIONS);
    if iterations == 0 {
        return Err("AXIS_MXC_MATRIX_ITERS must be greater than zero".into());
    }

    let mxc = run_mxc_matrix(iterations).await?;
    let axis_native = run_axis_native_filesystem_boundary().await;
    let report = MatrixReport {
        current_platform: std::env::consts::OS,
        iterations,
        mxc,
        axis_native,
    };
    serde_json::to_writer_pretty(std::io::stdout().lock(), &report)?;
    println!();
    Ok(())
}

#[derive(Debug, Serialize)]
struct MatrixReport {
    current_platform: &'static str,
    iterations: u64,
    mxc: MxcMatrixSection,
    axis_native: AxisNativeSection,
}

#[derive(Debug, Serialize)]
struct MxcMatrixSection {
    enabled: bool,
    executor: Option<String>,
    reason: Option<String>,
    rows: Vec<MatrixRow>,
}

#[derive(Debug, Serialize)]
struct AxisNativeSection {
    rows: Vec<MatrixRow>,
}

#[derive(Debug, Serialize)]
struct MatrixRow {
    backend: &'static str,
    containment: &'static str,
    backend_class: &'static str,
    mode: &'static str,
    category: &'static str,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    expected_markers: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics: Option<RowMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stdout_excerpt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stderr_excerpt: Option<String>,
}

#[derive(Debug, Serialize)]
struct RowMetrics {
    sandbox_wall_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_iterations: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_total_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requests_per_sec: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ns_per_request: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    denied_responses: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MxcBackend {
    Bubblewrap,
    Lxc,
    Microvm,
    Hyperlight,
}

impl MxcBackend {
    fn linux_backends() -> Vec<Self> {
        if cfg!(target_os = "linux") {
            vec![Self::Bubblewrap, Self::Lxc, Self::Microvm, Self::Hyperlight]
        } else {
            Vec::new()
        }
    }

    fn from_filter_token(token: &str) -> Option<Self> {
        match token {
            "bubblewrap" | "bwrap" | "mxc-linux-bubblewrap" => Some(Self::Bubblewrap),
            "lxc" | "mxc-linux-lxc" => Some(Self::Lxc),
            "microvm" | "mxc-linux-microvm" => Some(Self::Microvm),
            "hyperlight" | "mxc-linux-hyperlight" => Some(Self::Hyperlight),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Bubblewrap => "mxc-linux-bubblewrap",
            Self::Lxc => "mxc-linux-lxc",
            Self::Microvm => "mxc-linux-microvm",
            Self::Hyperlight => "mxc-linux-hyperlight",
        }
    }

    fn containment(self) -> &'static str {
        match self {
            Self::Bubblewrap => "bubblewrap",
            Self::Lxc => "lxc",
            Self::Microvm => "microvm",
            Self::Hyperlight => "hyperlight",
        }
    }

    fn backend_class(self) -> &'static str {
        match self {
            Self::Bubblewrap => "process",
            Self::Lxc => "container",
            Self::Microvm | Self::Hyperlight => "vm",
        }
    }

    fn command_family(self) -> CommandFamily {
        match self {
            Self::Bubblewrap | Self::Lxc => CommandFamily::PosixShell,
            Self::Microvm | Self::Hyperlight => CommandFamily::PythonSource,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum CommandFamily {
    PosixShell,
    PythonSource,
}

#[derive(Debug, Clone, Copy)]
enum NetworkScenario {
    AllowControl,
    DefaultBlock,
    HostFilterCapabilities,
    HostFilterFirewall,
    HostFilterBoth,
    ProxyLocalhost,
    ProxyUrl,
    ProxyBuiltinTestServer,
}

impl NetworkScenario {
    fn all() -> Vec<Self> {
        vec![
            Self::AllowControl,
            Self::DefaultBlock,
            Self::HostFilterCapabilities,
            Self::HostFilterFirewall,
            Self::HostFilterBoth,
            Self::ProxyLocalhost,
            Self::ProxyUrl,
            Self::ProxyBuiltinTestServer,
        ]
    }

    fn mode(self) -> &'static str {
        match self {
            Self::AllowControl => "network.defaultPolicy.allow",
            Self::DefaultBlock => "network.defaultPolicy.block",
            Self::HostFilterCapabilities => "network.enforcementMode.capabilities",
            Self::HostFilterFirewall => "network.enforcementMode.firewall",
            Self::HostFilterBoth => "network.enforcementMode.both",
            Self::ProxyLocalhost => "network.proxy.localhost",
            Self::ProxyUrl => "network.proxy.url",
            Self::ProxyBuiltinTestServer => "network.proxy.builtinTestServer",
        }
    }

    fn category(self) -> &'static str {
        match self {
            Self::AllowControl => "baseline",
            Self::DefaultBlock => "strict_network",
            Self::HostFilterCapabilities | Self::HostFilterFirewall | Self::HostFilterBoth => {
                "host_filter"
            }
            Self::ProxyLocalhost | Self::ProxyUrl | Self::ProxyBuiltinTestServer => "proxy",
        }
    }

    fn expected_markers(self) -> Vec<&'static str> {
        match self {
            Self::AllowControl => vec!["MXC_MATRIX_ALLOW_CONTROL_OK"],
            Self::DefaultBlock => vec!["MXC_MATRIX_DEFAULT_BLOCK_OK"],
            Self::HostFilterCapabilities | Self::HostFilterFirewall | Self::HostFilterBoth => {
                vec!["MXC_MATRIX_ALLOWLIST_OK", "MXC_MATRIX_DENYLIST_OK"]
            }
            Self::ProxyLocalhost | Self::ProxyUrl => vec!["MXC_MATRIX_PROXY_DENY_OK"],
            Self::ProxyBuiltinTestServer => {
                vec!["MXC_MATRIX_PROXY_ALLOW_OK", "MXC_MATRIX_PROXY_DENY_OK"]
            }
        }
    }

    fn is_proxy(self) -> bool {
        matches!(
            self,
            Self::ProxyLocalhost | Self::ProxyUrl | Self::ProxyBuiltinTestServer
        )
    }

    fn network_json(self, runtime: &ScenarioRuntime) -> Value {
        match self {
            Self::AllowControl => json!({ "defaultPolicy": "allow" }),
            Self::DefaultBlock => json!({ "defaultPolicy": "block" }),
            Self::HostFilterCapabilities => json!({
                "defaultPolicy": "block",
                "enforcementMode": "capabilities",
                "allowedHosts": [ALLOW_HOST]
            }),
            Self::HostFilterFirewall => json!({
                "defaultPolicy": "block",
                "enforcementMode": "firewall",
                "allowedHosts": [ALLOW_HOST]
            }),
            Self::HostFilterBoth => json!({
                "defaultPolicy": "block",
                "enforcementMode": "both",
                "allowedHosts": [ALLOW_HOST]
            }),
            Self::ProxyLocalhost => {
                let proxy = runtime
                    .external_proxy_addr
                    .expect("external proxy must be started for localhost mode");
                json!({
                    "defaultPolicy": "allow",
                    "proxy": { "localhost": proxy.port() }
                })
            }
            Self::ProxyUrl => {
                let proxy = runtime
                    .external_proxy_addr
                    .expect("external proxy must be started for url mode");
                json!({
                    "defaultPolicy": "allow",
                    "proxy": { "url": format!("http://{}", proxy) }
                })
            }
            Self::ProxyBuiltinTestServer => {
                let allowed = runtime
                    .allowed_probe_addr
                    .expect("allowed probe must be started for builtin proxy mode");
                json!({
                    "defaultPolicy": "block",
                    "allowedHosts": [allowed.ip().to_string()],
                    "proxy": { "builtinTestServer": true }
                })
            }
        }
    }

    fn command(
        self,
        backend: MxcBackend,
        workspace: &Path,
        runtime: &ScenarioRuntime,
        iterations: u64,
    ) -> Result<String, Box<dyn std::error::Error>> {
        if self.is_proxy() {
            let script_path = workspace.join("mxc-proxy-request-bench.py");
            std::fs::write(&script_path, MXC_PROXY_REQUEST_BENCH_PY)?;
            let (allowed_host, allowed_port) = match self {
                Self::ProxyBuiltinTestServer => {
                    let addr = runtime
                        .allowed_probe_addr
                        .expect("allowed probe must be started for builtin proxy mode");
                    (addr.ip().to_string(), addr.port())
                }
                _ => ("-".into(), 0),
            };
            return Ok(match backend.command_family() {
                CommandFamily::PosixShell => format!(
                    "/usr/bin/python3 {} {} {} {} {} {}",
                    shell_quote(&script_path.to_string_lossy()),
                    iterations,
                    shell_quote(DENIED_HOST),
                    DENIED_PORT,
                    shell_quote(&allowed_host),
                    allowed_port
                ),
                CommandFamily::PythonSource => python_proxy_source(
                    iterations,
                    DENIED_HOST,
                    DENIED_PORT,
                    &allowed_host,
                    allowed_port,
                ),
            });
        }

        Ok(match (self, backend.command_family()) {
            (Self::AllowControl, CommandFamily::PosixShell) => {
                format!(
                    "set -e; wget -qO- --timeout=8 https://{ALLOW_HOST}/zen >/dev/null; \
                     echo MXC_MATRIX_ALLOW_CONTROL_OK"
                )
            }
            (Self::AllowControl, CommandFamily::PythonSource) => format!(
                "import urllib.request\n\
                 urllib.request.urlopen('https://{ALLOW_HOST}/zen', timeout=8).read()\n\
                 print('MXC_MATRIX_ALLOW_CONTROL_OK')"
            ),
            (Self::DefaultBlock, CommandFamily::PosixShell) => {
                format!(
                    "if wget -qO- --timeout=3 https://{ALLOW_HOST}/zen >/dev/null 2>&1; then \
                       echo MXC_MATRIX_NETWORK_LEAK; exit 1; \
                     else \
                       echo MXC_MATRIX_DEFAULT_BLOCK_OK; \
                     fi"
                )
            }
            (Self::DefaultBlock, CommandFamily::PythonSource) => format!(
                "import urllib.request\n\
                 try:\n\
                     urllib.request.urlopen('https://{ALLOW_HOST}/zen', timeout=3).read()\n\
                     print('MXC_MATRIX_NETWORK_LEAK')\n\
                     raise SystemExit(1)\n\
                 except Exception:\n\
                     print('MXC_MATRIX_DEFAULT_BLOCK_OK')"
            ),
            (
                Self::HostFilterCapabilities | Self::HostFilterFirewall | Self::HostFilterBoth,
                CommandFamily::PosixShell,
            ) => {
                format!(
                    "set -e; \
                     wget -qO- --timeout=8 https://{ALLOW_HOST}/zen >/dev/null; \
                     echo MXC_MATRIX_ALLOWLIST_OK; \
                     if wget -qO- --timeout=5 https://{DENIED_HOST}/ >/dev/null 2>&1; then \
                       echo MXC_MATRIX_DENYLIST_LEAK; exit 1; \
                     else \
                       echo MXC_MATRIX_DENYLIST_OK; \
                     fi"
                )
            }
            (
                Self::HostFilterCapabilities | Self::HostFilterFirewall | Self::HostFilterBoth,
                CommandFamily::PythonSource,
            ) => format!(
                "import urllib.request\n\
                 urllib.request.urlopen('https://{ALLOW_HOST}/zen', timeout=8).read()\n\
                 print('MXC_MATRIX_ALLOWLIST_OK')\n\
                 try:\n\
                     urllib.request.urlopen('https://{DENIED_HOST}/', timeout=5).read()\n\
                     print('MXC_MATRIX_DENYLIST_LEAK')\n\
                     raise SystemExit(1)\n\
                 except Exception:\n\
                     print('MXC_MATRIX_DENYLIST_OK')"
            ),
            _ => unreachable!("proxy scenarios returned earlier"),
        })
    }
}

#[derive(Default)]
struct ScenarioRuntime {
    _external_proxy: Option<StaticDenyProxy>,
    external_proxy_addr: Option<SocketAddr>,
    _allowed_probe: Option<TcpAcceptProbe>,
    allowed_probe_addr: Option<SocketAddr>,
}

impl ScenarioRuntime {
    async fn start(scenario: NetworkScenario) -> Result<Self, Box<dyn std::error::Error>> {
        match scenario {
            NetworkScenario::ProxyLocalhost | NetworkScenario::ProxyUrl => {
                let proxy = StaticDenyProxy::start().await?;
                Ok(Self {
                    external_proxy_addr: Some(proxy.addr),
                    _external_proxy: Some(proxy),
                    ..Self::default()
                })
            }
            NetworkScenario::ProxyBuiltinTestServer => {
                let probe = TcpAcceptProbe::start().await?;
                Ok(Self {
                    allowed_probe_addr: Some(probe.addr),
                    _allowed_probe: Some(probe),
                    ..Self::default()
                })
            }
            _ => Ok(Self::default()),
        }
    }
}

async fn run_mxc_matrix(iterations: u64) -> Result<MxcMatrixSection, Box<dyn std::error::Error>> {
    let backends = selected_mxc_backends()?;
    let Some(executor) = find_mxc_executor() else {
        return Ok(MxcMatrixSection {
            enabled: false,
            executor: None,
            reason: Some(
                "set AXIS_TEST_MXC_EXECUTOR to a safe lxc-exec path, or put lxc-exec on PATH"
                    .into(),
            ),
            rows: Vec::new(),
        });
    };

    let mut rows = Vec::new();
    for backend in backends {
        for scenario in NetworkScenario::all() {
            rows.push(run_mxc_case(&executor, backend, scenario, iterations).await);
        }
    }

    Ok(MxcMatrixSection {
        enabled: true,
        executor: Some(executor.display().to_string()),
        reason: None,
        rows,
    })
}

fn selected_mxc_backends() -> Result<Vec<MxcBackend>, String> {
    parse_backend_filter(std::env::var("AXIS_MXC_MATRIX_BACKENDS").ok().as_deref())
}

fn parse_backend_filter(value: Option<&str>) -> Result<Vec<MxcBackend>, String> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(MxcBackend::linux_backends());
    };
    if value.eq_ignore_ascii_case("all") {
        return Ok(MxcBackend::linux_backends());
    }

    let mut backends = Vec::new();
    for raw_token in value.split(',') {
        let token = raw_token.trim().to_ascii_lowercase();
        if token.is_empty() {
            continue;
        }
        let Some(backend) = MxcBackend::from_filter_token(&token) else {
            return Err(format!(
                "unsupported AXIS_MXC_MATRIX_BACKENDS token '{raw_token}'; expected one of bubblewrap, lxc, microvm, hyperlight, or all"
            ));
        };
        if !backends.contains(&backend) {
            backends.push(backend);
        }
    }

    if backends.is_empty() {
        Ok(MxcBackend::linux_backends())
    } else {
        Ok(backends)
    }
}

async fn run_mxc_case(
    executor: &Path,
    backend: MxcBackend,
    scenario: NetworkScenario,
    iterations: u64,
) -> MatrixRow {
    let expected_markers = scenario.expected_markers();
    let unavailable = |reason: String| MatrixRow {
        backend: backend.label(),
        containment: backend.containment(),
        backend_class: backend.backend_class(),
        mode: scenario.mode(),
        category: scenario.category(),
        status: "unavailable",
        reason: Some(reason),
        expected_markers: expected_markers.clone(),
        metrics: None,
        exit_code: None,
        stdout_excerpt: None,
        stderr_excerpt: None,
    };

    if matches!(backend, MxcBackend::Bubblewrap) && find_on_path("bwrap").is_none() {
        return unavailable("bwrap is not on PATH".into());
    }
    if matches!(
        (backend, scenario),
        (
            MxcBackend::Bubblewrap,
            NetworkScenario::ProxyBuiltinTestServer
        )
    ) && !linux_test_proxy_available(executor)
    {
        return unavailable("linux-test-proxy is not next to the MXC executor".into());
    }

    let runtime = match ScenarioRuntime::start(scenario).await {
        Ok(runtime) => runtime,
        Err(err) => return unavailable(format!("scenario runtime setup failed: {err}")),
    };
    let workspace = match tempfile::Builder::new()
        .prefix("axis-mxc-matrix-")
        .tempdir()
    {
        Ok(workspace) => workspace,
        Err(err) => return unavailable(format!("temp workspace setup failed: {err}")),
    };
    let command = match scenario.command(backend, workspace.path(), &runtime, iterations) {
        Ok(command) => command,
        Err(err) => return unavailable(format!("scenario command setup failed: {err}")),
    };
    let config_path = workspace.path().join("mxc-matrix.json");
    let config = mxc_config_json(
        backend,
        scenario,
        &safe_container_id(backend, scenario),
        &command,
        workspace.path(),
        scenario.network_json(&runtime),
    );
    if let Err(err) = std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&config).unwrap_or_default(),
    ) {
        return unavailable(format!("config write failed: {err}"));
    }

    let started = Instant::now();
    let mut command = Command::new(executor);
    command
        .arg("--experimental")
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = match run_with_timeout(&mut command, COMMAND_TIMEOUT) {
        Ok(output) => output,
        Err(err) => return unavailable(err.to_string()),
    };
    let sandbox_wall_ms = started.elapsed().as_millis();
    mxc_row_from_output(backend, scenario, expected_markers, output, sandbox_wall_ms)
}

fn mxc_config_json(
    backend: MxcBackend,
    scenario: NetworkScenario,
    container_id: &str,
    command: &str,
    workspace: &Path,
    network: Value,
) -> Value {
    let mut config = json!({
        "version": "0.6.0-alpha",
        "containerId": container_id,
        "containment": backend.containment(),
        "platform": "linux",
        "process": {
            "commandLine": command,
            "env": ["PATH=/usr/bin:/bin"],
            "timeout": 30000
        },
        "filesystem": {
            "readwritePaths": if scenario.is_proxy() {
                vec![workspace.to_string_lossy().to_string()]
            } else {
                Vec::<String>::new()
            },
            "readonlyPaths": Vec::<String>::new(),
            "deniedPaths": Vec::<String>::new()
        },
        "network": network,
        "lifecycle": {
            "destroyOnExit": true,
            "preservePolicy": false
        }
    });

    if matches!(backend, MxcBackend::Lxc) {
        config["lxc"] = json!({
            "distribution": std::env::var("AXIS_MXC_LXC_DISTRIBUTION")
                .unwrap_or_else(|_| "alpine".into()),
            "release": std::env::var("AXIS_MXC_LXC_RELEASE").unwrap_or_else(|_| "3.23".into())
        });
    }

    config
}

fn mxc_row_from_output(
    backend: MxcBackend,
    scenario: NetworkScenario,
    expected_markers: Vec<&'static str>,
    output: CommandOutput,
    sandbox_wall_ms: u128,
) -> MatrixRow {
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}\n{stderr}");
    let exit_code = output.status.code();

    let base_row = |status, reason: Option<String>, metrics: Option<RowMetrics>| MatrixRow {
        backend: backend.label(),
        containment: backend.containment(),
        backend_class: backend.backend_class(),
        mode: scenario.mode(),
        category: scenario.category(),
        status,
        reason,
        expected_markers: expected_markers.clone(),
        metrics,
        exit_code,
        stdout_excerpt: excerpt_if_interesting(status, &stdout),
        stderr_excerpt: excerpt_if_interesting(status, &stderr),
    };

    if !output.status.success() {
        let (status, reason) = classify_mxc_failure(&combined);
        return base_row(status, Some(reason), None);
    }

    for marker in &expected_markers {
        if !stdout.contains(marker) && !stderr.contains(marker) {
            return base_row(
                "failed",
                Some(format!("expected marker {marker} was not emitted")),
                None,
            );
        }
    }

    let metrics = if scenario.is_proxy() {
        match parse_proxy_child_report(&stdout) {
            Ok(proxy_report) => {
                if proxy_report.failed_requests != 0
                    || proxy_report.denied_responses != proxy_report.iterations
                {
                    return base_row(
                        "failed",
                        Some(format!(
                            "proxy report had {} failed requests and {} denied responses for {} iterations",
                            proxy_report.failed_requests,
                            proxy_report.denied_responses,
                            proxy_report.iterations
                        )),
                        None,
                    );
                }
                Some(RowMetrics {
                    sandbox_wall_ms,
                    request_iterations: Some(proxy_report.iterations),
                    request_total_ns: Some(proxy_report.total_ns),
                    requests_per_sec: Some(proxy_report.requests_per_sec),
                    ns_per_request: Some(proxy_report.ns_per_request),
                    denied_responses: Some(proxy_report.denied_responses),
                })
            }
            Err(err) => {
                return base_row(
                    "failed",
                    Some(format!("proxy report parse failed: {err}")),
                    None,
                );
            }
        }
    } else {
        Some(RowMetrics {
            sandbox_wall_ms,
            request_iterations: None,
            request_total_ns: None,
            requests_per_sec: None,
            ns_per_request: None,
            denied_responses: None,
        })
    };

    base_row("passed", None, metrics)
}

fn classify_mxc_failure(combined: &str) -> (&'static str, String) {
    let normalized = combined.to_ascii_lowercase();
    let unavailable_needles = [
        "not compiled",
        "not installed",
        "not on path",
        "no such file or directory",
        "permission denied",
        "operation not permitted",
        "requires x86_64",
        "requires kvm",
        "/dev/kvm",
        "no warmed snapshot",
        "run `lxc-exec --setup-hyperlight`",
        "failed to start container",
        "failed to run lxc",
        "failed to run iptables",
        "iptables",
        "cap_net_admin",
        "lxc-create",
        "lxc-execute",
        "wget: not found",
        "python3: not found",
    ];
    if let Some(needle) = unavailable_needles
        .iter()
        .find(|needle| normalized.contains(**needle))
    {
        return ("unavailable", summarize_failure(combined, needle));
    }

    let unsupported_needles = [
        "network proxy is not supported",
        "network policy is not supported",
        "not supported by the",
        "unsupported",
        "cannot be combined",
        "only supported",
        "rejected",
    ];
    if let Some(needle) = unsupported_needles
        .iter()
        .find(|needle| normalized.contains(**needle))
    {
        return ("unsupported", summarize_failure(combined, needle));
    }

    ("failed", truncate(combined.trim(), 500))
}

fn summarize_failure(combined: &str, needle: &str) -> String {
    combined
        .lines()
        .find(|line| line.to_ascii_lowercase().contains(needle))
        .map(|line| truncate(line.trim(), 500))
        .unwrap_or_else(|| truncate(combined.trim(), 500))
}

#[derive(Debug, Deserialize)]
struct ProxyChildReport {
    iterations: u64,
    total_ns: u64,
    requests_per_sec: f64,
    ns_per_request: f64,
    denied_responses: u64,
    failed_requests: u64,
}

fn parse_proxy_child_report(stdout: &str) -> Result<ProxyChildReport, serde_json::Error> {
    let line = stdout
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .unwrap_or(stdout);
    serde_json::from_str(line.trim())
}

async fn run_axis_native_filesystem_boundary() -> AxisNativeSection {
    let row = if cfg!(target_os = "linux") {
        run_axis_native_linux_filesystem_boundary().await
    } else {
        MatrixRow {
            backend: "axis-native",
            containment: "native",
            backend_class: "process",
            mode: "filesystem.boundary",
            category: "filesystem",
            status: "unavailable",
            reason: Some("AXIS native filesystem comparison is implemented for Linux here".into()),
            expected_markers: vec!["AXIS_NATIVE_FS_BOUNDARY_OK"],
            metrics: None,
            exit_code: None,
            stdout_excerpt: None,
            stderr_excerpt: None,
        }
    };
    AxisNativeSection { rows: vec![row] }
}

async fn run_axis_native_linux_filesystem_boundary() -> MatrixRow {
    let workspace = match tempfile::Builder::new()
        .prefix("axis-native-matrix-workspace-")
        .tempdir()
    {
        Ok(workspace) => workspace,
        Err(err) => {
            return axis_native_unavailable(format!("workspace setup failed: {err}"));
        }
    };
    let denied = match tempfile::Builder::new()
        .prefix("axis-native-matrix-denied-")
        .tempdir()
    {
        Ok(denied) => denied,
        Err(err) => return axis_native_unavailable(format!("denied path setup failed: {err}")),
    };
    let secret_path = denied.path().join("secret.txt");
    if let Err(err) = std::fs::write(&secret_path, "do-not-read") {
        return axis_native_unavailable(format!("denied fixture write failed: {err}"));
    }

    let policy_yaml = format!(
        r#"
version: 1
name: axis-native-matrix-fs
filesystem:
  read_only:
    - "/usr"
    - "/bin"
    - "/lib"
    - "/lib64"
    - "/etc"
  read_write:
    - "{}"
  deny:
    - "{}"
network:
  mode: allow
process:
  max_processes: 0
  max_memory_mb: 0
  cpu_rate_percent: 0
"#,
        yaml_escape(&workspace.path().to_string_lossy()),
        yaml_escape(&denied.path().to_string_lossy())
    );
    let policy = match Policy::from_yaml(&policy_yaml) {
        Ok(policy) => policy,
        Err(err) => return axis_native_unavailable(format!("policy setup failed: {err}")),
    };

    let started = Instant::now();
    let config = SandboxConfig {
        id: SandboxId::new(),
        policy,
        command: "/usr/bin/python3".into(),
        args: vec!["-c".into(), AXIS_NATIVE_FS_PROBE_PY.into()],
        working_dir: Some(workspace.path().to_path_buf()),
        workspace_dir: workspace.path().to_path_buf(),
        env: vec![
            (
                "AXIS_MATRIX_WORKSPACE".into(),
                workspace.path().to_string_lossy().to_string(),
            ),
            (
                "AXIS_MATRIX_DENIED".into(),
                denied.path().to_string_lossy().to_string(),
            ),
        ],
        proxy_port: 0,
        proxy_addr: None,
        connect_attribution: None,
        capture_output: true,
        timeout_sec: Some(10),
    };
    let mut sandbox = match Sandbox::create_for_exec(config) {
        Ok(sandbox) => sandbox,
        Err(err) => return axis_native_unavailable(err.to_string()),
    };
    if let Err(err) = sandbox.start() {
        return axis_native_unavailable(err.to_string());
    }
    let exit_code = match sandbox.wait().await {
        Ok(code) => Some(code),
        Err(err) => return axis_native_unavailable(err.to_string()),
    };
    let sandbox_wall_ms = started.elapsed().as_millis();
    let stdout = std::fs::read_to_string(workspace.path().join("stdout.log")).unwrap_or_default();
    let stderr = std::fs::read_to_string(workspace.path().join("stderr.log")).unwrap_or_default();

    if exit_code == Some(0) && stdout.contains("AXIS_NATIVE_FS_BOUNDARY_OK") {
        MatrixRow {
            backend: "axis-native-linux",
            containment: "native",
            backend_class: "process",
            mode: "filesystem.boundary",
            category: "filesystem",
            status: "passed",
            reason: None,
            expected_markers: vec!["AXIS_NATIVE_FS_BOUNDARY_OK"],
            metrics: Some(RowMetrics {
                sandbox_wall_ms,
                request_iterations: None,
                request_total_ns: None,
                requests_per_sec: None,
                ns_per_request: None,
                denied_responses: None,
            }),
            exit_code,
            stdout_excerpt: None,
            stderr_excerpt: None,
        }
    } else {
        MatrixRow {
            backend: "axis-native-linux",
            containment: "native",
            backend_class: "process",
            mode: "filesystem.boundary",
            category: "filesystem",
            status: "failed",
            reason: Some("filesystem boundary probe did not emit success marker".into()),
            expected_markers: vec!["AXIS_NATIVE_FS_BOUNDARY_OK"],
            metrics: None,
            exit_code,
            stdout_excerpt: excerpt_if_interesting("failed", &stdout),
            stderr_excerpt: excerpt_if_interesting("failed", &stderr),
        }
    }
}

fn axis_native_unavailable(reason: String) -> MatrixRow {
    MatrixRow {
        backend: "axis-native-linux",
        containment: "native",
        backend_class: "process",
        mode: "filesystem.boundary",
        category: "filesystem",
        status: "unavailable",
        reason: Some(reason),
        expected_markers: vec!["AXIS_NATIVE_FS_BOUNDARY_OK"],
        metrics: None,
        exit_code: None,
        stdout_excerpt: None,
        stderr_excerpt: None,
    }
}

#[derive(Debug)]
struct CommandOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> Result<CommandOutput, Box<dyn std::error::Error>> {
    let mut child = command.spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            if let Some(mut handle) = child.stdout.take() {
                handle.read_to_end(&mut stdout)?;
            }
            if let Some(mut handle) = child.stderr.take() {
                handle.read_to_end(&mut stderr)?;
            }
            return Ok(CommandOutput {
                status,
                stdout,
                stderr,
            });
        }
        if Instant::now() >= deadline {
            terminate_child(&mut child);
            return Err(format!("command timed out after {}s", timeout.as_secs()).into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

struct StaticDenyProxy {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl StaticDenyProxy {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut reader = BufReader::new(stream);
                    let mut request_line = String::new();
                    let _ = reader.read_line(&mut request_line).await;
                    let mut stream = reader.into_inner();
                    let body = b"denied by matrix proxy\n";
                    let response = format!(
                        "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.write_all(body).await;
                });
            }
        });
        Ok(Self { addr, task })
    }
}

impl Drop for StaticDenyProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct TcpAcceptProbe {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl TcpAcceptProbe {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _peer)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let _ = stream.write_all(b"axis matrix probe\n").await;
                });
            }
        });
        Ok(Self { addr, task })
    }
}

impl Drop for TcpAcceptProbe {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn find_mxc_executor() -> Option<PathBuf> {
    std::env::var_os("AXIS_TEST_MXC_EXECUTOR")
        .map(PathBuf::from)
        .or_else(|| find_on_path("lxc-exec"))
}

fn linux_test_proxy_available(executor: &Path) -> bool {
    executor
        .parent()
        .is_some_and(|parent| parent.join("linux-test-proxy").is_file())
}

fn find_on_path(binary: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(binary))
            .find(|candidate| candidate.is_file())
    })
}

fn safe_container_id(backend: MxcBackend, scenario: NetworkScenario) -> String {
    format!(
        "axis-mxc-matrix-{}-{}",
        backend.containment(),
        scenario
            .mode()
            .replace("network.", "")
            .replace(['.', '_'], "-")
    )
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn yaml_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn excerpt_if_interesting(status: &str, value: &str) -> Option<String> {
    if status == "passed" || value.trim().is_empty() {
        None
    } else {
        Some(truncate(value.trim(), 1_000))
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let mut truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        truncated.push_str("...");
    }
    truncated
}

fn python_proxy_source(
    iterations: u64,
    denied_host: &str,
    denied_port: u16,
    allowed_host: &str,
    allowed_port: u16,
) -> String {
    format!(
        "import sys\n\
         sys.argv = ['mxc-proxy-request-bench.py', '{iterations}', '{denied_host}', '{denied_port}', '{allowed_host}', '{allowed_port}']\n\
         {MXC_PROXY_REQUEST_BENCH_PY}"
    )
}

const MXC_PROXY_REQUEST_BENCH_PY: &str = r#"
import json
import os
import socket
import sys
import time
from urllib.parse import urlparse

iterations = int(sys.argv[1])
denied_host = sys.argv[2]
denied_port = int(sys.argv[3])
allowed_host = sys.argv[4]
allowed_port = int(sys.argv[5])
proxy_url = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
if not proxy_url:
    raise SystemExit("HTTP_PROXY was not set")
parsed = urlparse(proxy_url)
proxy_host = parsed.hostname
proxy_port = parsed.port
if not proxy_host or not proxy_port:
    raise SystemExit(f"invalid HTTP_PROXY: {proxy_url}")

def connect_status(target_host, target_port):
    request = (
        f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
        f"Host: {target_host}:{target_port}\r\n"
        "\r\n"
    ).encode("ascii")
    with socket.create_connection((proxy_host, proxy_port), timeout=2.0) as sock:
        sock.sendall(request)
        data = b""
        while b"\r\n" not in data:
            chunk = sock.recv(1)
            if not chunk:
                break
            data += chunk
    return data.split(b"\r\n", 1)[0]

if allowed_host != "-":
    status = connect_status(allowed_host, allowed_port)
    if b" 200 " not in status:
        raise SystemExit(f"allowed probe failed: {status!r}")
    print("MXC_MATRIX_PROXY_ALLOW_OK")

denied = 0
failed = 0
start = time.perf_counter_ns()
for _ in range(iterations):
    try:
        status = connect_status(denied_host, denied_port)
        if b" 403 " in status:
            denied += 1
        else:
            failed += 1
    except Exception:
        failed += 1
end = time.perf_counter_ns()

if denied == iterations and failed == 0:
    print("MXC_MATRIX_PROXY_DENY_OK")

total_ns = end - start
print(json.dumps({
    "iterations": iterations,
    "total_ns": total_ns,
    "requests_per_sec": iterations / (total_ns / 1_000_000_000),
    "ns_per_request": total_ns / iterations,
    "denied_responses": denied,
    "failed_requests": failed,
}))
"#;

const AXIS_NATIVE_FS_PROBE_PY: &str = r#"
import os
import pathlib
import sys

workspace = pathlib.Path(os.environ["AXIS_MATRIX_WORKSPACE"])
denied = pathlib.Path(os.environ["AXIS_MATRIX_DENIED"])
(workspace / "write-ok.txt").write_text("ok", encoding="utf-8")
try:
    (denied / "secret.txt").read_text(encoding="utf-8")
except Exception:
    print("AXIS_NATIVE_FS_BOUNDARY_OK")
    raise SystemExit(0)
print("AXIS_NATIVE_FS_BOUNDARY_LEAK", file=sys.stderr)
raise SystemExit(1)
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_mxc_failure_distinguishes_unavailable_unsupported_and_failed() {
        let (status, reason) = classify_mxc_failure(
            "Error: MicroVM backend not compiled in (build with --features microvm)",
        );
        assert_eq!(status, "unavailable");
        assert!(reason.contains("not compiled"));

        let (status, reason) = classify_mxc_failure(
            "Request error\nNetwork proxy is only supported with the 'processcontainer' or 'bubblewrap' containment backends",
        );
        assert_eq!(status, "unsupported");
        assert!(reason.contains("Network proxy"));

        let (status, reason) =
            classify_mxc_failure("MXC_MATRIX_ALLOWLIST_OK\nMXC_MATRIX_DENYLIST_LEAK");
        assert_eq!(status, "failed");
        assert!(reason.contains("DENYLIST_LEAK"));
    }

    #[test]
    fn parse_proxy_child_report_uses_last_json_line_after_markers() {
        let stdout = r#"
MXC_MATRIX_PROXY_DENY_OK
{"iterations":7,"total_ns":70,"requests_per_sec":100000000.0,"ns_per_request":10.0,"denied_responses":7,"failed_requests":0}
"#;
        let report = parse_proxy_child_report(stdout).unwrap();
        assert_eq!(report.iterations, 7);
        assert_eq!(report.denied_responses, 7);
        assert_eq!(report.failed_requests, 0);
    }

    #[test]
    fn parse_backend_filter_accepts_aliases_and_rejects_unknown_tokens() {
        assert_eq!(
            parse_backend_filter(Some("bwrap,lxc")).unwrap(),
            vec![MxcBackend::Bubblewrap, MxcBackend::Lxc]
        );
        assert_eq!(
            parse_backend_filter(Some("mxc-linux-bubblewrap,bubblewrap")).unwrap(),
            vec![MxcBackend::Bubblewrap]
        );
        assert!(parse_backend_filter(Some("docker")).is_err());
    }

    #[test]
    fn network_json_separates_proxy_routing_from_firewall_modes() {
        let proxy_runtime = ScenarioRuntime {
            external_proxy_addr: Some("127.0.0.1:8123".parse().unwrap()),
            ..ScenarioRuntime::default()
        };
        assert_eq!(
            NetworkScenario::ProxyLocalhost.network_json(&proxy_runtime),
            json!({"defaultPolicy": "allow", "proxy": {"localhost": 8123}})
        );

        let firewall =
            NetworkScenario::HostFilterFirewall.network_json(&ScenarioRuntime::default());
        assert_eq!(firewall["defaultPolicy"], "block");
        assert_eq!(firewall["enforcementMode"], "firewall");
        assert_eq!(firewall["allowedHosts"][0], ALLOW_HOST);
        assert!(firewall.get("proxy").is_none());
    }

    #[test]
    fn mxc_config_adds_lxc_section_only_for_lxc_and_mounts_workspace_only_for_proxy() {
        let workspace = tempfile::tempdir().unwrap();
        let proxy_config = mxc_config_json(
            MxcBackend::Lxc,
            NetworkScenario::ProxyUrl,
            "case",
            "echo ok",
            workspace.path(),
            json!({"defaultPolicy": "allow", "proxy": {"url": "http://127.0.0.1:1"}}),
        );
        assert_eq!(proxy_config["containment"], "lxc");
        assert_eq!(proxy_config["lxc"]["distribution"], "alpine");
        assert_eq!(
            proxy_config["filesystem"]["readwritePaths"][0].as_str(),
            Some(workspace.path().to_string_lossy().as_ref())
        );

        let strict_config = mxc_config_json(
            MxcBackend::Bubblewrap,
            NetworkScenario::DefaultBlock,
            "case",
            "echo ok",
            workspace.path(),
            json!({"defaultPolicy": "block"}),
        );
        assert!(strict_config.get("lxc").is_none());
        assert!(
            strict_config["filesystem"]["readwritePaths"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
}
