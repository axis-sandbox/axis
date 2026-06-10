// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Compare the success-metrics subset across runtime provider selections.

use axis_core::policy::Policy;
use axis_core::types::SandboxId;
use axis_proxy::proxy::{AxisProxy, ProxyConfig};
use axis_sandbox::SandboxConfig;
use serde::Serialize;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const DEFAULT_STARTUP_SAMPLES: usize = 10;
const DEFAULT_OPA_EVALS: u64 = 50_000;
const DEFAULT_PROXY_BASELINE_CONNS: u32 = 50;
const DEFAULT_PROXY_REQUESTS: u32 = 100;
const STARTUP_POLICY_PROFILE: &str = "process_limits_disabled";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = BenchmarkConfig::from_env()?;
    let mut rows = Vec::new();

    for provider in &config.providers {
        rows.push(benchmark_provider(*provider, &config).await?);
    }

    let report = RuntimeMetricsReport {
        startup_policy_profile: STARTUP_POLICY_PROFILE,
        startup_samples: config.startup_samples,
        opa_evals: config.opa_evals,
        proxy_baseline_connections: config.proxy_baseline_connections,
        proxy_requests: config.proxy_requests,
        rows,
    };

    serde_json::to_writer_pretty(std::io::stdout().lock(), &report)?;
    println!();
    Ok(())
}

#[derive(Debug, Clone)]
struct BenchmarkConfig {
    providers: Vec<RuntimeProviderCase>,
    startup_samples: usize,
    opa_evals: u64,
    proxy_baseline_connections: u32,
    proxy_requests: u32,
}

impl BenchmarkConfig {
    fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let providers = match std::env::var("AXIS_RUNTIME_METRICS_PROVIDERS") {
            Ok(value) => parse_providers(&value)?,
            Err(_) => RuntimeProviderCase::all().to_vec(),
        };
        if providers.is_empty() {
            return Err("AXIS_RUNTIME_METRICS_PROVIDERS must not be empty".into());
        }

        Ok(Self {
            providers,
            startup_samples: env_usize(
                "AXIS_RUNTIME_METRICS_STARTUP_SAMPLES",
                DEFAULT_STARTUP_SAMPLES,
            )?,
            opa_evals: env_u64("AXIS_RUNTIME_METRICS_OPA_EVALS", DEFAULT_OPA_EVALS)?,
            proxy_baseline_connections: env_u32(
                "AXIS_RUNTIME_METRICS_PROXY_BASELINE_CONNS",
                DEFAULT_PROXY_BASELINE_CONNS,
            )?,
            proxy_requests: env_u32(
                "AXIS_RUNTIME_METRICS_PROXY_REQUESTS",
                DEFAULT_PROXY_REQUESTS,
            )?,
        })
    }
}

fn env_usize(key: &str, default: usize) -> Result<usize, Box<dyn std::error::Error>> {
    let value = std::env::var(key)
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(default);
    if value == 0 {
        return Err(format!("{key} must be greater than zero").into());
    }
    Ok(value)
}

fn env_u64(key: &str, default: u64) -> Result<u64, Box<dyn std::error::Error>> {
    let value = std::env::var(key)
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(default);
    if value == 0 {
        return Err(format!("{key} must be greater than zero").into());
    }
    Ok(value)
}

fn env_u32(key: &str, default: u32) -> Result<u32, Box<dyn std::error::Error>> {
    let value = std::env::var(key)
        .ok()
        .map(|value| value.parse::<u32>())
        .transpose()?
        .unwrap_or(default);
    if value == 0 {
        return Err(format!("{key} must be greater than zero").into());
    }
    Ok(value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeProviderCase {
    Auto,
    Mxc,
    AxisNative,
}

impl RuntimeProviderCase {
    fn all() -> &'static [Self] {
        &[Self::Auto, Self::Mxc, Self::AxisNative]
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Mxc => "mxc",
            Self::AxisNative => "axis_native",
        }
    }
}

fn parse_providers(value: &str) -> Result<Vec<RuntimeProviderCase>, Box<dyn std::error::Error>> {
    value
        .split(',')
        .map(|raw| match raw.trim() {
            "auto" => Ok(RuntimeProviderCase::Auto),
            "mxc" => Ok(RuntimeProviderCase::Mxc),
            "axis_native" | "axis-native" => Ok(RuntimeProviderCase::AxisNative),
            "" => Err("empty runtime provider in AXIS_RUNTIME_METRICS_PROVIDERS".into()),
            other => Err(format!("unknown runtime provider '{other}'").into()),
        })
        .collect()
}

#[derive(Debug, Serialize)]
struct RuntimeMetricsReport {
    startup_policy_profile: &'static str,
    startup_samples: usize,
    opa_evals: u64,
    proxy_baseline_connections: u32,
    proxy_requests: u32,
    rows: Vec<RuntimeMetricsRow>,
}

#[derive(Debug, Serialize)]
struct RuntimeMetricsRow {
    runtime_containment: &'static str,
    runtime_provider: &'static str,
    startup: StartupReport,
    cold_proxy_deny: ColdProxyReport,
    synthetic_opa: SyntheticOpaReport,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum StartupReport {
    Ok {
        median_ms: f64,
        p99_ms: f64,
        samples_ms: Vec<f64>,
    },
    Error {
        sample_index: usize,
        error: String,
    },
}

#[derive(Debug, Serialize)]
struct ColdProxyReport {
    latency_ms: f64,
    baseline_ms: f64,
    total_ms: f64,
}

#[derive(Debug, Serialize)]
struct SyntheticOpaReport {
    evals_per_sec: f64,
    us_per_eval: f64,
}

async fn benchmark_provider(
    provider: RuntimeProviderCase,
    config: &BenchmarkConfig,
) -> Result<RuntimeMetricsRow, Box<dyn std::error::Error>> {
    Ok(RuntimeMetricsRow {
        runtime_containment: "process",
        runtime_provider: provider.as_str(),
        startup: benchmark_startup(provider, config.startup_samples).await,
        cold_proxy_deny: benchmark_cold_proxy_deny(
            provider,
            config.proxy_baseline_connections,
            config.proxy_requests,
        )
        .await?,
        synthetic_opa: benchmark_synthetic_opa(config.opa_evals),
    })
}

async fn benchmark_startup(provider: RuntimeProviderCase, samples: usize) -> StartupReport {
    let mut durations = Vec::with_capacity(samples);
    for sample_index in 0..samples {
        match measure_sandbox_startup(provider).await {
            Ok(duration) => durations.push(duration),
            Err(err) => {
                return StartupReport::Error {
                    sample_index,
                    error: err,
                };
            }
        }
    }

    let mut sorted = durations.clone();
    sorted.sort();
    StartupReport::Ok {
        median_ms: duration_ms(sorted[sorted.len() / 2]),
        p99_ms: duration_ms(sorted[sorted.len() * 99 / 100]),
        samples_ms: durations.into_iter().map(duration_ms).collect(),
    }
}

async fn measure_sandbox_startup(provider: RuntimeProviderCase) -> Result<Duration, String> {
    let policy = startup_policy(provider).map_err(|err| err.to_string())?;
    let workspace = tempfile::tempdir().map_err(|err| err.to_string())?;

    let command = if cfg!(target_os = "windows") {
        "cmd.exe".to_string()
    } else {
        "/bin/true".to_string()
    };
    let args = if cfg!(target_os = "windows") {
        vec!["/C".into(), "exit".into(), "0".into()]
    } else {
        Vec::new()
    };

    let config = SandboxConfig {
        id: SandboxId::new(),
        policy,
        command,
        args,
        working_dir: None,
        workspace_dir: workspace.path().to_path_buf(),
        env: Vec::new(),
        proxy_port: 0,
        proxy_addr: None,
        connect_attribution: None,
        capture_output: false,
        interactive_terminal: false,
        timeout_sec: None,
    };

    let start = Instant::now();
    let mut sandbox = axis_sandbox::Sandbox::create(config).map_err(|err| err.to_string())?;
    if let Err(err) = sandbox.start() {
        let _ = sandbox.destroy();
        return Err(err.to_string());
    }
    let startup_time = start.elapsed();

    let wait_result = sandbox.wait().await;
    let destroy_result = sandbox.destroy();
    match wait_result {
        Ok(0) => {}
        Ok(code) => return Err(format!("sandbox command exited with status {code}")),
        Err(err) => return Err(err.to_string()),
    }
    if let Err(err) = destroy_result {
        return Err(err.to_string());
    }
    Ok(startup_time)
}

fn startup_policy(provider: RuntimeProviderCase) -> Result<Policy, Box<dyn std::error::Error>> {
    let yaml = if cfg!(target_os = "windows") {
        format!(
            r#"
version: 1
name: bench
runtime:
  containment: process
  provider: {}
process:
  max_processes: 0
  cpu_rate_percent: 0
"#,
            provider.as_str()
        )
    } else {
        format!(
            r#"
version: 1
name: bench
runtime:
  containment: process
  provider: {}
filesystem:
  read_only:
    - /usr
    - /lib
    - /lib64
    - /bin
    - /sbin
    - /etc
  read_write:
    - "{{workspace}}"
process:
  max_processes: 0
  cpu_rate_percent: 0
network:
  mode: allow
"#,
            provider.as_str()
        )
    };
    Ok(Policy::from_yaml(&yaml)?)
}

async fn benchmark_cold_proxy_deny(
    provider: RuntimeProviderCase,
    baseline_connections: u32,
    proxy_requests: u32,
) -> Result<ColdProxyReport, Box<dyn std::error::Error>> {
    let policy = proxy_policy(provider)?;
    let mut proxy = AxisProxy::new(ProxyConfig {
        sandbox_id: SandboxId::new(),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        policy,
        enable_l7: false,
        enable_leak_detection: false,
        upstream_tls_roots_pem: Vec::new(),
        inference_endpoint: None,
        connect_attribution: None,
    })?;
    let addr = proxy.bind().await?;
    let proxy_task = tokio::spawn(async move { proxy.run().await });

    tokio::time::sleep(Duration::from_millis(20)).await;

    let baseline_start = Instant::now();
    for _ in 0..baseline_connections {
        let stream = TcpStream::connect(addr).await?;
        drop(stream);
    }
    let baseline_per_conn = baseline_start.elapsed() / baseline_connections;

    let request_start = Instant::now();
    for _ in 0..proxy_requests {
        let mut stream = TcpStream::connect(addr).await?;
        stream
            .write_all(
                b"CONNECT denied.example.com:443 HTTP/1.1\r\nHost: denied.example.com\r\n\r\n",
            )
            .await?;
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if !line.contains("403") {
            proxy_task.abort();
            return Err(format!("expected 403 response, got {line:?}").into());
        }
    }
    let total_per_req = request_start.elapsed() / proxy_requests;
    proxy_task.abort();

    let latency = total_per_req.saturating_sub(baseline_per_conn);
    Ok(ColdProxyReport {
        latency_ms: duration_ms(latency),
        baseline_ms: duration_ms(baseline_per_conn),
        total_ms: duration_ms(total_per_req),
    })
}

fn proxy_policy(provider: RuntimeProviderCase) -> Result<Policy, Box<dyn std::error::Error>> {
    let yaml = format!(
        r#"
version: 1
name: bench-proxy
runtime:
  containment: process
  provider: {}
network:
  mode: proxy
  policies:
    - name: test
      endpoints:
        - host: "example.com"
          port: 443
"#,
        provider.as_str()
    );
    Ok(Policy::from_yaml(&yaml)?)
}

fn benchmark_synthetic_opa(iterations: u64) -> SyntheticOpaReport {
    let (_total_ns, evals_per_sec) = axis_core::bench::bench_network_eval(iterations);
    SyntheticOpaReport {
        evals_per_sec,
        us_per_eval: 1_000_000.0 / evals_per_sec,
    }
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_provider_list_accepts_aliases() {
        assert_eq!(
            parse_providers("auto,mxc,axis-native").unwrap(),
            vec![
                RuntimeProviderCase::Auto,
                RuntimeProviderCase::Mxc,
                RuntimeProviderCase::AxisNative
            ]
        );
    }

    #[test]
    fn parse_provider_list_rejects_unknown() {
        let err = parse_providers("auto,container").unwrap_err();
        assert!(err.to_string().contains("unknown runtime provider"));
    }
}
