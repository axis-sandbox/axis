// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Compare the success-metrics subset across runtime provider selections.

use axis_core::policy::Policy;
use axis_core::types::SandboxId;
use axis_proxy::proxy::{AxisProxy, ProxyConfig, ProxyTimingEvent, ProxyTimingOutcome};
use axis_sandbox::{SandboxConfig, StartupTrace};
use serde::Serialize;
use std::collections::BTreeMap;
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
        phases: Vec<PhaseReport>,
    },
    Error {
        sample_index: usize,
        error: String,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ColdProxyReport {
    Ok {
        latency_ms: f64,
        baseline_ms: f64,
        total_ms: f64,
        phases: Vec<PhaseReport>,
    },
    Error {
        reason: String,
    },
}

#[derive(Debug, Serialize)]
struct SyntheticOpaReport {
    evals_per_sec: f64,
    us_per_eval: f64,
}

#[derive(Debug, Clone, Serialize)]
struct PhaseReport {
    phase: String,
    median_ms: f64,
    p99_ms: f64,
    samples_ms: Vec<f64>,
}

#[derive(Debug)]
struct StartupSample {
    total: Duration,
    phases: Vec<PhaseSample>,
}

#[derive(Debug, Clone)]
struct PhaseSample {
    phase: String,
    duration: Duration,
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
        .await,
        synthetic_opa: benchmark_synthetic_opa(config.opa_evals),
    })
}

async fn benchmark_startup(provider: RuntimeProviderCase, samples: usize) -> StartupReport {
    let mut startup_samples = Vec::with_capacity(samples);
    for sample_index in 0..samples {
        match measure_sandbox_startup(provider).await {
            Ok(sample) => startup_samples.push(sample),
            Err(err) => {
                return StartupReport::Error {
                    sample_index,
                    error: err,
                };
            }
        }
    }

    let durations = startup_samples
        .iter()
        .map(|sample| sample.total)
        .collect::<Vec<_>>();
    let mut sorted = durations.clone();
    sorted.sort();
    let phase_samples = startup_samples
        .iter()
        .map(|sample| sample.phases.clone())
        .collect::<Vec<_>>();
    StartupReport::Ok {
        median_ms: duration_ms(sorted[sorted.len() / 2]),
        p99_ms: duration_ms(sorted[sorted.len() * 99 / 100]),
        samples_ms: durations.into_iter().map(duration_ms).collect(),
        phases: summarize_phase_samples(&phase_samples),
    }
}

async fn measure_sandbox_startup(provider: RuntimeProviderCase) -> Result<StartupSample, String> {
    let policy = startup_policy(provider).map_err(|err| err.to_string())?;
    let workspace = tempfile::tempdir().map_err(|err| err.to_string())?;
    let trace = StartupTrace::new();

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
        backend_preflight: Default::default(),
        startup_trace: Some(trace.clone()),
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
    let mut phases = trace
        .phases()
        .into_iter()
        .map(|phase| PhaseSample {
            phase: phase.phase.into(),
            duration: phase.duration,
        })
        .collect::<Vec<_>>();
    phases.push(PhaseSample {
        phase: "startup.total".into(),
        duration: startup_time,
    });
    Ok(StartupSample {
        total: startup_time,
        phases,
    })
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
  max_memory_mb: 0
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
  max_memory_mb: 0
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
) -> ColdProxyReport {
    match benchmark_cold_proxy_deny_inner(provider, baseline_connections, proxy_requests).await {
        Ok(report) => report,
        Err(err) => ColdProxyReport::Error {
            reason: err.to_string(),
        },
    }
}

async fn benchmark_cold_proxy_deny_inner(
    provider: RuntimeProviderCase,
    baseline_connections: u32,
    proxy_requests: u32,
) -> Result<ColdProxyReport, Box<dyn std::error::Error>> {
    let policy = proxy_policy(provider)?;
    let (timing_tx, mut timing_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut proxy = AxisProxy::new(ProxyConfig {
        sandbox_id: SandboxId::new(),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        policy,
        enable_l7: false,
        enable_leak_detection: false,
        upstream_tls_roots_pem: Vec::new(),
        inference_endpoint: None,
        connect_attribution: None,
        enable_identity_diagnostics: false,
        timing_tx: Some(timing_tx),
    })?;
    let addr = proxy.bind().await?;
    let proxy_task = tokio::spawn(async move { proxy.run().await });

    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut baseline_samples = Vec::with_capacity(baseline_connections as usize);
    for _ in 0..baseline_connections {
        let baseline_start = Instant::now();
        let stream = TcpStream::connect(addr).await?;
        drop(stream);
        baseline_samples.push(baseline_start.elapsed());
    }
    let baseline_per_conn = mean_duration(&baseline_samples);

    let mut request_samples = Vec::with_capacity(proxy_requests as usize);
    let mut proxy_phase_samples = Vec::with_capacity(proxy_requests as usize);
    for _ in 0..proxy_requests {
        let request_start = Instant::now();
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
        request_samples.push(request_start.elapsed());
        let event = recv_denied_timing_event(&mut timing_rx, "denied.example.com", 443).await?;
        proxy_phase_samples.push(
            event
                .phases
                .into_iter()
                .map(|phase| PhaseSample {
                    phase: phase.phase.into(),
                    duration: phase.duration,
                })
                .collect::<Vec<_>>(),
        );
    }
    proxy_task.abort();

    let total_per_req = mean_duration(&request_samples);
    let latency = total_per_req.saturating_sub(baseline_per_conn);
    let mut phase_reports = Vec::new();
    phase_reports.push(summarize_named_phase(
        "tcp_baseline",
        baseline_samples.as_slice(),
    ));
    phase_reports.push(summarize_named_phase(
        "request_total",
        request_samples.as_slice(),
    ));
    phase_reports.extend(summarize_phase_samples(&proxy_phase_samples));
    Ok(ColdProxyReport::Ok {
        latency_ms: duration_ms(latency),
        baseline_ms: duration_ms(baseline_per_conn),
        total_ms: duration_ms(total_per_req),
        phases: phase_reports,
    })
}

async fn recv_denied_timing_event(
    timing_rx: &mut tokio::sync::mpsc::UnboundedReceiver<ProxyTimingEvent>,
    host: &str,
    port: u16,
) -> Result<ProxyTimingEvent, Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let event = timing_rx
                .recv()
                .await
                .ok_or("proxy timing channel closed before denied request event")?;
            if event.outcome == ProxyTimingOutcome::Denied
                && event.target_host.as_deref() == Some(host)
                && event.target_port == Some(port)
            {
                return Ok::<ProxyTimingEvent, &'static str>(event);
            }
        }
    })
    .await
    .map_err(|_| "timed out waiting for denied proxy timing event")?
    .map_err(Into::into)
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

fn summarize_phase_samples(samples: &[Vec<PhaseSample>]) -> Vec<PhaseReport> {
    let mut by_phase: BTreeMap<String, Vec<Duration>> = BTreeMap::new();
    for sample in samples {
        let mut sample_totals: BTreeMap<String, Duration> = BTreeMap::new();
        for phase in sample {
            *sample_totals.entry(phase.phase.clone()).or_default() += phase.duration;
        }
        for (phase, duration) in sample_totals {
            by_phase.entry(phase).or_default().push(duration);
        }
    }

    by_phase
        .into_iter()
        .map(|(phase, samples)| summarize_named_phase(&phase, &samples))
        .collect()
}

fn summarize_named_phase(phase: &str, samples: &[Duration]) -> PhaseReport {
    let mut sorted = samples.to_vec();
    sorted.sort();
    PhaseReport {
        phase: phase.into(),
        median_ms: duration_ms(sorted[sorted.len() / 2]),
        p99_ms: duration_ms(sorted[sorted.len() * 99 / 100]),
        samples_ms: samples.iter().copied().map(duration_ms).collect(),
    }
}

fn mean_duration(samples: &[Duration]) -> Duration {
    if samples.is_empty() {
        return Duration::ZERO;
    }
    let total_nanos = samples.iter().map(Duration::as_nanos).sum::<u128>() / samples.len() as u128;
    Duration::from_nanos(total_nanos.min(u64::MAX as u128) as u64)
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

    #[test]
    fn phase_summary_sums_duplicate_phases_per_sample() {
        let reports = summarize_phase_samples(&[
            vec![
                PhaseSample {
                    phase: "spawn.child".into(),
                    duration: Duration::from_millis(1),
                },
                PhaseSample {
                    phase: "spawn.child".into(),
                    duration: Duration::from_millis(2),
                },
            ],
            vec![PhaseSample {
                phase: "spawn.child".into(),
                duration: Duration::from_millis(5),
            }],
        ]);

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].phase, "spawn.child");
        assert_eq!(reports[0].samples_ms, vec![3.0, 5.0]);
    }

    #[test]
    fn startup_policy_profile_disables_all_resource_limits() {
        for provider in [
            RuntimeProviderCase::Auto,
            RuntimeProviderCase::Mxc,
            RuntimeProviderCase::AxisNative,
        ] {
            let policy = startup_policy(provider).unwrap();
            assert_eq!(policy.process.max_processes, 0);
            assert_eq!(policy.process.max_memory_mb, 0);
            assert_eq!(policy.process.cpu_rate_percent, 0);
        }
    }

    #[test]
    fn failed_rows_serialize_without_timing_fields() {
        let row = RuntimeMetricsRow {
            runtime_containment: "process",
            runtime_provider: "mxc",
            startup: StartupReport::Error {
                sample_index: 0,
                error: "injected startup failure".into(),
            },
            cold_proxy_deny: ColdProxyReport::Error {
                reason: "injected proxy failure".into(),
            },
            synthetic_opa: SyntheticOpaReport {
                evals_per_sec: 1.0,
                us_per_eval: 1.0,
            },
        };

        let value = serde_json::to_value(row).unwrap();
        let startup = value.get("startup").unwrap();
        assert_eq!(startup.get("status").unwrap(), "error");
        assert!(startup.get("median_ms").is_none());
        assert!(startup.get("phases").is_none());

        let cold = value.get("cold_proxy_deny").unwrap();
        assert_eq!(cold.get("status").unwrap(), "error");
        assert!(cold.get("latency_ms").is_none());
        assert!(cold.get("baseline_ms").is_none());
        assert!(cold.get("phases").is_none());
    }
}
