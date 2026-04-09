// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! HTTP CONNECT proxy with per-connection OPA policy evaluation.
//!
//! Each sandbox gets its own proxy instance. On every CONNECT request:
//! 1. Parse target host:port
//! 2. Resolve calling binary (TOFU identity)
//! 3. Evaluate OPA network policy → allow or deny
//! 4. If allowed, relay bytes; optionally run leak detection
//! 5. Log decision via OCSF audit

use axis_core::audit::AuditLog;
use axis_core::opa::PolicyEngine;
use axis_core::policy::Policy;
use axis_core::types::{NetworkAction, SandboxId};
use axis_safety::leak_detect::LeakDetector;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::net::TcpListener;

use crate::identity::TofuStore;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("failed to bind proxy: {0}")]
    BindFailed(String),

    #[error("connection error: {0}")]
    ConnectionError(String),

    #[error("policy denied connection to {host}:{port}: {reason}")]
    PolicyDenied {
        host: String,
        port: u16,
        reason: String,
    },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Configuration for an AXIS proxy instance.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub sandbox_id: SandboxId,
    pub bind_addr: SocketAddr,
    pub policy: Policy,
    pub enable_l7: bool,
    pub enable_leak_detection: bool,
    /// Local inference server endpoint for `inference.local` virtual host.
    /// When set, CONNECT requests to `inference.local` are routed here
    /// instead of the real internet.
    pub inference_endpoint: Option<SocketAddr>,
}

/// Shared state for the proxy, protected by a Mutex for thread-safe access.
struct ProxyState {
    policy_engine: PolicyEngine,
    tofu_store: TofuStore,
    audit_log: AuditLog,
    leak_detector: Option<LeakDetector>,
}

/// An AXIS HTTP CONNECT proxy serving a single sandbox.
pub struct AxisProxy {
    config: ProxyConfig,
    listener: Option<TcpListener>,
    state: Arc<Mutex<ProxyState>>,
}

impl AxisProxy {
    /// Create a new proxy with OPA policy evaluation.
    pub fn new(config: ProxyConfig) -> Result<Self, ProxyError> {
        // Initialize the OPA policy engine with the sandbox policy.
        let mut policy_engine = PolicyEngine::new()
            .map_err(|e| ProxyError::BindFailed(format!("OPA engine init: {e}")))?;
        policy_engine
            .load_policy(&config.policy)
            .map_err(|e| ProxyError::BindFailed(format!("OPA policy load: {e}")))?;

        // Initialize leak detector if enabled.
        let leak_detector = if config.enable_leak_detection {
            Some(
                LeakDetector::new()
                    .map_err(|e| ProxyError::BindFailed(format!("leak detector: {e}")))?,
            )
        } else {
            None
        };

        let state = Arc::new(Mutex::new(ProxyState {
            policy_engine,
            tofu_store: TofuStore::new(),
            audit_log: AuditLog::new(),
            leak_detector,
        }));

        Ok(Self {
            config,
            listener: None,
            state,
        })
    }

    /// Start listening for proxy connections.
    pub async fn bind(&mut self) -> Result<SocketAddr, ProxyError> {
        let listener = TcpListener::bind(self.config.bind_addr)
            .await
            .map_err(|e| ProxyError::BindFailed(e.to_string()))?;

        let addr = listener.local_addr()?;
        tracing::info!(
            "proxy for sandbox {} listening on {addr}",
            self.config.sandbox_id,
        );
        self.listener = Some(listener);
        Ok(addr)
    }

    /// Run the proxy accept loop. Blocks until shutdown.
    pub async fn run(&self) -> Result<(), ProxyError> {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| ProxyError::BindFailed("not bound".into()))?;

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let sandbox_id = self.config.sandbox_id;
            let state = Arc::clone(&self.state);
            let enable_l7 = self.config.enable_l7;
            let inference_endpoint = self.config.inference_endpoint;

            tokio::spawn(async move {
                if let Err(e) =
                    handle_connection(sandbox_id, stream, peer_addr, state, enable_l7, inference_endpoint).await
                {
                    tracing::warn!(
                        "sandbox {sandbox_id}: connection from {peer_addr} failed: {e}"
                    );
                }
            });
        }
    }
}

/// Handle a single proxy connection with full policy evaluation.
async fn handle_connection(
    sandbox_id: SandboxId,
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    state: Arc<Mutex<ProxyState>>,
    _enable_l7: bool,
    inference_endpoint: Option<SocketAddr>,
) -> Result<(), ProxyError> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut reader = BufReader::new(stream);

    // 1. Read the CONNECT request line.
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    let (host, port) = parse_connect_target(&request_line)?;

    tracing::debug!("sandbox {sandbox_id}: CONNECT {host}:{port} from {peer_addr}");

    // 2. Read remaining headers (consume until empty line).
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }

    // 3. Resolve calling binary identity.
    //    On Linux we'd resolve via /proc/net/tcp → PID → /proc/[pid]/exe.
    //    For now, use the peer address to identify the caller.
    let binary_path = resolve_binary_path(peer_addr);
    let binary_sha256 = "unknown".to_string();

    // 4. Evaluate OPA network policy.
    let decision = {
        let mut st = state.lock().unwrap();

        // TOFU identity check (if we have a real path).
        if binary_path != "unknown" {
            if let Ok(path) = std::path::Path::new(&binary_path).canonicalize() {
                match st.tofu_store.verify(&path) {
                    Ok(_fp) => {}
                    Err(e) => {
                        tracing::warn!("sandbox {sandbox_id}: TOFU check failed for {binary_path}: {e}");
                    }
                }
            }
        }

        let action = NetworkAction {
            host: host.clone(),
            port,
            binary_path: binary_path.clone(),
            binary_sha256: binary_sha256.clone(),
            sandbox_id,
        };

        let decision = st
            .policy_engine
            .eval_network(&action)
            .unwrap_or_else(|e| {
                tracing::error!("OPA eval failed: {e}, defaulting to deny");
                axis_core::types::PolicyDecision {
                    allowed: false,
                    matched_policy: None,
                    reason: Some(format!("OPA error: {e}")),
                }
            });

        // Audit log the decision.
        st.audit_log
            .network_decision(sandbox_id, &host, port, &decision);

        decision
    };

    // 5. Enforce the decision.
    if !decision.allowed {
        let reason = decision
            .reason
            .as_deref()
            .unwrap_or("policy denied");
        tracing::info!(
            "sandbox {sandbox_id}: DENIED {host}:{port} (binary={binary_path}, reason={reason})"
        );

        // Send HTTP 403 Forbidden.
        let mut stream = reader.into_inner();
        let body = format!(
            "AXIS policy denied connection to {host}:{port}\r\nReason: {reason}\r\n"
        );
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    let matched = decision.matched_policy.as_deref().unwrap_or("?");
    tracing::info!(
        "sandbox {sandbox_id}: ALLOWED {host}:{port} (policy={matched}, binary={binary_path})"
    );

    // 6. Connect to upstream.
    //    If the target is `inference.local`, route to the local inference server.
    let is_inference_local = host == "inference.local" || host.starts_with("inference.local:");
    let upstream_target = if is_inference_local {
        if let Some(ep) = inference_endpoint {
            tracing::info!(
                "sandbox {sandbox_id}: routing inference.local -> {ep}"
            );
            ep.to_string()
        } else {
            // No inference endpoint configured — return 502.
            let mut stream = reader.into_inner();
            let body = "AXIS: no local inference server configured\r\n";
            let response = format!(
                "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await?;
            return Ok(());
        }
    } else {
        format!("{host}:{port}")
    };

    let upstream = tokio::net::TcpStream::connect(&upstream_target)
        .await
        .map_err(|e| ProxyError::ConnectionError(format!("upstream {upstream_target}: {e}")))?;

    // 7. Send 200 Connection Established.
    let mut stream = reader.into_inner();
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    // 8. Bidirectional relay with optional L7 inspection and leak detection.
    let leak_enabled = {
        let st = state.lock().unwrap();
        st.leak_detector.is_some()
    };

    if _enable_l7 {
        relay_with_l7_inspection(sandbox_id, &host, stream, upstream, state).await
    } else if leak_enabled {
        relay_with_leak_detection(sandbox_id, stream, upstream, state).await
    } else {
        relay_plain(stream, upstream).await
    }
}

/// L7 relay: peek for TLS, terminate if detected, inspect HTTP, scan for leaks.
async fn relay_with_l7_inspection(
    sandbox_id: SandboxId,
    hostname: &str,
    mut client: tokio::net::TcpStream,
    upstream: tokio::net::TcpStream,
    state: Arc<Mutex<ProxyState>>,
) -> Result<(), ProxyError> {
    use tokio::io::AsyncReadExt;

    // Peek first byte to detect TLS ClientHello (0x16 = TLS handshake).
    let mut peek_buf = [0u8; 1];
    let n = client.peek(&mut peek_buf).await?;

    if n > 0 && peek_buf[0] == 0x16 {
        // TLS detected — terminate and inspect.
        tracing::debug!(
            "sandbox {sandbox_id}: L7 TLS detected for {hostname}, terminating"
        );
        relay_tls_inspected(sandbox_id, hostname, client, upstream, state).await
    } else {
        // Not TLS — relay with leak detection on plaintext.
        tracing::debug!(
            "sandbox {sandbox_id}: L7 plaintext for {hostname}"
        );
        relay_with_leak_detection(sandbox_id, client, upstream, state).await
    }
}

/// TLS-terminating relay: accept TLS from client, inspect plaintext, forward to upstream.
async fn relay_tls_inspected(
    sandbox_id: SandboxId,
    hostname: &str,
    client: tokio::net::TcpStream,
    upstream: tokio::net::TcpStream,
    state: Arc<Mutex<ProxyState>>,
) -> Result<(), ProxyError> {
    // Generate a leaf certificate for this hostname.
    let leaf = {
        let ca = crate::l7::tls::SandboxCa::generate(&sandbox_id.to_string())
            .map_err(|e| ProxyError::ConnectionError(format!("CA generation: {e}")))?;
        ca.issue_leaf(hostname)
            .map_err(|e| ProxyError::ConnectionError(format!("leaf cert: {e}")))?
    };

    // Build rustls ServerConfig with the leaf cert.
    let cert_chain = rustls_pemfile::certs(&mut leaf.cert_pem.as_bytes())
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();
    let key = rustls_pemfile::private_key(&mut leaf.key_pem.as_bytes())
        .ok()
        .flatten()
        .ok_or_else(|| ProxyError::ConnectionError("cannot parse leaf key".into()))?;

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| ProxyError::ConnectionError(format!("TLS server config: {e}")))?;

    let tls_acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));

    // Accept TLS from the client.
    let tls_client = tls_acceptor
        .accept(client)
        .await
        .map_err(|e| ProxyError::ConnectionError(format!("TLS accept: {e}")))?;

    tracing::info!(
        "sandbox {sandbox_id}: L7 TLS terminated for {hostname}"
    );

    // Now relay plaintext between decrypted client and raw upstream.
    // The upstream connection stays plaintext (the proxy is the TLS endpoint).
    // Scan the decrypted traffic for credential leaks.
    let (mut cr, mut cw) = tokio::io::split(tls_client);
    let (mut ur, mut uw) = tokio::io::split(upstream);

    let state_c2u = Arc::clone(&state);
    let sid = sandbox_id;
    let c2u = async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = tokio::io::AsyncReadExt::read(&mut cr, &mut buf).await?;
            if n == 0 { break; }

            // Scan decrypted outgoing data for credential leaks.
            {
                let st = state_c2u.lock().unwrap();
                if let Some(ref detector) = st.leak_detector {
                    let findings = detector.scan(&buf[..n]);
                    for f in &findings {
                        tracing::warn!(
                            "sandbox {sid}: L7 CREDENTIAL LEAK in TLS traffic: {} at offset {}",
                            f.pattern_name, f.byte_offset,
                        );
                        st.audit_log.credential_leak_detected(sid, f.pattern_name);
                    }
                    if !findings.is_empty() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "credential leak in TLS-decrypted traffic",
                        ));
                    }
                }
            }

            tokio::io::AsyncWriteExt::write_all(&mut uw, &buf[..n]).await?;
        }
        Ok::<_, std::io::Error>(())
    };

    let u2c = tokio::io::copy(&mut ur, &mut cw);

    tokio::select! {
        r = c2u => { r.map_err(ProxyError::Io)?; }
        r = u2c => { r?; }
    }
    Ok(())
}

/// Plain bidirectional TCP relay (no inspection).
async fn relay_plain(
    stream: tokio::net::TcpStream,
    upstream: tokio::net::TcpStream,
) -> Result<(), ProxyError> {
    let (mut cr, mut cw) = tokio::io::split(stream);
    let (mut ur, mut uw) = tokio::io::split(upstream);

    let c2u = tokio::io::copy(&mut cr, &mut uw);
    let u2c = tokio::io::copy(&mut ur, &mut cw);

    tokio::select! {
        r = c2u => { r?; }
        r = u2c => { r?; }
    }
    Ok(())
}

/// Bidirectional relay with leak detection on response data.
async fn relay_with_leak_detection(
    sandbox_id: SandboxId,
    stream: tokio::net::TcpStream,
    upstream: tokio::net::TcpStream,
    state: Arc<Mutex<ProxyState>>,
) -> Result<(), ProxyError> {
    let (mut cr, mut cw) = tokio::io::split(stream);
    let (mut ur, mut uw) = tokio::io::split(upstream);

    // Client → upstream: scan outgoing data for leaked credentials.
    let state_c2u = Arc::clone(&state);
    let c2u = async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = tokio::io::AsyncReadExt::read(&mut cr, &mut buf).await?;
            if n == 0 {
                break;
            }

            // Scan outgoing data for credential leaks.
            {
                let st = state_c2u.lock().unwrap();
                if let Some(ref detector) = st.leak_detector {
                    let findings = detector.scan(&buf[..n]);
                    for finding in &findings {
                        tracing::warn!(
                            "sandbox {sandbox_id}: CREDENTIAL LEAK in outgoing data: {} at offset {}",
                            finding.pattern_name,
                            finding.byte_offset,
                        );
                        st.audit_log.credential_leak_detected(
                            sandbox_id,
                            finding.pattern_name,
                        );
                    }
                    if !findings.is_empty() {
                        // Block the data — don't forward it.
                        tracing::warn!(
                            "sandbox {sandbox_id}: BLOCKED outgoing data ({n} bytes) due to credential leak"
                        );
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "credential leak detected in outgoing data",
                        ));
                    }
                }
            }

            tokio::io::AsyncWriteExt::write_all(&mut uw, &buf[..n]).await?;
        }
        Ok::<_, std::io::Error>(())
    };

    // Upstream → client: pass through (response data is less likely to leak creds).
    let u2c = tokio::io::copy(&mut ur, &mut cw);

    tokio::select! {
        r = c2u => { r.map_err(ProxyError::Io)?; }
        r = u2c => { r?; }
    }
    Ok(())
}

/// Resolve the calling binary path from the peer address.
/// On Linux: /proc/net/tcp → socket inode → PID → /proc/[pid]/exe.
fn resolve_binary_path(peer_addr: SocketAddr) -> String {
    #[cfg(target_os = "linux")]
    {
        match crate::identity::resolve_peer_binary(peer_addr) {
            Ok(path) => return path.to_string_lossy().into_owned(),
            Err(e) => {
                tracing::debug!("binary resolution failed for {peer_addr}: {e}");
            }
        }
    }
    let _ = peer_addr;
    "unknown".to_string()
}

/// Parse "CONNECT host:port HTTP/1.1" into (host, port).
fn parse_connect_target(request_line: &str) -> Result<(String, u16), ProxyError> {
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 || !parts[0].eq_ignore_ascii_case("CONNECT") {
        return Err(ProxyError::ConnectionError(format!(
            "invalid CONNECT request: {request_line}"
        )));
    }

    let target = parts[1];
    if let Some((host, port_str)) = target.rsplit_once(':') {
        let port: u16 = port_str.parse().map_err(|_| {
            ProxyError::ConnectionError(format!("invalid port in CONNECT target: {target}"))
        })?;
        Ok((host.to_string(), port))
    } else {
        Ok((target.to_string(), 443))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_connect_host_port() {
        let (host, port) =
            parse_connect_target("CONNECT api.github.com:443 HTTP/1.1\r\n").unwrap();
        assert_eq!(host, "api.github.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_connect_no_port() {
        let (host, port) = parse_connect_target("CONNECT example.com HTTP/1.1\r\n").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_connect_invalid() {
        assert!(parse_connect_target("GET / HTTP/1.1\r\n").is_err());
    }

    #[test]
    fn proxy_config_creates_with_policy() {
        let policy = Policy::from_yaml("version: 1\nname: test\n").unwrap();
        let config = ProxyConfig {
            sandbox_id: SandboxId::new(),
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            policy,
            enable_l7: false,
            enable_leak_detection: true,
            inference_endpoint: None,
        };
        let proxy = AxisProxy::new(config);
        assert!(proxy.is_ok(), "proxy creation failed: {:?}", proxy.err());
    }

    #[test]
    fn proxy_with_full_policy() {
        let policy_yaml = r#"
version: 1
name: test-proxy-policy
network:
  mode: proxy
  policies:
    - name: allowed-api
      endpoints:
        - host: "api.example.com"
          port: 443
"#;
        let policy = Policy::from_yaml(policy_yaml).unwrap();
        let config = ProxyConfig {
            sandbox_id: SandboxId::new(),
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            policy,
            enable_l7: false,
            enable_leak_detection: false,
            inference_endpoint: None,
        };
        let proxy = AxisProxy::new(config).unwrap();
        // Verify the proxy state was initialized correctly.
        let st = proxy.state.lock().unwrap();
        let action = NetworkAction {
            host: "api.example.com".into(),
            port: 443,
            binary_path: "unknown".into(),
            binary_sha256: "unknown".into(),
            sandbox_id: SandboxId::new(),
        };
        drop(st);

        // Test policy evaluation through the proxy's engine.
        let mut st = proxy.state.lock().unwrap();
        let decision = st.policy_engine.eval_network(&action).unwrap();
        assert!(decision.allowed, "expected allow, got: {decision:?}");
        assert_eq!(decision.matched_policy.as_deref(), Some("allowed-api"));

        // Test deny for unknown host.
        let deny_action = NetworkAction {
            host: "evil.example.com".into(),
            port: 443,
            binary_path: "unknown".into(),
            binary_sha256: "unknown".into(),
            sandbox_id: SandboxId::new(),
        };
        let deny_decision = st.policy_engine.eval_network(&deny_action).unwrap();
        assert!(!deny_decision.allowed, "expected deny, got: {deny_decision:?}");
    }
}
