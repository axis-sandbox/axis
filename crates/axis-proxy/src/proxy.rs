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
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::net::TcpListener;
#[cfg(target_os = "linux")]
use tokio::net::TcpSocket;

use crate::identity::{BinaryFingerprint, IdentityError, TofuStore};
use crate::secrets::CredentialInjector;

const MAX_HTTP_HEAD_BYTES: usize = 64 * 1024;

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
    /// Additional PEM-encoded trust anchors for upstream TLS provider tests or
    /// private provider deployments. System/webpki roots are always included.
    pub upstream_tls_roots_pem: Vec<String>,
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
    credential_injector: CredentialInjector,
    upstream_tls_roots: Vec<rustls::pki_types::CertificateDer<'static>>,
}

/// An AXIS HTTP CONNECT proxy serving a single sandbox.
pub struct AxisProxy {
    config: ProxyConfig,
    listener: Option<TcpListener>,
    state: Arc<Mutex<ProxyState>>,
}

impl AxisProxy {
    /// Create a new proxy with OPA policy evaluation.
    pub fn new(mut config: ProxyConfig) -> Result<Self, ProxyError> {
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

        let credential_injector = CredentialInjector::from_policy(&config.policy)
            .map_err(|e| ProxyError::BindFailed(format!("credential injection: {e}")))?;
        if credential_injector.has_rules() {
            config.enable_l7 = true;
        }
        let upstream_tls_roots = parse_upstream_tls_roots(&config.upstream_tls_roots_pem)
            .map_err(|e| ProxyError::BindFailed(format!("upstream TLS roots: {e}")))?;

        let state = Arc::new(Mutex::new(ProxyState {
            policy_engine,
            tofu_store: TofuStore::new(),
            audit_log: AuditLog::new(),
            leak_detector,
            credential_injector,
            upstream_tls_roots,
        }));

        Ok(Self {
            config,
            listener: None,
            state,
        })
    }

    /// Start listening for proxy connections.
    pub async fn bind(&mut self) -> Result<SocketAddr, ProxyError> {
        let listener = bind_proxy_listener(self.config.bind_addr).await?;

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
            let proxy_addr = stream.local_addr()?;
            // Resolve immediately after accept, before any sandbox-controlled
            // request bytes are consumed. TCP does not expose kernel
            // connect-time credentials, so ambiguous proc identities fail
            // closed inside the resolver.
            let binary_identity = resolve_binary_identity(peer_addr, proxy_addr);
            let sandbox_id = self.config.sandbox_id;
            let state = Arc::clone(&self.state);
            let enable_l7 = self.config.enable_l7;
            let inference_endpoint = self.config.inference_endpoint;

            tokio::spawn(async move {
                if let Err(e) = handle_connection(
                    sandbox_id,
                    stream,
                    peer_addr,
                    binary_identity,
                    state,
                    enable_l7,
                    inference_endpoint,
                )
                .await
                {
                    tracing::warn!("sandbox {sandbox_id}: connection from {peer_addr} failed: {e}");
                }
            });
        }
    }
}

async fn bind_proxy_listener(bind_addr: SocketAddr) -> Result<TcpListener, ProxyError> {
    #[cfg(target_os = "linux")]
    {
        if linux_proxy_bind_requires_freebind(bind_addr) {
            return bind_linux_freebind_listener(bind_addr);
        }
    }

    TcpListener::bind(bind_addr)
        .await
        .map_err(|e| ProxyError::BindFailed(e.to_string()))
}

#[cfg(target_os = "linux")]
fn linux_proxy_bind_requires_freebind(bind_addr: SocketAddr) -> bool {
    match bind_addr.ip() {
        std::net::IpAddr::V4(addr) => !addr.is_loopback() && !addr.is_unspecified(),
        std::net::IpAddr::V6(_) => false,
    }
}

#[cfg(target_os = "linux")]
fn bind_linux_freebind_listener(bind_addr: SocketAddr) -> Result<TcpListener, ProxyError> {
    let socket = match bind_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }
    .map_err(|e| ProxyError::BindFailed(e.to_string()))?;
    socket
        .set_reuseaddr(true)
        .map_err(|e| ProxyError::BindFailed(e.to_string()))?;
    set_ip_freebind(socket.as_raw_fd()).map_err(|e| ProxyError::BindFailed(e.to_string()))?;
    socket
        .bind(bind_addr)
        .map_err(|e| ProxyError::BindFailed(e.to_string()))?;
    socket
        .listen(1024)
        .map_err(|e| ProxyError::BindFailed(e.to_string()))
}

#[cfg(target_os = "linux")]
fn set_ip_freebind(fd: std::os::fd::RawFd) -> std::io::Result<()> {
    let enabled: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_FREEBIND,
            &enabled as *const libc::c_int as *const libc::c_void,
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Handle a single proxy connection with full policy evaluation.
async fn handle_connection(
    sandbox_id: SandboxId,
    mut stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    binary_identity: Result<Option<BinaryFingerprint>, IdentityError>,
    state: Arc<Mutex<ProxyState>>,
    enable_l7: bool,
    inference_endpoint: Option<SocketAddr>,
) -> Result<(), ProxyError> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let identity_check = {
        let mut st = state.lock().unwrap();
        verify_binary_identity(&mut st.tofu_store, binary_identity)
    };
    let (binary_path, binary_sha256) = match identity_check {
        Ok(identity) => identity,
        Err(e) => {
            tracing::warn!("sandbox {sandbox_id}: binary identity check failed: {e}");
            send_forbidden_response(
                &mut stream,
                "AXIS policy denied connection\r\nReason: binary identity check failed\r\n",
            )
            .await?;
            return Ok(());
        }
    };

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

    // 4. Evaluate OPA network policy.
    let decision = {
        let mut st = state.lock().unwrap();

        let action = NetworkAction {
            host: host.clone(),
            port,
            binary_path: binary_path.clone(),
            binary_sha256: binary_sha256.clone(),
            sandbox_id,
        };

        let decision = st.policy_engine.eval_network(&action).unwrap_or_else(|e| {
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
        let reason = decision.reason.as_deref().unwrap_or("policy denied");
        tracing::info!(
            "sandbox {sandbox_id}: DENIED {host}:{port} (binary={binary_path}, reason={reason})"
        );

        // Send HTTP 403 Forbidden.
        let mut stream = reader.into_inner();
        let body =
            format!("AXIS policy denied connection to {host}:{port}\r\nReason: {reason}\r\n");
        send_forbidden_response(&mut stream, &body).await?;
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
            tracing::info!("sandbox {sandbox_id}: routing inference.local -> {ep}");
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

    if enable_l7 {
        relay_with_l7_inspection(sandbox_id, &host, port, stream, upstream, state).await
    } else if leak_enabled {
        relay_with_leak_detection(sandbox_id, &host, port, false, stream, upstream, state).await
    } else {
        relay_plain(stream, upstream).await
    }
}

/// L7 relay: peek for TLS, terminate if detected, inspect HTTP, scan for leaks.
async fn relay_with_l7_inspection(
    sandbox_id: SandboxId,
    hostname: &str,
    port: u16,
    client: tokio::net::TcpStream,
    upstream: tokio::net::TcpStream,
    state: Arc<Mutex<ProxyState>>,
) -> Result<(), ProxyError> {
    // Peek first byte to detect TLS ClientHello (0x16 = TLS handshake).
    let mut peek_buf = [0u8; 1];
    let n = client.peek(&mut peek_buf).await?;

    if n > 0 && peek_buf[0] == 0x16 {
        // TLS detected — terminate and inspect.
        tracing::debug!("sandbox {sandbox_id}: L7 TLS detected for {hostname}, terminating");
        relay_tls_inspected(sandbox_id, hostname, port, client, upstream, state).await
    } else {
        // Not TLS — relay with leak detection on plaintext.
        tracing::debug!("sandbox {sandbox_id}: L7 plaintext for {hostname}");
        relay_with_leak_detection(sandbox_id, hostname, port, false, client, upstream, state).await
    }
}

/// TLS-terminating relay: accept TLS from client, inspect plaintext, forward to upstream.
async fn relay_tls_inspected(
    sandbox_id: SandboxId,
    hostname: &str,
    port: u16,
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

    tracing::info!("sandbox {sandbox_id}: L7 TLS terminated for {hostname}");

    let upstream_tls_roots = {
        let st = state.lock().unwrap();
        st.upstream_tls_roots.clone()
    };
    let upstream = connect_tls_upstream(hostname, upstream, &upstream_tls_roots).await?;
    relay_tls_inspected_to_upstream(sandbox_id, hostname, port, tls_client, upstream, state).await
}

async fn relay_tls_inspected_to_upstream(
    sandbox_id: SandboxId,
    hostname: &str,
    port: u16,
    tls_client: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    tls_upstream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    state: Arc<Mutex<ProxyState>>,
) -> Result<(), ProxyError> {
    let (mut cr, mut cw) = tokio::io::split(tls_client);
    let (mut ur, mut uw) = tokio::io::split(tls_upstream);

    let state_c2u = Arc::clone(&state);
    let sid = sandbox_id;
    let hostname = hostname.to_string();
    let c2u = async move {
        relay_client_to_upstream_with_policy(
            sid, &hostname, port, true, &mut cr, &mut uw, state_c2u,
        )
        .await?;
        Ok::<_, std::io::Error>(())
    };

    let u2c = tokio::io::copy(&mut ur, &mut cw);

    tokio::select! {
        r = c2u => { r.map_err(ProxyError::Io)?; }
        r = u2c => { r?; }
    }
    Ok(())
}

async fn connect_tls_upstream(
    hostname: &str,
    upstream: tokio::net::TcpStream,
    extra_roots: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, ProxyError> {
    let mut root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    for cert in extra_roots {
        root_store
            .add(cert.clone())
            .map_err(|e| ProxyError::ConnectionError(format!("invalid upstream TLS root: {e}")))?;
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let server_name =
        rustls::pki_types::ServerName::try_from(hostname.to_string()).map_err(|_| {
            ProxyError::ConnectionError(format!("invalid TLS upstream name: {hostname}"))
        })?;
    connector
        .connect(server_name, upstream)
        .await
        .map_err(|e| ProxyError::ConnectionError(format!("TLS upstream {hostname}: {e}")))
}

fn parse_upstream_tls_roots(
    root_pems: &[String],
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    let mut roots = Vec::new();
    for pem in root_pems {
        let mut reader = pem.as_bytes();
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        if certs.is_empty() {
            return Err("PEM block did not contain a certificate".into());
        }
        roots.extend(certs);
    }
    Ok(roots)
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
    hostname: &str,
    port: u16,
    is_tls: bool,
    stream: tokio::net::TcpStream,
    upstream: tokio::net::TcpStream,
    state: Arc<Mutex<ProxyState>>,
) -> Result<(), ProxyError> {
    let (mut cr, mut cw) = tokio::io::split(stream);
    let (mut ur, mut uw) = tokio::io::split(upstream);

    // Client -> upstream: scan sandbox-origin bytes, then inject host-side
    // provider credentials into each matching HTTP request head.
    let state_c2u = Arc::clone(&state);
    let hostname = hostname.to_string();
    let c2u = async move {
        relay_client_to_upstream_with_policy(
            sandbox_id, &hostname, port, is_tls, &mut cr, &mut uw, state_c2u,
        )
        .await?;
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

async fn relay_client_to_upstream_with_policy<R, W>(
    sandbox_id: SandboxId,
    hostname: &str,
    port: u16,
    is_tls: bool,
    client_read: &mut R,
    upstream_write: &mut W,
    state: Arc<Mutex<ProxyState>>,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let requires_injection = {
        let st = state.lock().unwrap();
        st.credential_injector
            .connection_requires_injection(hostname, port, is_tls)
    };
    if !requires_injection {
        return relay_scanned_bytes(sandbox_id, client_read, upstream_write, state).await;
    }

    let mut buf = vec![0u8; 65536];
    let mut pending = Vec::new();
    let mut body_remaining = 0usize;
    loop {
        let n = tokio::io::AsyncReadExt::read(client_read, &mut buf).await?;
        if n == 0 {
            break;
        }

        scan_sandbox_bytes(sandbox_id, &buf[..n], &state)?;
        pending.extend_from_slice(&buf[..n]);

        loop {
            if body_remaining > 0 {
                let take = body_remaining.min(pending.len());
                if take == 0 {
                    break;
                }
                tokio::io::AsyncWriteExt::write_all(upstream_write, &pending[..take]).await?;
                pending.drain(..take);
                body_remaining -= take;
                if body_remaining > 0 {
                    break;
                }
                continue;
            }

            let Some(head_end) = find_http_head_end(&pending) else {
                if pending.len() > MAX_HTTP_HEAD_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!(
                            "credential injection failed closed for {hostname}: HTTP request head exceeds {MAX_HTTP_HEAD_BYTES} bytes"
                        ),
                    ));
                }
                break;
            };

            let head = pending[..head_end].to_vec();
            let next_body_len = http_body_length(&head)?;
            let rewritten = {
                let st = state.lock().unwrap();
                st.credential_injector
                    .rewrite_http_request_head(hostname, port, is_tls, &head)
                    .map_err(secret_error_to_io)?
            };
            if let Some(rewritten_head) = rewritten {
                tokio::io::AsyncWriteExt::write_all(upstream_write, &rewritten_head).await?;
            } else {
                tokio::io::AsyncWriteExt::write_all(upstream_write, &head).await?;
            }
            pending.drain(..head_end);
            body_remaining = next_body_len;

            if body_remaining == 0 {
                continue;
            }
        }
    }

    if body_remaining == 0 && !pending.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "credential injection failed closed for {hostname}: incomplete HTTP request head"
            ),
        ));
    }
    if !pending.is_empty() {
        tokio::io::AsyncWriteExt::write_all(upstream_write, &pending).await?;
    }
    Ok(())
}

fn http_body_length(head: &[u8]) -> std::io::Result<usize> {
    let text = std::str::from_utf8(head).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "credential injection failed closed: HTTP request head is not UTF-8",
        )
    })?;
    let mut length = None;
    for line in text.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("transfer-encoding") && !value.trim().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "credential injection failed closed: transfer-encoded request bodies are not supported",
            ));
        }
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = value.trim().parse::<usize>().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "credential injection failed closed: invalid Content-Length",
                )
            })?;
            if let Some(existing) = length {
                if existing != parsed {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "credential injection failed closed: conflicting Content-Length values",
                    ));
                }
            }
            length = Some(parsed);
        }
    }
    Ok(length.unwrap_or(0))
}

async fn relay_scanned_bytes<R, W>(
    sandbox_id: SandboxId,
    client_read: &mut R,
    upstream_write: &mut W,
    state: Arc<Mutex<ProxyState>>,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 65536];
    loop {
        let n = tokio::io::AsyncReadExt::read(client_read, &mut buf).await?;
        if n == 0 {
            break;
        }
        scan_sandbox_bytes(sandbox_id, &buf[..n], &state)?;
        tokio::io::AsyncWriteExt::write_all(upstream_write, &buf[..n]).await?;
    }
    Ok(())
}

fn scan_sandbox_bytes(
    sandbox_id: SandboxId,
    bytes: &[u8],
    state: &Arc<Mutex<ProxyState>>,
) -> std::io::Result<()> {
    let st = state.lock().unwrap();
    if let Some(ref detector) = st.leak_detector {
        let findings = detector.scan(bytes);
        for finding in &findings {
            tracing::warn!(
                "sandbox {sandbox_id}: CREDENTIAL LEAK in outgoing data: {} at offset {}",
                finding.pattern_name,
                finding.byte_offset,
            );
            st.audit_log
                .credential_leak_detected(sandbox_id, finding.pattern_name);
        }
        if !findings.is_empty() {
            tracing::warn!(
                "sandbox {sandbox_id}: BLOCKED outgoing data ({} bytes) due to credential leak",
                bytes.len()
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "credential leak detected in outgoing data",
            ));
        }
    }
    Ok(())
}

fn secret_error_to_io(error: crate::secrets::SecretError) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!("credential injection failed closed: {error}"),
    )
}

fn find_http_head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|idx| idx + 4)
        .or_else(|| {
            bytes
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|idx| idx + 2)
        })
}

/// Resolve the calling binary path from the peer address.
/// On Linux: /proc/[pid]/net/tcp → socket inode → PID → /proc/[pid]/exe.
fn resolve_binary_identity(
    peer_addr: SocketAddr,
    proxy_addr: SocketAddr,
) -> Result<Option<BinaryFingerprint>, IdentityError> {
    #[cfg(target_os = "linux")]
    {
        crate::identity::resolve_peer_identity(peer_addr, proxy_addr).map(Some)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = peer_addr;
        let _ = proxy_addr;
        Ok(None)
    }
}

fn verify_binary_identity(
    tofu_store: &mut TofuStore,
    identity: Result<Option<BinaryFingerprint>, IdentityError>,
) -> Result<(String, String), IdentityError> {
    let Some(identity) = identity? else {
        return Ok(("unknown".into(), "unknown".into()));
    };
    tofu_store.verify_fingerprint(&identity)?;
    Ok((
        identity.path.to_string_lossy().into_owned(),
        identity.sha256,
    ))
}

async fn send_forbidden_response(
    stream: &mut tokio::net::TcpStream,
    body: &str,
) -> Result<(), ProxyError> {
    use tokio::io::AsyncWriteExt;

    let response = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
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
        let (host, port) = parse_connect_target("CONNECT api.github.com:443 HTTP/1.1\r\n").unwrap();
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
    fn find_http_head_end_accepts_crlf_and_lf_heads() {
        assert_eq!(
            find_http_head_end(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody"),
            Some(37)
        );
        assert_eq!(
            find_http_head_end(b"GET / HTTP/1.1\nHost: example.com\n\nbody"),
            Some(34)
        );
    }

    #[test]
    fn http_body_length_reads_content_length() {
        let len =
            http_body_length(b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 12\r\n\r\n")
                .unwrap();
        assert_eq!(len, 12);
    }

    #[test]
    fn http_body_length_rejects_chunked_bodies() {
        let err = http_body_length(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("transfer-encoded"));
    }

    #[test]
    fn http_body_length_rejects_invalid_content_length() {
        let err = http_body_length(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: nope\r\n\r\n",
        )
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("Content-Length"));
    }

    #[test]
    fn http_body_length_rejects_conflicting_content_lengths() {
        let err = http_body_length(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n",
        )
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("conflicting Content-Length"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_freebind_is_used_only_for_nonlocal_ipv4_binds() {
        assert!(linux_proxy_bind_requires_freebind(
            "10.200.0.1:3128".parse().unwrap()
        ));
        assert!(!linux_proxy_bind_requires_freebind(
            "127.0.0.1:3128".parse().unwrap()
        ));
        assert!(!linux_proxy_bind_requires_freebind(
            "0.0.0.0:3128".parse().unwrap()
        ));
        assert!(!linux_proxy_bind_requires_freebind(
            "[::1]:3128".parse().unwrap()
        ));
    }

    #[test]
    fn verify_binary_identity_preserves_unsupported_unknown() {
        let mut tofu_store = TofuStore::new();
        let identity = verify_binary_identity(&mut tofu_store, Ok(None)).unwrap();
        assert_eq!(identity, ("unknown".into(), "unknown".into()));
    }

    #[test]
    fn verify_binary_identity_propagates_resolver_error() {
        let mut tofu_store = TofuStore::new();
        let err = verify_binary_identity(
            &mut tofu_store,
            Err(IdentityError::ResolveFailed {
                pid: 0,
                reason: "ambiguous socket owner".into(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, IdentityError::ResolveFailed { .. }));
    }

    #[test]
    fn verify_binary_identity_rejects_tofu_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("binary");
        std::fs::write(&binary, b"content").unwrap();
        let mut tofu_store = TofuStore::new();
        tofu_store
            .verify_fingerprint(&BinaryFingerprint {
                path: binary.clone(),
                sha256: "0".repeat(64),
            })
            .unwrap();

        let err = verify_binary_identity(
            &mut tofu_store,
            Ok(Some(BinaryFingerprint {
                path: binary,
                sha256: "1".repeat(64),
            })),
        )
        .unwrap_err();
        assert!(matches!(err, IdentityError::HashMismatch { .. }));
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
            upstream_tls_roots_pem: Vec::new(),
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
            upstream_tls_roots_pem: Vec::new(),
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
        assert!(
            !deny_decision.allowed,
            "expected deny, got: {deny_decision:?}"
        );
    }
}
