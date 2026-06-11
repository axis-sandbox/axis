// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Integration test: proxy with OPA policy evaluation.
//!
//! Starts a real proxy, sends CONNECT requests, verifies that allowed
//! hosts get 200 and denied hosts get 403.

use axis_core::connect_attribution::{
    ConnectAttributionRecord, ConnectAttributionSource, ConnectAttributionStore,
};
use axis_core::policy::Policy;
use axis_core::types::SandboxId;
use axis_proxy::proxy::{AxisProxy, ProxyConfig, ProxyTimingOutcome};
use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const TEST_POLICY: &str = r#"
version: 1
name: proxy-integration-test

network:
  mode: proxy
  policies:
    - name: github
      endpoints:
        - host: "api.github.com"
          port: 443
          access: read-write
    - name: pypi
      endpoints:
        - host: "pypi.org"
          port: 443
          access: read-only
    - name: inference
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write
"#;

async fn start_proxy() -> (SandboxId, std::net::SocketAddr) {
    start_proxy_with_inference(None).await
}

async fn start_proxy_with_inference(
    inference_ep: Option<std::net::SocketAddr>,
) -> (SandboxId, std::net::SocketAddr) {
    start_proxy_with_policy(TEST_POLICY, inference_ep).await
}

async fn start_proxy_with_policy(
    policy_yaml: &str,
    inference_ep: Option<std::net::SocketAddr>,
) -> (SandboxId, std::net::SocketAddr) {
    start_proxy_with_policy_and_roots(policy_yaml, inference_ep, Vec::new()).await
}

async fn start_proxy_with_policy_and_roots(
    policy_yaml: &str,
    inference_ep: Option<std::net::SocketAddr>,
    upstream_tls_roots_pem: Vec<String>,
) -> (SandboxId, std::net::SocketAddr) {
    start_proxy_with_policy_roots_and_attribution(
        policy_yaml,
        inference_ep,
        upstream_tls_roots_pem,
        None,
    )
    .await
}

async fn start_proxy_with_policy_roots_and_attribution(
    policy_yaml: &str,
    inference_ep: Option<std::net::SocketAddr>,
    upstream_tls_roots_pem: Vec<String>,
    connect_attribution: Option<ConnectAttributionStore>,
) -> (SandboxId, std::net::SocketAddr) {
    let policy = Policy::from_yaml(policy_yaml).unwrap();
    let sandbox_id = SandboxId::new();
    let config = ProxyConfig {
        sandbox_id,
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        policy,
        enable_l7: false,
        enable_leak_detection: true,
        upstream_tls_roots_pem,
        inference_endpoint: inference_ep,
        connect_attribution,
        timing_tx: None,
    };

    let mut proxy = AxisProxy::new(config).unwrap();
    let addr = proxy.bind().await.unwrap();

    // Spawn the proxy accept loop in the background.
    tokio::spawn(async move {
        let _ = proxy.run().await;
    });

    // Give the proxy a moment to start.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    (sandbox_id, addr)
}

#[tokio::test]
async fn denied_connect_emits_phase_timing_event() {
    let policy = Policy::from_yaml(TEST_POLICY).unwrap();
    let sandbox_id = SandboxId::new();
    let (timing_tx, mut timing_rx) = tokio::sync::mpsc::unbounded_channel();
    let config = ProxyConfig {
        sandbox_id,
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        policy,
        enable_l7: false,
        enable_leak_detection: false,
        upstream_tls_roots_pem: Vec::new(),
        inference_endpoint: None,
        connect_attribution: None,
        timing_tx: Some(timing_tx),
    };
    let mut proxy = AxisProxy::new(config).unwrap();
    let addr = proxy.bind().await.unwrap();
    let proxy_task = tokio::spawn(async move {
        let _ = proxy.run().await;
    });

    let status = send_connect(addr, "blocked.example.com:443").await;
    assert!(status.starts_with("HTTP/1.1 403"), "{status}");
    let event = tokio::time::timeout(std::time::Duration::from_secs(2), timing_rx.recv())
        .await
        .unwrap()
        .expect("proxy should emit timing for denied CONNECT");
    proxy_task.abort();

    assert_eq!(event.outcome, ProxyTimingOutcome::Denied);
    assert_eq!(event.target_host.as_deref(), Some("blocked.example.com"));
    assert_eq!(event.target_port, Some(443));
    let phases = event
        .phases
        .iter()
        .map(|phase| phase.phase)
        .collect::<Vec<_>>();
    assert!(phases.contains(&"identity_attribution"));
    assert!(phases.contains(&"request_parse"));
    assert!(phases.contains(&"opa_evaluation"));
    assert!(phases.contains(&"response_write"));
    assert!(phases.contains(&"total"));
}

async fn start_mock_tcp_server() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = listener.accept().await;
    });
    addr
}

async fn start_recording_http_server()
-> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<String>) {
    start_recording_http_server_until("\r\n\r\n").await
}

async fn start_recording_http_server_until(
    stop_pattern: &'static str,
) -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut received = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let read = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
                )
                .await;
                let n = match read {
                    Ok(Ok(n)) => n,
                    Ok(Err(_)) | Err(_) => break,
                };
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
                if String::from_utf8_lossy(&received).contains(stop_pattern) {
                    break;
                }
            }
            let _ = tx.send(String::from_utf8_lossy(&received).into_owned());
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
        }
    });
    (addr, rx)
}

async fn start_recording_https_server_until(
    hostname: &'static str,
    stop_pattern: &'static str,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<String>,
    String,
) {
    let (cert_pem, key_pem, ca_pem) = provider_tls_material(hostname);
    let mut cert_reader = cert_pem.as_bytes();
    let cert_chain = rustls_pemfile::certs(&mut cert_reader)
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();
    let mut key_reader = key_pem.as_bytes();
    let key = rustls_pemfile::private_key(&mut key_reader)
        .ok()
        .flatten()
        .unwrap();
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let Ok(mut stream) = acceptor.accept(stream).await else {
                let _ = tx.send(String::new());
                return;
            };
            let mut received = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let read = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
                )
                .await;
                let n = match read {
                    Ok(Ok(n)) => n,
                    Ok(Err(_)) | Err(_) => break,
                };
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
                if String::from_utf8_lossy(&received).contains(stop_pattern) {
                    break;
                }
            }
            let _ = tx.send(String::from_utf8_lossy(&received).into_owned());
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
        }
    });
    (addr, rx, ca_pem)
}

fn provider_tls_material(hostname: &str) -> (String, String, String) {
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);
    ca_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let mut leaf_params = rcgen::CertificateParams::new(vec![hostname.to_string()]).unwrap();
    leaf_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);
    leaf_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

    (leaf_cert.pem(), leaf_key.serialize_pem(), ca_cert.pem())
}

fn insecure_tls_connector() -> tokio_rustls::TlsConnector {
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(NoCertificateVerification))
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
}

#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

/// Send a CONNECT request and return the response status line.
async fn send_connect(proxy_addr: std::net::SocketAddr, target: &str) -> String {
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    send_connect_on_stream(&mut stream, target).await
}

async fn send_connect_on_stream(stream: &mut TcpStream, target: &str) -> String {
    use tokio::io::AsyncReadExt;

    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    let mut buf = [0u8; 1];
    while stream.read(&mut buf).await.unwrap_or(0) == 1 {
        response.push(buf[0]);
        if response.ends_with(b"\n") {
            break;
        }
    }
    String::from_utf8(response).unwrap()
}

async fn send_connect_with_attribution(
    store: &ConnectAttributionStore,
    sandbox_id: SandboxId,
    proxy_addr: SocketAddr,
    target: &str,
    executable_path: &str,
    executable_sha256: &str,
) -> String {
    let (socket, peer_addr) = bound_tcp_socket();
    store
        .insert(connect_attribution_record(
            sandbox_id,
            peer_addr,
            proxy_addr,
            executable_path,
            executable_sha256,
        ))
        .unwrap();
    let mut stream = socket.connect(proxy_addr).await.unwrap();
    send_connect_on_stream(&mut stream, target).await
}

fn bound_tcp_socket() -> (tokio::net::TcpSocket, SocketAddr) {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let peer_addr = socket.local_addr().unwrap();
    (socket, peer_addr)
}

fn connect_attribution_record(
    sandbox_id: SandboxId,
    peer_addr: SocketAddr,
    proxy_addr: SocketAddr,
    executable_path: &str,
    executable_sha256: &str,
) -> ConnectAttributionRecord {
    ConnectAttributionRecord {
        sandbox_id,
        peer_addr,
        proxy_addr,
        pid: 42,
        executable_path: executable_path.into(),
        executable_sha256: executable_sha256.into(),
        source: ConnectAttributionSource::Test,
    }
}

#[tokio::test]
async fn allowed_host_gets_200() {
    let (_sandbox_id, addr) = start_proxy().await;

    // api.github.com:443 is in the policy — should get 200.
    // Note: the upstream connection will fail (no real server), but the
    // proxy should attempt it, meaning it passed the OPA check.
    // We test by verifying we DON'T get a 403.
    let response = send_connect(addr, "api.github.com:443").await;

    // The proxy either returns 200 (if upstream connects) or drops
    // the connection (if upstream fails). It should NOT return 403.
    assert!(
        !response.contains("403"),
        "expected allow for api.github.com, got: {response}"
    );
}

#[tokio::test]
async fn denied_host_gets_403() {
    let (_sandbox_id, addr) = start_proxy().await;

    // evil.example.com is NOT in the policy — should get 403.
    let response = send_connect(addr, "evil.example.com:443").await;
    assert!(
        response.contains("403"),
        "expected 403 for evil.example.com, got: {response}"
    );
}

#[tokio::test]
async fn denied_wrong_port_gets_403() {
    let (_sandbox_id, addr) = start_proxy().await;

    // api.github.com on port 80 is NOT in the policy — should get 403.
    let response = send_connect(addr, "api.github.com:80").await;
    assert!(
        response.contains("403"),
        "expected 403 for api.github.com:80, got: {response}"
    );
}

#[tokio::test]
async fn second_allowed_host() {
    let (_sandbox_id, addr) = start_proxy().await;

    // pypi.org:443 is in the policy.
    let response = send_connect(addr, "pypi.org:443").await;
    assert!(
        !response.contains("403"),
        "expected allow for pypi.org, got: {response}"
    );
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn binary_policy_allows_current_test_binary() {
    let binary_path = std::env::current_exe().unwrap();
    let binary_path = binary_path.to_string_lossy().into_owned();
    let store = ConnectAttributionStore::default();
    let policy = format!(
        r#"
version: 1
name: proxy-binary-allow-test

network:
  mode: proxy
  policies:
    - name: current-test-binary
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write
      binaries:
        - path: "{}"
"#,
        binary_path
    );
    let upstream = start_mock_tcp_server().await;
    let (sandbox_id, addr) = start_proxy_with_policy_roots_and_attribution(
        &policy,
        Some(upstream),
        Vec::new(),
        Some(store.clone()),
    )
    .await;

    let response = send_connect_with_attribution(
        &store,
        sandbox_id,
        addr,
        "inference.local:443",
        &binary_path,
        &"a".repeat(64),
    )
    .await;
    assert!(
        response.contains("200"),
        "expected current test binary to match policy, got: {response}"
    );
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn binary_policy_does_not_fall_back_to_unknown_when_identity_is_available() {
    let policy = r#"
version: 1
name: proxy-binary-no-unknown-fallback-test

network:
  mode: proxy
  policies:
    - name: unknown-fallback
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write
      binaries:
        - path: "unknown"
"#;
    let (_sandbox_id, addr) = start_proxy_with_policy(policy, None).await;

    let response = send_connect(addr, "inference.local:443").await;
    assert!(
        response.contains("403"),
        "expected missing connect-time attribution to deny unknown fallback, got: {response}"
    );
}

#[tokio::test]
async fn binary_policy_denies_wrong_connect_time_binary() {
    let store = ConnectAttributionStore::default();
    let policy = r#"
version: 1
name: proxy-binary-deny-test

network:
  mode: proxy
  policies:
    - name: allowed-binary
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write
      binaries:
        - path: "/usr/bin/allowed"
"#;
    let (sandbox_id, addr) = start_proxy_with_policy_roots_and_attribution(
        policy,
        None,
        Vec::new(),
        Some(store.clone()),
    )
    .await;

    let response = send_connect_with_attribution(
        &store,
        sandbox_id,
        addr,
        "inference.local:443",
        "/usr/bin/denied",
        &"b".repeat(64),
    )
    .await;
    assert!(
        response.contains("403"),
        "expected denied connect-time binary to fail policy, got: {response}"
    );
}

#[tokio::test]
async fn binary_policy_denies_stale_connect_time_record() {
    let store = ConnectAttributionStore::new(std::time::Duration::from_millis(1));
    let policy = r#"
version: 1
name: proxy-binary-stale-test

network:
  mode: proxy
  policies:
    - name: allowed-binary
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write
      binaries:
        - path: "/usr/bin/allowed"
"#;
    let (sandbox_id, addr) = start_proxy_with_policy_roots_and_attribution(
        policy,
        None,
        Vec::new(),
        Some(store.clone()),
    )
    .await;

    let (socket, peer_addr) = bound_tcp_socket();
    store
        .insert(connect_attribution_record(
            sandbox_id,
            peer_addr,
            addr,
            "/usr/bin/allowed",
            &"a".repeat(64),
        ))
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let mut stream = socket.connect(addr).await.unwrap();

    let response = send_connect_on_stream(&mut stream, "inference.local:443").await;
    assert!(
        response.contains("403"),
        "expected stale connect-time record to deny, got: {response}"
    );
}

#[tokio::test]
async fn binary_policy_denies_ambiguous_connect_time_records() {
    let store = ConnectAttributionStore::default();
    let policy = r#"
version: 1
name: proxy-binary-ambiguous-test

network:
  mode: proxy
  policies:
    - name: allowed-binary
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write
      binaries:
        - path: "/usr/bin/allowed"
"#;
    let (sandbox_id, addr) = start_proxy_with_policy_roots_and_attribution(
        policy,
        None,
        Vec::new(),
        Some(store.clone()),
    )
    .await;

    let (socket, peer_addr) = bound_tcp_socket();
    store
        .insert(connect_attribution_record(
            sandbox_id,
            peer_addr,
            addr,
            "/usr/bin/allowed",
            &"a".repeat(64),
        ))
        .unwrap();
    store
        .insert(connect_attribution_record(
            sandbox_id,
            peer_addr,
            addr,
            "/usr/bin/other",
            &"b".repeat(64),
        ))
        .unwrap();
    let mut stream = socket.connect(addr).await.unwrap();

    let response = send_connect_on_stream(&mut stream, "inference.local:443").await;
    assert!(
        response.contains("403"),
        "expected ambiguous connect-time records to deny, got: {response}"
    );
}

#[tokio::test]
async fn provider_credentials_are_injected_at_proxy_boundary() {
    unsafe {
        std::env::set_var("AXIS_TEST_PROXY_PROVIDER_KEY", "provider-secret");
    }
    let policy = r#"
version: 1
name: proxy-credential-injection-test

network:
  mode: proxy
  policies:
    - name: inference
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write

inference:
  routes:
    - name: mock-provider
      endpoint: "http://inference.local:443"
      api_key_env: AXIS_TEST_PROXY_PROVIDER_KEY
"#;
    let (mock_addr, received) = start_recording_http_server().await;
    let (_sandbox_id, addr) = start_proxy_with_policy(policy, Some(mock_addr)).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"CONNECT inference.local:443 HTTP/1.1\r\nHost: inference.local\r\n\r\n")
        .await
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).await.unwrap();
    assert!(
        response_line.contains("200"),
        "expected CONNECT 200, got: {response_line}"
    );

    let mut stream = reader.into_inner();
    stream
        .write_all(
            b"POST /v1/chat/completions HTTP/1.1\r\nHost: inference.local\r\nContent-Length: 2\r\n\r\n{}",
        )
        .await
        .unwrap();

    let request = received.await.unwrap();
    unsafe {
        std::env::remove_var("AXIS_TEST_PROXY_PROVIDER_KEY");
    }

    assert!(request.contains("Authorization: Bearer provider-secret\r\n"));
    assert!(!request.contains("AXIS_TEST_PROXY_PROVIDER_KEY"));
}

#[tokio::test]
async fn https_provider_credentials_are_reencrypted_to_upstream_tls() {
    unsafe {
        std::env::set_var("AXIS_TEST_PROXY_TLS_PROVIDER_KEY", "provider-secret");
    }
    let policy = r#"
version: 1
name: proxy-credential-tls-injection-test

network:
  mode: proxy
  policies:
    - name: inference
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write

inference:
  routes:
    - name: mock-provider
      endpoint: "https://inference.local:443"
      api_key_env: AXIS_TEST_PROXY_TLS_PROVIDER_KEY
"#;
    let (mock_addr, received, ca_pem) =
        start_recording_https_server_until("inference.local", "\r\n\r\n").await;
    let (_sandbox_id, addr) =
        start_proxy_with_policy_and_roots(policy, Some(mock_addr), vec![ca_pem]).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"CONNECT inference.local:443 HTTP/1.1\r\nHost: inference.local\r\n\r\n")
        .await
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).await.unwrap();
    assert!(
        response_line.contains("200"),
        "expected CONNECT 200, got: {response_line}"
    );

    let stream = reader.into_inner();
    let server_name = rustls::pki_types::ServerName::try_from("inference.local").unwrap();
    let mut stream = insecure_tls_connector()
        .connect(server_name, stream)
        .await
        .unwrap();
    stream
        .write_all(
            b"POST /v1/chat/completions HTTP/1.1\r\nHost: inference.local\r\nContent-Length: 2\r\n\r\n{}",
        )
        .await
        .unwrap();

    let request = received.await.unwrap();
    unsafe {
        std::env::remove_var("AXIS_TEST_PROXY_TLS_PROVIDER_KEY");
    }

    assert!(request.contains("Authorization: Bearer provider-secret\r\n"));
    assert!(!request.contains("AXIS_TEST_PROXY_TLS_PROVIDER_KEY"));
}

#[tokio::test]
async fn provider_credentials_are_injected_for_each_request_on_same_tunnel() {
    unsafe {
        std::env::set_var("AXIS_TEST_PROXY_PIPELINED_KEY", "provider-secret");
    }
    let policy = r#"
version: 1
name: proxy-credential-keepalive-test

network:
  mode: proxy
  policies:
    - name: inference
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write

inference:
  routes:
    - name: mock-provider
      endpoint: "http://inference.local:443"
      api_key_env: AXIS_TEST_PROXY_PIPELINED_KEY
"#;
    let (mock_addr, received) = start_recording_http_server_until("/v1/models").await;
    let (_sandbox_id, addr) = start_proxy_with_policy(policy, Some(mock_addr)).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"CONNECT inference.local:443 HTTP/1.1\r\nHost: inference.local\r\n\r\n")
        .await
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).await.unwrap();
    assert!(
        response_line.contains("200"),
        "expected CONNECT 200, got: {response_line}"
    );

    let mut stream = reader.into_inner();
    stream
        .write_all(
            b"POST /v1/chat/completions HTTP/1.1\r\nHost: inference.local\r\nContent-Length: 2\r\n\r\n{}GET /v1/models HTTP/1.1\r\nHost: inference.local\r\n\r\n",
        )
        .await
        .unwrap();

    let request = received.await.unwrap();
    unsafe {
        std::env::remove_var("AXIS_TEST_PROXY_PIPELINED_KEY");
    }

    assert_eq!(
        request
            .matches("Authorization: Bearer provider-secret\r\n")
            .count(),
        2,
        "each HTTP request on a credential-bearing tunnel must be rewritten: {request}"
    );
    assert!(!request.contains("AXIS_TEST_PROXY_PIPELINED_KEY"));
}

#[tokio::test]
async fn unresolved_provider_credentials_are_not_forwarded() {
    unsafe {
        std::env::remove_var("AXIS_TEST_PROXY_MISSING_KEY");
    }
    let policy = r#"
version: 1
name: proxy-credential-missing-test

network:
  mode: proxy
  policies:
    - name: inference
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write

inference:
  routes:
    - name: mock-provider
      endpoint: "http://inference.local:443"
      api_key_env: AXIS_TEST_PROXY_MISSING_KEY
"#;
    let (mock_addr, received) = start_recording_http_server().await;
    let (_sandbox_id, addr) = start_proxy_with_policy(policy, Some(mock_addr)).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"CONNECT inference.local:443 HTTP/1.1\r\nHost: inference.local\r\n\r\n")
        .await
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).await.unwrap();
    assert!(
        response_line.contains("200"),
        "expected CONNECT 200 before inner request validation, got: {response_line}"
    );

    let mut stream = reader.into_inner();
    stream
        .write_all(b"POST /v1/chat/completions HTTP/1.1\r\nHost: inference.local\r\n\r\n")
        .await
        .unwrap();

    let request = received.await.unwrap();
    assert!(
        request.is_empty(),
        "missing credential must fail closed without forwarding request, got: {request}"
    );
}

#[tokio::test]
async fn inference_local_without_endpoint_gets_502() {
    // No inference endpoint configured — should get 502 Bad Gateway.
    let (_sandbox_id, addr) = start_proxy_with_inference(None).await;
    let response = send_connect(addr, "inference.local:443").await;
    assert!(
        response.contains("502"),
        "expected 502 for inference.local without endpoint, got: {response}"
    );
}

#[tokio::test]
async fn inference_local_routes_to_endpoint() {
    // Start a mock inference server.
    let mock_server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = mock_server.local_addr().unwrap();

    // Accept one connection and send a mock response.
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = mock_server.accept().await {
            // The proxy will establish a raw TCP connection.
            // Read whatever the client sends and respond.
            let mut buf = [0u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
            let response =
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"model\":\"test\"}";
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
        }
    });

    let (_sandbox_id, addr) = start_proxy_with_inference(Some(mock_addr)).await;

    // CONNECT to inference.local — proxy should route to our mock server.
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"CONNECT inference.local:443 HTTP/1.1\r\nHost: inference.local\r\n\r\n")
        .await
        .unwrap();

    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).await.unwrap();

    // Should get 200 Connection Established (proxy connected to mock).
    assert!(
        response_line.contains("200"),
        "expected 200 for inference.local with endpoint, got: {response_line}"
    );

    // Now send an HTTP request through the tunnel.
    let inner = reader.into_inner();
    let (mut read_half, mut write_half) = tokio::io::split(inner);
    write_half
        .write_all(b"GET /v1/models HTTP/1.1\r\nHost: inference.local\r\n\r\n")
        .await
        .unwrap();

    // Read the mock server's response through the tunnel.
    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut read_half, &mut buf)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&buf[..n]);
    assert!(
        body.contains("\"model\":\"test\""),
        "expected mock inference response, got: {body}"
    );
}

#[tokio::test]
async fn inference_local_relays_streaming_responses() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
                    .await
                    .unwrap_or(0);
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                if String::from_utf8_lossy(&request).contains("\r\n\r\n") {
                    break;
                }
            }
            let _ = tx.send(String::from_utf8_lossy(&request).into_owned());
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: {\"delta\":\"one\"}\n\n",
                )
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            stream.write_all(b"data: [DONE]\n\n").await.unwrap();
        }
    });

    let (_sandbox_id, addr) = start_proxy_with_inference(Some(mock_addr)).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"CONNECT inference.local:443 HTTP/1.1\r\nHost: inference.local\r\n\r\n")
        .await
        .unwrap();

    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).await.unwrap();
    assert!(
        response_line.contains("200"),
        "expected 200 for inference.local with endpoint, got: {response_line}"
    );

    let inner = reader.into_inner();
    let (mut read_half, mut write_half) = tokio::io::split(inner);
    write_half
        .write_all(b"POST /v1/responses HTTP/1.1\r\nHost: inference.local\r\n\r\n")
        .await
        .unwrap();

    let received = rx.await.unwrap();
    assert!(
        received.starts_with("POST /v1/responses HTTP/1.1"),
        "expected streaming request to reach mock provider, got: {received}"
    );

    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    for _ in 0..4 {
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::io::AsyncReadExt::read(&mut read_half, &mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        if String::from_utf8_lossy(&response).contains("data: [DONE]") {
            break;
        }
    }
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.contains("data: {\"delta\":\"one\"}") && response.contains("data: [DONE]"),
        "expected streaming chunks to relay through proxy, got: {response}"
    );
}
