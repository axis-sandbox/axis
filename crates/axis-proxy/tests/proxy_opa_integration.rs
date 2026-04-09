// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Integration test: proxy with OPA policy evaluation.
//!
//! Starts a real proxy, sends CONNECT requests, verifies that allowed
//! hosts get 200 and denied hosts get 403.

use axis_core::policy::Policy;
use axis_core::types::SandboxId;
use axis_proxy::proxy::{AxisProxy, ProxyConfig};
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
    let policy = Policy::from_yaml(TEST_POLICY).unwrap();
    let sandbox_id = SandboxId::new();
    let config = ProxyConfig {
        sandbox_id,
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        policy,
        enable_l7: false,
        enable_leak_detection: true,
        inference_endpoint: inference_ep,
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

/// Send a CONNECT request and return the response status line.
async fn send_connect(proxy_addr: std::net::SocketAddr, target: &str) -> String {
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();

    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).await.unwrap();
    response_line
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
            let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"model\":\"test\"}";
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
    let n = tokio::io::AsyncReadExt::read(&mut read_half, &mut buf).await.unwrap();
    let body = String::from_utf8_lossy(&buf[..n]);
    assert!(
        body.contains("\"model\":\"test\""),
        "expected mock inference response, got: {body}"
    );
}
