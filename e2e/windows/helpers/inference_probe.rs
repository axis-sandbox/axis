// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::Duration;

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let result = match arguments.first().map(String::as_str) {
        Some("provider") if arguments.len() == 2 => run_provider(Path::new(&arguments[1])),
        Some("client") if arguments.len() == 4 => {
            run_client(&arguments[1], &arguments[2], &arguments[3])
        }
        _ => Err("usage: inference_probe provider REQUEST_FILE | client HOST PORT MAX_TOKENS".into()),
    };
    if let Err(error) = result {
        eprintln!("INFERENCE_ERROR={error}");
        std::process::exit(2);
    }
}

fn run_provider(request_file: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    println!("PORT={}", listener.local_addr()?.port());
    std::io::stdout().flush()?;
    let (mut stream, _) = listener.accept()?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let request = read_http_message(&mut stream).unwrap_or_default();
    std::fs::write(request_file, &request)?;
    if !request.is_empty() {
        let body = b"data: {\"id\":\"axis-test\"}\n\ndata: [DONE]\n\n";
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )?;
        stream.write_all(body)?;
        stream.flush()?;
    }
    Ok(())
}

fn run_client(host: &str, port: &str, max_tokens: &str) -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os("AXIS_TEST_WINDOWS_PROVIDER_KEY").is_some() {
        return Err("provider secret environment variable crossed the sandbox boundary".into());
    }
    println!("SECRET_ENV=0");
    let proxy = std::env::var("HTTP_PROXY").or_else(|_| std::env::var("http_proxy"))?;
    let proxy = proxy
        .strip_prefix("http://")
        .ok_or("HTTP_PROXY is not an http URL")?;
    let mut stream = TcpStream::connect(proxy)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(
        stream,
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
    )?;
    stream.flush()?;
    let connect_response = read_http_head(&mut stream)?;
    if !connect_response.starts_with("HTTP/1.1 200") {
        return Err(format!("CONNECT rejected: {connect_response:?}").into());
    }

    let body = format!("{{\"model\":\"axis-test\",\"max_tokens\":{max_tokens}}}");
    write!(
        stream,
        "POST /v1/chat/completions HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    if !response.contains("200 OK") || !response.contains("data: [DONE]") {
        return Err(format!("provider response missing streaming proof: {response:?}").into());
    }
    println!("STREAMING=1");
    Ok(())
}

fn read_http_head(stream: &mut TcpStream) -> Result<String, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    while bytes.len() < 64 * 1024 {
        let read = stream.read(&mut byte)?;
        if read == 0 {
            break;
        }
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    Ok(String::from_utf8(bytes)?)
}

fn read_http_message(stream: &mut TcpStream) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => bytes.extend_from_slice(&buffer[..read]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(error) => return Err(error.into()),
        }
        if let Some(head_end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            let head_end = head_end + 4;
            let head = String::from_utf8_lossy(&bytes[..head_end]);
            let content_length = head
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                })
                .unwrap_or(0);
            if bytes.len() >= head_end + content_length {
                break;
            }
        }
    }
    Ok(bytes)
}
