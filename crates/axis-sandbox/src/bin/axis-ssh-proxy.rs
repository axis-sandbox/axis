// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Narrow HTTP CONNECT transport used by generated Windows OpenSSH config.

use std::io::{Read, Write};
use std::net::TcpStream;

fn main() {
    if let Err(error) = run() {
        eprintln!("axis-ssh-proxy: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let host = arguments.next().ok_or("missing SSH host")?;
    let port = arguments.next().ok_or("missing SSH port")?.parse::<u16>()?;
    if arguments.next().is_some()
        || host.is_empty()
        || host.chars().any(|character| {
            character.is_control() || character.is_whitespace() || matches!(character, '/' | '\\')
        })
    {
        return Err("invalid SSH CONNECT target".into());
    }

    let proxy = std::env::var("HTTP_PROXY").or_else(|_| std::env::var("http_proxy"))?;
    let proxy = proxy
        .strip_prefix("http://")
        .ok_or("HTTP_PROXY must use http://")?;
    let mut stream = TcpStream::connect(proxy)?;
    write!(
        stream,
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
    )?;
    stream.flush()?;

    let response = read_connect_response(&mut stream)?;
    if !response.starts_with("HTTP/1.1 200") {
        return Err(format!("proxy rejected {host}:{port}: {}", response.trim()).into());
    }

    let mut upload = stream.try_clone()?;
    let input = std::thread::spawn(move || {
        let _ = std::io::copy(&mut std::io::stdin().lock(), &mut upload);
    });
    std::io::copy(&mut stream, &mut std::io::stdout().lock())?;
    let _ = input.join();
    Ok(())
}

fn read_connect_response(stream: &mut TcpStream) -> Result<String, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    while bytes.len() < 64 * 1024 {
        if stream.read(&mut byte)? == 0 {
            break;
        }
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return Ok(String::from_utf8(bytes)?);
        }
    }
    Err("incomplete HTTP CONNECT response".into())
}
