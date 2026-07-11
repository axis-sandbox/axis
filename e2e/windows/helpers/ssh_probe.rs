// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::time::Duration;

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let result = match arguments.first().map(String::as_str) {
        Some("server") if arguments.len() == 2 => server(Path::new(&arguments[1])),
        Some("inspect") if arguments.len() == 3 => inspect(&arguments[1], Path::new(&arguments[2])),
        _ => Err("usage: ssh_probe server REQUEST_FILE | inspect KEY_FILE ORIGINAL_KEY".into()),
    };
    if let Err(error) = result {
        eprintln!("SSH_PROBE_ERROR={error}");
        std::process::exit(2);
    }
}

fn server(request_file: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:22")?;
    println!("PORT={}", listener.local_addr()?.port());
    std::io::stdout().flush()?;
    let (mut stream, _) = listener.accept()?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut request = [0u8; 1024];
    let read = stream.read(&mut request)?;
    std::fs::write(request_file, &request[..read])?;
    stream.write_all(b"SSH_TUNNEL_OK\n")?;
    stream.flush()?;
    Ok(())
}

fn inspect(key_file: &str, original_key: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let home = std::env::var("USERPROFILE")?;
    let ssh = Path::new(&home).join(".ssh");
    let config = std::fs::read_to_string(ssh.join("config"))?;
    for required in [
        "BatchMode yes",
        "IdentitiesOnly yes",
        "GlobalKnownHostsFile NUL",
        "ProxyCommand \"%d/.ssh/axis-ssh-proxy.exe\" %h %p",
        "ForwardAgent no",
        "ClearAllForwardings yes",
    ] {
        if !config.contains(required) {
            return Err(format!("generated config missing {required:?}").into());
        }
    }
    if config.contains("/dev/null") || !ssh.join("known_hosts").is_file() {
        return Err("generated Windows SSH files are incomplete".into());
    }
    if !ssh.join(key_file).is_file() || !ssh.join("axis-ssh-proxy.exe").is_file() {
        return Err("selected key or CONNECT helper was not projected".into());
    }
    if std::fs::read(original_key).is_ok() {
        return Err("original host private key remained readable".into());
    }
    println!("SSH_PROJECTION=1");
    Ok(())
}
