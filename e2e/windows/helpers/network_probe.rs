// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    match run() {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(10)
        }
    }
}

fn run() -> Result<String, String> {
    let mut args = env::args().skip(1);
    let operation = args.next().ok_or_else(usage)?;
    if operation == "hold" {
        let seconds = args
            .next()
            .ok_or_else(usage)?
            .parse::<u64>()
            .map_err(|error| format!("invalid hold duration: {error}"))?;
        if args.next().is_some() {
            return Err(usage());
        }
        println!("HOLDING pid={} seconds={seconds}", std::process::id());
        std::thread::sleep(Duration::from_secs(seconds));
        return Ok("HOLD_COMPLETE".into());
    }
    let delay = if operation == "delay-tcp" {
        Some(
            args.next()
                .ok_or_else(usage)?
                .parse::<u64>()
                .map_err(|error| format!("invalid delay: {error}"))?,
        )
    } else {
        None
    };
    let address = args
        .next()
        .ok_or_else(usage)?
        .parse::<IpAddr>()
        .map_err(|error| format!("invalid address: {error}"))?;
    let port = args
        .next()
        .ok_or_else(usage)?
        .parse::<u16>()
        .map_err(|error| format!("invalid port: {error}"))?;
    if args.next().is_some() {
        return Err(usage());
    }
    let remote = SocketAddr::new(address, port);
    match operation.as_str() {
        "tcp" | "tcp-hold" | "delay-tcp" => {
            if let Some(seconds) = delay {
                std::thread::sleep(Duration::from_secs(seconds));
            }
            match TcpStream::connect_timeout(&remote, Duration::from_secs(4)) {
            Ok(_) => Ok(format!("TCP_CONNECTED {remote}")),
            Err(error) => {
                if operation == "tcp-hold" {
                    std::thread::sleep(Duration::from_secs(2));
                }
                Err(format!("TCP_BLOCKED {remote}: {error}"))
            }
        }
        },
        "udp" => udp_probe(remote, UdpProbe::SendOnly),
        "dns" => udp_probe(remote, UdpProbe::Dns),
        "quic" => udp_probe(remote, UdpProbe::QuicVersionNegotiation),
        _ => Err(usage()),
    }
}

enum UdpProbe {
    SendOnly,
    Dns,
    QuicVersionNegotiation,
}

fn udp_probe(remote: SocketAddr, probe: UdpProbe) -> Result<String, String> {
    let bind = if remote.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = UdpSocket::bind(bind).map_err(|error| format!("UDP_BIND_FAILED: {error}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(4)))
        .map_err(|error| format!("UDP_TIMEOUT_CONFIG_FAILED: {error}"))?;
    socket
        .connect(remote)
        .map_err(|error| format!("UDP_BLOCKED {remote}: {error}"))?;

    let payload = match probe {
        UdpProbe::Dns => {
            // Standard recursive A query for example.com with transaction id 0x4158.
            b"\x41\x58\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01".to_vec()
        }
        UdpProbe::QuicVersionNegotiation => {
            // A 1200-byte long-header packet with an unsupported version. A
            // reachable QUIC listener answers with Version Negotiation before
            // it needs TLS keys, making this an adversarial raw-UDP proof.
            let mut packet = vec![0u8; 1200];
            packet[0] = 0xc0;
            packet[1..5].copy_from_slice(&0xface_b00cu32.to_be_bytes());
            packet[5] = 8;
            packet[6..14].copy_from_slice(b"AXISDCID");
            packet[14] = 8;
            packet[15..23].copy_from_slice(b"AXISSCID");
            packet
        }
        UdpProbe::SendOnly => b"axis-wfp-udp-probe".to_vec(),
    };
    socket
        .send(&payload)
        .map_err(|error| format!("UDP_BLOCKED {remote}: {error}"))?;
    if matches!(probe, UdpProbe::SendOnly) {
        return Ok(format!("UDP_SENT {remote}"));
    }

    let mut response = [0u8; 2048];
    let response_kind = if matches!(probe, UdpProbe::Dns) {
        "DNS"
    } else {
        "QUIC"
    };
    let length = socket
        .recv(&mut response)
        .map_err(|error| format!("{response_kind}_BLOCKED {remote}: {error}"))?;
    match probe {
        UdpProbe::Dns if length >= 2 && response[..2] == [0x41, 0x58] => {
            Ok(format!("DNS_RESPONSE {remote} bytes={length}"))
        }
        UdpProbe::QuicVersionNegotiation if length >= 5 && response[0] & 0x80 != 0 => {
            Ok(format!("QUIC_RESPONSE {remote} bytes={length}"))
        }
        UdpProbe::Dns => Err(format!("DNS_INVALID_RESPONSE {remote} bytes={length}")),
        UdpProbe::QuicVersionNegotiation => {
            Err(format!("QUIC_INVALID_RESPONSE {remote} bytes={length}"))
        }
        UdpProbe::SendOnly => unreachable!(),
    }
}

fn usage() -> String {
    "usage: network_probe hold <seconds> | delay-tcp <seconds> <ip> <port> | <tcp|tcp-hold|udp|dns|quic> <ip> <port>"
        .into()
}
