// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Network namespace + veth pair creation for sandbox network isolation.
//!
//! Creates a network namespace with a veth pair routing all sandbox traffic
//! through the AXIS proxy. All bypass attempts are logged and rejected.
//!
//! Strategy: use `ip` commands which handle the netns/veth/iptables setup.
//! This requires either root (via setuid helper) or CAP_NET_ADMIN.
//! For unprivileged sandboxes, we use `unshare --net` in the pre_exec path
//! and set up the namespace from the parent.

use std::process::Command;

/// Create a network namespace with veth pair and iptables rules.
///
/// The namespace routes all traffic through the AXIS proxy.
/// Returns the namespace name on success.
pub fn create_netns(sandbox_name: &str, proxy_port: u16) -> Result<String, String> {
    let ns_name = format!("axis-{sandbox_name}");
    let veth_host = format!("axh-{}", &sandbox_name[..sandbox_name.len().min(8)]);
    let veth_sandbox = format!("axs-{}", &sandbox_name[..sandbox_name.len().min(8)]);

    let strategy = detect_strategy();
    tracing::info!("netns: using strategy '{strategy}' for namespace '{ns_name}'");

    match strategy {
        NetnsStrategy::IpNetns => create_with_ip_netns(&ns_name, &veth_host, &veth_sandbox, proxy_port),
        NetnsStrategy::Bubblewrap => {
            // Bubblewrap mode: network isolation is all-or-nothing (no proxy).
            // The sandbox gets --unshare-net which creates an isolated netns
            // with no connectivity at all.
            tracing::info!("netns: bubblewrap mode — sandbox will have no network access");
            Ok(ns_name)
        }
        NetnsStrategy::Unavailable => {
            Err("no network namespace strategy available (need ip command or bubblewrap)".into())
        }
    }
}

/// Create netns using the `ip` command (requires CAP_NET_ADMIN or root).
fn create_with_ip_netns(
    ns_name: &str,
    veth_host: &str,
    veth_sandbox: &str,
    proxy_port: u16,
) -> Result<String, String> {
    // 1. Create the network namespace.
    run_cmd("ip", &["netns", "add", ns_name])?;

    // 2. Create veth pair.
    run_cmd("ip", &[
        "link", "add", veth_host, "type", "veth", "peer", "name", veth_sandbox,
    ])?;

    // 3. Move sandbox end into the namespace.
    run_cmd("ip", &["link", "set", veth_sandbox, "netns", ns_name])?;

    // 4. Configure host side: 10.200.0.1/30.
    run_cmd("ip", &["addr", "add", "10.200.0.1/30", "dev", veth_host])?;
    run_cmd("ip", &["link", "set", veth_host, "up"])?;

    // 5. Configure sandbox side: 10.200.0.2/30.
    run_cmd("ip", &["netns", "exec", ns_name, "ip", "addr", "add", "10.200.0.2/30", "dev", veth_sandbox])?;
    run_cmd("ip", &["netns", "exec", ns_name, "ip", "link", "set", veth_sandbox, "up"])?;
    run_cmd("ip", &["netns", "exec", ns_name, "ip", "link", "set", "lo", "up"])?;

    // 6. Default route in sandbox via host veth.
    run_cmd("ip", &["netns", "exec", ns_name, "ip", "route", "add", "default", "via", "10.200.0.1"])?;

    // 7. iptables in sandbox namespace: ACCEPT proxy, LOG+REJECT everything else.
    let port_str = proxy_port.to_string();

    // Allow traffic to the proxy.
    run_cmd("ip", &[
        "netns", "exec", ns_name, "iptables",
        "-A", "OUTPUT", "-d", "10.200.0.1", "-p", "tcp", "--dport", &port_str,
        "-j", "ACCEPT",
    ])?;

    // Allow established/related connections (return traffic).
    run_cmd("ip", &[
        "netns", "exec", ns_name, "iptables",
        "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED",
        "-j", "ACCEPT",
    ])?;

    // Allow loopback.
    run_cmd("ip", &[
        "netns", "exec", ns_name, "iptables",
        "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT",
    ])?;

    // Log bypass attempts.
    run_cmd("ip", &[
        "netns", "exec", ns_name, "iptables",
        "-A", "OUTPUT", "-j", "LOG", "--log-prefix", "AXIS-BYPASS: ", "--log-level", "4",
    ])?;

    // Reject everything else.
    run_cmd("ip", &[
        "netns", "exec", ns_name, "iptables",
        "-A", "OUTPUT", "-j", "REJECT",
    ])?;

    // 8. Enable IP forwarding on host for NAT (so proxy can reach the internet).
    // This is a no-op if already enabled.
    let _ = run_cmd("sysctl", &["-w", "net.ipv4.ip_forward=1"]);

    // 9. NAT masquerade for outbound traffic from the sandbox subnet.
    let _ = run_cmd("iptables", &[
        "-t", "nat", "-A", "POSTROUTING", "-s", "10.200.0.0/30", "-j", "MASQUERADE",
    ]);

    tracing::info!(
        "netns: created '{ns_name}' with veth {veth_host}<->{veth_sandbox}, proxy=10.200.0.1:{proxy_port}"
    );
    Ok(ns_name.to_string())
}

/// Destroy a network namespace and clean up its veth pair.
pub fn destroy_netns(ns_name: &str) -> Result<(), String> {
    // Deleting the namespace also deletes the veth pair.
    let result = run_cmd("ip", &["netns", "del", ns_name]);
    if let Err(e) = &result {
        tracing::warn!("netns: failed to delete '{ns_name}': {e}");
    }
    // Remove NAT rule (best-effort).
    let _ = run_cmd("iptables", &[
        "-t", "nat", "-D", "POSTROUTING", "-s", "10.200.0.0/30", "-j", "MASQUERADE",
    ]);
    Ok(())
}

/// Enter an existing network namespace (for axis exec).
/// Returns an fd to the namespace that can be used with setns().
pub fn enter_netns(ns_name: &str) -> Result<i32, String> {
    let ns_path = format!("/var/run/netns/{ns_name}");
    let fd = unsafe {
        libc::open(
            std::ffi::CString::new(ns_path.as_str()).unwrap().as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!("cannot open netns '{ns_name}': {}", std::io::Error::last_os_error()));
    }
    Ok(fd)
}

/// Run a command, returning Ok on success or Err with stderr on failure.
fn run_cmd(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run {program}: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("{program} {} failed: {stderr}", args.join(" ")))
    }
}

/// Check which netns creation strategy is available on this system.
pub fn detect_strategy() -> NetnsStrategy {
    // Check if `ip netns` is available and we have permission.
    if let Ok(output) = Command::new("ip").args(["netns", "list"]).output() {
        if output.status.success() {
            return NetnsStrategy::IpNetns;
        }
    }

    // Check for bubblewrap.
    if which("bwrap") {
        return NetnsStrategy::Bubblewrap;
    }

    NetnsStrategy::Unavailable
}

fn which(binary: &str) -> bool {
    Command::new("which")
        .arg(binary)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Available strategies for network namespace creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetnsStrategy {
    /// Use `ip netns` commands (requires CAP_NET_ADMIN or root).
    IpNetns,
    /// Use bubblewrap --unshare-net (no proxy, just network isolation).
    Bubblewrap,
    /// No strategy available.
    Unavailable,
}

impl std::fmt::Display for NetnsStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IpNetns => write!(f, "ip netns (CAP_NET_ADMIN)"),
            Self::Bubblewrap => write!(f, "bubblewrap (--unshare-net)"),
            Self::Unavailable => write!(f, "unavailable"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_strategy_returns_value() {
        let strategy = detect_strategy();
        eprintln!("detected netns strategy: {strategy}");
    }

    #[test]
    fn run_cmd_works() {
        assert!(run_cmd("true", &[]).is_ok());
        assert!(run_cmd("false", &[]).is_err());
    }
}
