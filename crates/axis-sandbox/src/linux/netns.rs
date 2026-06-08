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

use axis_core::types::SandboxId;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::Command;

const PROXY_NET_A: u8 = 10;
const PROXY_PREFIX_LEN: u8 = 30;
const PROXY_SUBNET_COUNT: u32 = 1 << 22;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyNetnsAllocation {
    pub namespace: String,
    pub veth_host: String,
    pub veth_sandbox: String,
    pub host_addr: Ipv4Addr,
    pub sandbox_addr: Ipv4Addr,
    pub host_cidr: String,
    pub sandbox_cidr: String,
    pub subnet_cidr: String,
    pub proxy_addr: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetnsCommand {
    program: &'static str,
    args: Vec<String>,
    ignore_missing_link: bool,
}

trait CommandRunner {
    fn run(&mut self, command: &NetnsCommand) -> Result<(), String>;
}

struct ProcessCommandRunner;

impl CommandRunner for ProcessCommandRunner {
    fn run(&mut self, command: &NetnsCommand) -> Result<(), String> {
        let args: Vec<&str> = command.args.iter().map(String::as_str).collect();
        run_cmd(command.program, &args)
    }
}

/// Create a network namespace with veth pair and iptables rules.
///
/// The namespace routes all traffic through the AXIS proxy.
/// Returns the namespace name on success.
pub fn create_netns(sandbox_id: SandboxId, proxy_port: u16) -> Result<String, String> {
    let allocation = proxy_netns_allocation(sandbox_id, proxy_port);

    let strategy = detect_strategy();
    tracing::info!(
        "netns: using strategy '{strategy}' for namespace '{}'",
        allocation.namespace
    );

    match strategy {
        NetnsStrategy::IpNetns => {
            let mut runner = ProcessCommandRunner;
            match create_with_runner(&allocation, &mut runner) {
                Ok(name) => Ok(name),
                Err(e) => Err(e),
            }
        }
        NetnsStrategy::Bubblewrap => {
            // Bubblewrap mode: network isolation is all-or-nothing (no proxy).
            // The sandbox gets --unshare-net which creates an isolated netns
            // with no connectivity at all.
            tracing::info!("netns: bubblewrap mode — sandbox will have no network access");
            Ok(allocation.namespace)
        }
        NetnsStrategy::Unavailable => {
            Err("no network namespace strategy available (need ip command or bubblewrap)".into())
        }
    }
}

pub fn proxy_bind_addr(sandbox_id: SandboxId, proxy_port: u16) -> SocketAddr {
    proxy_netns_allocation(sandbox_id, proxy_port).proxy_addr
}

pub fn proxy_netns_allocation(sandbox_id: SandboxId, proxy_port: u16) -> ProxyNetnsAllocation {
    let sandbox_name = sandbox_id.to_string();
    let namespace = format!("axis-{sandbox_name}");
    let veth_host = veth_host_name(&sandbox_name);
    let veth_sandbox = veth_sandbox_name(&sandbox_name);
    let subnet_index = subnet_index(sandbox_id);
    let network_host_bits = subnet_index << 2;
    let host_addr = proxy_addr_from_host_bits(network_host_bits + 1);
    let sandbox_addr = proxy_addr_from_host_bits(network_host_bits + 2);
    let network_addr = proxy_addr_from_host_bits(network_host_bits);
    ProxyNetnsAllocation {
        namespace,
        veth_host,
        veth_sandbox,
        host_addr,
        sandbox_addr,
        host_cidr: format!("{host_addr}/{PROXY_PREFIX_LEN}"),
        sandbox_cidr: format!("{sandbox_addr}/{PROXY_PREFIX_LEN}"),
        subnet_cidr: format!("{network_addr}/{PROXY_PREFIX_LEN}"),
        proxy_addr: SocketAddr::new(host_addr.into(), proxy_port),
    }
}

fn subnet_index(sandbox_id: SandboxId) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for byte in sandbox_id.0.as_bytes() {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash % PROXY_SUBNET_COUNT
}

fn proxy_addr_from_host_bits(host_bits: u32) -> Ipv4Addr {
    debug_assert!(host_bits < (1 << 24));
    Ipv4Addr::new(
        PROXY_NET_A,
        (host_bits >> 16) as u8,
        (host_bits >> 8) as u8,
        host_bits as u8,
    )
}

fn create_with_runner(
    allocation: &ProxyNetnsAllocation,
    runner: &mut dyn CommandRunner,
) -> Result<String, String> {
    for command in create_command_plan(allocation) {
        if let Err(e) = runner.run(&command) {
            if let Err(cleanup) = destroy_with_runner(&allocation.namespace, runner) {
                tracing::warn!("netns cleanup after create failure failed: {cleanup}");
            }
            return Err(e);
        }
    }

    tracing::info!(
        "netns: created '{}' with veth {}<->{}, proxy={}",
        allocation.namespace,
        allocation.veth_host,
        allocation.veth_sandbox,
        allocation.proxy_addr
    );
    Ok(allocation.namespace.clone())
}

fn create_command_plan(allocation: &ProxyNetnsAllocation) -> Vec<NetnsCommand> {
    let ns = &allocation.namespace;
    let host = &allocation.veth_host;
    let sandbox = &allocation.veth_sandbox;
    let proxy_port = allocation.proxy_addr.port().to_string();
    vec![
        ip(["netns", "add", ns]),
        ip(["link", "add", host, "type", "veth", "peer", "name", sandbox]),
        ip(["link", "set", sandbox, "netns", ns]),
        ip(["addr", "add", &allocation.host_cidr, "dev", host]),
        ip(["link", "set", host, "up"]),
        ip([
            "netns",
            "exec",
            ns,
            "ip",
            "addr",
            "add",
            &allocation.sandbox_cidr,
            "dev",
            sandbox,
        ]),
        ip(["netns", "exec", ns, "ip", "link", "set", sandbox, "up"]),
        ip(["netns", "exec", ns, "ip", "link", "set", "lo", "up"]),
        ip([
            "netns",
            "exec",
            ns,
            "sysctl",
            "-w",
            "net.ipv6.conf.all.disable_ipv6=1",
        ]),
        ip([
            "netns",
            "exec",
            ns,
            "sysctl",
            "-w",
            "net.ipv6.conf.default.disable_ipv6=1",
        ]),
        ip([
            "netns",
            "exec",
            ns,
            "ip",
            "route",
            "add",
            "default",
            "via",
            &allocation.host_addr.to_string(),
        ]),
        ip(["netns", "exec", ns, "iptables", "-P", "OUTPUT", "DROP"]),
        ip([
            "netns", "exec", ns, "iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT",
        ]),
        ip([
            "netns",
            "exec",
            ns,
            "iptables",
            "-A",
            "OUTPUT",
            "-d",
            &allocation.host_addr.to_string(),
            "-p",
            "tcp",
            "--dport",
            &proxy_port,
            "-j",
            "ACCEPT",
        ]),
        ip([
            "netns",
            "exec",
            ns,
            "iptables",
            "-A",
            "OUTPUT",
            "-j",
            "LOG",
            "--log-prefix",
            "AXIS-BYPASS: ",
            "--log-level",
            "4",
        ]),
        ip([
            "netns", "exec", ns, "iptables", "-A", "OUTPUT", "-j", "REJECT",
        ]),
    ]
}

/// Destroy a network namespace and clean up its veth pair.
pub fn destroy_netns(ns_name: &str) -> Result<(), String> {
    let mut runner = ProcessCommandRunner;
    destroy_with_runner(ns_name, &mut runner)
}

fn destroy_with_runner(ns_name: &str, runner: &mut dyn CommandRunner) -> Result<(), String> {
    let sandbox_name = sandbox_name_from_netns(ns_name);
    let mut failures = Vec::new();
    for command in destroy_command_plan(ns_name, sandbox_name) {
        if let Err(e) = runner.run(&command) {
            if command.ignore_missing_link && is_missing_link_error(&e) {
                tracing::debug!("netns cleanup command ignored absent link: {e}");
                continue;
            }
            tracing::debug!("netns cleanup command failed: {e}");
            failures.push(e);
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn destroy_command_plan(ns_name: &str, sandbox_name: &str) -> Vec<NetnsCommand> {
    vec![
        ip(["netns", "del", ns_name]),
        ip_ignore_missing_link(["link", "del", &veth_host_name(sandbox_name)]),
    ]
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
        return Err(format!(
            "cannot open netns '{ns_name}': {}",
            std::io::Error::last_os_error()
        ));
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

fn sandbox_name_from_netns(ns_name: &str) -> &str {
    ns_name.strip_prefix("axis-").unwrap_or(ns_name)
}

fn veth_host_name(sandbox_name: &str) -> String {
    format!("axh{}", veth_suffix(sandbox_name))
}

fn veth_sandbox_name(sandbox_name: &str) -> String {
    format!("axs{}", veth_suffix(sandbox_name))
}

fn veth_suffix(sandbox_name: &str) -> String {
    let suffix: String = sandbox_name
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(12)
        .collect();
    if suffix.is_empty() {
        "000000000000".into()
    } else {
        suffix
    }
}

fn ip(args: impl IntoIterator<Item = impl AsRef<str>>) -> NetnsCommand {
    NetnsCommand {
        program: "ip",
        args: args
            .into_iter()
            .map(|arg| arg.as_ref().to_string())
            .collect(),
        ignore_missing_link: false,
    }
}

fn ip_ignore_missing_link(args: impl IntoIterator<Item = impl AsRef<str>>) -> NetnsCommand {
    NetnsCommand {
        ignore_missing_link: true,
        ..ip(args)
    }
}

fn is_missing_link_error(error: &str) -> bool {
    error.contains("Cannot find device")
        || error.contains("does not exist")
        || error.contains("No such device")
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
    use std::str::FromStr;

    #[derive(Default)]
    struct FakeRunner {
        commands: Vec<NetnsCommand>,
        fail_at: Option<usize>,
        failure_message: Option<String>,
    }

    impl CommandRunner for FakeRunner {
        fn run(&mut self, command: &NetnsCommand) -> Result<(), String> {
            self.commands.push(command.clone());
            if self.fail_at == Some(self.commands.len()) {
                Err(self.failure_message.clone().unwrap_or_else(|| {
                    format!(
                        "forced failure: {} {}",
                        command.program,
                        command.args.join(" ")
                    )
                }))
            } else {
                Ok(())
            }
        }
    }

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

    #[test]
    fn veth_names_are_derived_from_sandbox_id_prefix() {
        assert_eq!(veth_host_name("1234567890abcdef"), "axh1234567890ab");
        assert_eq!(veth_sandbox_name("1234567890abcdef"), "axs1234567890ab");
        assert_eq!(veth_host_name("zzzz"), "axh000000000000");
    }

    #[test]
    fn proxy_allocation_is_deterministic_and_per_sandbox() {
        let first = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let second = SandboxId::from_str("00010000-0000-4000-8000-000000000001").unwrap();

        let first_alloc = proxy_netns_allocation(first, 3128);
        let second_alloc = proxy_netns_allocation(second, 3128);
        let first_alloc_again = proxy_netns_allocation(first, 3128);

        assert_eq!(first_alloc, first_alloc_again);
        assert_eq!(first_alloc.host_addr.octets()[0], PROXY_NET_A);
        assert_eq!(first_alloc.sandbox_addr.octets()[0], PROXY_NET_A);
        assert!(first_alloc.host_cidr.ends_with("/30"));
        assert_eq!(first_alloc.proxy_addr, SocketAddr::new(first_alloc.host_addr.into(), 3128));
        assert_ne!(first_alloc.subnet_cidr, second_alloc.subnet_cidr);
        assert_ne!(first_alloc.veth_host, second_alloc.veth_host);
    }

    #[test]
    fn proxy_allocation_uses_full_uuid_not_just_first_two_bytes() {
        let first = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let same_prefix = SandboxId::from_str("00000000-0001-4000-8000-000000000002").unwrap();

        let first_alloc = proxy_netns_allocation(first, 3128);
        let same_prefix_alloc = proxy_netns_allocation(same_prefix, 3128);

        assert_eq!(&first.0.as_bytes()[..2], &same_prefix.0.as_bytes()[..2]);
        assert_ne!(first_alloc.subnet_cidr, same_prefix_alloc.subnet_cidr);
        assert_ne!(first_alloc.proxy_addr.ip(), same_prefix_alloc.proxy_addr.ip());
    }

    #[test]
    fn create_plan_allows_only_proxy_output_and_has_no_nat_or_forwarding() {
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let allocation = proxy_netns_allocation(sandbox_id, 3128);

        let commands = create_command_plan(&allocation);
        let rendered: Vec<String> = commands
            .iter()
            .map(|command| format!("{} {}", command.program, command.args.join(" ")))
            .collect();

        assert!(rendered.iter().any(|cmd| cmd.contains("ip netns add")));
        assert!(rendered.iter().any(|cmd| cmd.contains(&allocation.host_cidr)));
        assert!(
            rendered
                .iter()
                .any(|cmd| cmd.contains(&allocation.sandbox_cidr))
        );
        assert!(
            rendered
                .iter()
                .any(|cmd| cmd.contains("net.ipv6.conf.all.disable_ipv6=1"))
        );
        assert!(
            rendered
                .iter()
                .any(|cmd| cmd.contains("net.ipv6.conf.default.disable_ipv6=1"))
        );
        assert!(
            rendered
                .iter()
                .any(|cmd| cmd.contains("iptables -P OUTPUT DROP"))
        );
        assert!(rendered.iter().any(|cmd| {
            cmd.contains(&format!(
                "iptables -A OUTPUT -d {} -p tcp --dport 3128 -j ACCEPT",
                allocation.host_addr
            ))
        }));
        assert!(rendered.iter().any(|cmd| cmd.contains("AXIS-BYPASS: ")));
        assert!(
            rendered
                .iter()
                .any(|cmd| cmd.contains("iptables -A OUTPUT -j REJECT"))
        );
        let disable_ipv6_all = rendered
            .iter()
            .position(|cmd| cmd.contains("net.ipv6.conf.all.disable_ipv6=1"))
            .unwrap();
        let disable_ipv6_default = rendered
            .iter()
            .position(|cmd| cmd.contains("net.ipv6.conf.default.disable_ipv6=1"))
            .unwrap();
        let default_route = rendered
            .iter()
            .position(|cmd| cmd.contains("ip route add default"))
            .unwrap();
        let output_policy = rendered
            .iter()
            .position(|cmd| cmd.contains("iptables -P OUTPUT DROP"))
            .unwrap();
        assert!(disable_ipv6_all < default_route);
        assert!(disable_ipv6_default < default_route);
        assert!(disable_ipv6_all < output_policy);
        assert!(disable_ipv6_default < output_policy);
        assert!(!rendered.iter().any(|cmd| cmd.contains("MASQUERADE")));
        assert!(!rendered.iter().any(|cmd| cmd.contains("ip_forward")));
    }

    #[test]
    fn create_with_runner_cleans_up_namespace_and_veth_after_failure() {
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let allocation = proxy_netns_allocation(sandbox_id, 3128);
        let mut runner = FakeRunner {
            fail_at: Some(3),
            ..Default::default()
        };

        let err = create_with_runner(&allocation, &mut runner).unwrap_err();
        let rendered: Vec<String> = runner
            .commands
            .iter()
            .map(|command| format!("{} {}", command.program, command.args.join(" ")))
            .collect();

        assert!(err.contains("forced failure"));
        assert!(
            rendered
                .iter()
                .any(|cmd| { cmd == &format!("ip netns del {}", allocation.namespace) })
        );
        assert!(
            rendered
                .iter()
                .any(|cmd| { cmd == &format!("ip link del {}", allocation.veth_host) })
        );
    }

    #[test]
    fn host_address_collision_fails_closed_and_cleans_up() {
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let allocation = proxy_netns_allocation(sandbox_id, 3128);
        let host_addr_command_index = create_command_plan(&allocation)
            .iter()
            .position(|command| {
                command.program == "ip"
                    && command.args
                        == vec![
                            "addr".to_string(),
                            "add".to_string(),
                            allocation.host_cidr.clone(),
                            "dev".to_string(),
                            allocation.veth_host.clone(),
                        ]
            })
            .unwrap()
            + 1;
        let mut runner = FakeRunner {
            fail_at: Some(host_addr_command_index),
            ..Default::default()
        };

        let err = create_with_runner(&allocation, &mut runner).unwrap_err();
        let rendered: Vec<String> = runner
            .commands
            .iter()
            .map(|command| format!("{} {}", command.program, command.args.join(" ")))
            .collect();

        assert!(err.contains(&allocation.host_cidr));
        assert!(
            rendered
                .iter()
                .any(|cmd| { cmd == &format!("ip netns del {}", allocation.namespace) })
        );
        assert!(
            rendered
                .iter()
                .any(|cmd| { cmd == &format!("ip link del {}", allocation.veth_host) })
        );
    }

    #[test]
    fn destroy_with_runner_reports_cleanup_failures_after_best_effort_cleanup() {
        let mut runner = FakeRunner {
            fail_at: Some(1),
            ..Default::default()
        };

        let err = destroy_with_runner("axis-1234567890abcdef", &mut runner).unwrap_err();
        let rendered: Vec<String> = runner
            .commands
            .iter()
            .map(|command| format!("{} {}", command.program, command.args.join(" ")))
            .collect();

        assert!(err.contains("forced failure"));
        assert_eq!(rendered.len(), 2);
        assert_eq!(rendered[0], "ip netns del axis-1234567890abcdef");
        assert_eq!(rendered[1], "ip link del axh1234567890ab");
    }

    #[test]
    fn destroy_with_runner_ignores_host_veth_already_removed_by_namespace_delete() {
        let mut runner = FakeRunner {
            fail_at: Some(2),
            failure_message: Some("Cannot find device \"axh1234567890ab\"".into()),
            ..Default::default()
        };

        destroy_with_runner("axis-1234567890abcdef", &mut runner).unwrap();

        assert_eq!(runner.commands.len(), 2);
    }

    #[test]
    fn gated_real_ip_netns_create_and_destroy_cleans_namespace() {
        if std::env::var("AXIS_REAL_NETNS_TESTS").as_deref() != Ok("1") {
            eprintln!("AXIS_REAL_NETNS_TESTS=1 not set (test skipped)");
            return;
        }

        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-00000000bb05").unwrap();
        let allocation = proxy_netns_allocation(sandbox_id, 43_128);
        let namespace = allocation.namespace.clone();

        let create_result = create_netns(sandbox_id, 43_128);
        if create_result.is_err() {
            let _ = destroy_netns(&namespace);
        }
        create_result.unwrap();

        let verify_result = verify_real_netns_setup(&allocation);
        let cleanup_result = destroy_netns(&namespace);

        assert!(
            cleanup_result.is_ok(),
            "real netns cleanup failed: {cleanup_result:?}"
        );
        assert!(
            !real_netns_exists(&namespace),
            "namespace {namespace} remained after cleanup"
        );
        assert!(
            verify_result.is_ok(),
            "real netns verification failed: {verify_result:?}"
        );
    }

    #[test]
    fn destroy_derives_sandbox_name_from_axis_namespace() {
        let sandbox_name = sandbox_name_from_netns("axis-1234567890");

        assert_eq!(sandbox_name, "1234567890");
        assert_eq!(veth_host_name(sandbox_name), "axh1234567890");
    }

    fn verify_real_netns_setup(allocation: &ProxyNetnsAllocation) -> Result<(), String> {
        if !which("python3") {
            return Err("AXIS_REAL_NETNS_TESTS=1 requires python3 on PATH".into());
        }
        run_cmd(
            "ip",
            &[
                "netns",
                "exec",
                &allocation.namespace,
                "ip",
                "addr",
                "show",
                "dev",
                &allocation.veth_sandbox,
            ],
        )?;
        run_cmd(
            "ip",
            &[
                "netns",
                "exec",
                &allocation.namespace,
                "ip",
                "route",
                "show",
                "default",
            ],
        )?;
        run_cmd(
            "ip",
            &[
                "netns",
                "exec",
                &allocation.namespace,
                "iptables",
                "-S",
                "OUTPUT",
            ],
        )?;
        verify_real_proxy_port_reachable(allocation)?;
        verify_real_non_proxy_port_denied(allocation)?;
        verify_real_ipv6_denied(allocation)
    }

    fn real_netns_exists(namespace: &str) -> bool {
        Command::new("ip")
            .args(["netns", "list"])
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).contains(namespace))
            .unwrap_or(false)
    }

    fn verify_real_proxy_port_reachable(allocation: &ProxyNetnsAllocation) -> Result<(), String> {
        let listener = bind_real_host_listener(allocation, allocation.proxy_addr.port())?;

        let status = run_netns_python(
            &allocation.namespace,
            &format!(
                "import socket; s=socket.create_connection(('{}', {}), 2); s.close()",
                allocation.host_addr,
                allocation.proxy_addr.port()
            ),
        )?;

        if !status.success() {
            return Err(format!(
                "sandbox could not reach proxy port {}",
                allocation.proxy_addr.port()
            ));
        }
        if !listener_observed_connection(&listener)? {
            return Err("host listener did not observe proxy-port connection".into());
        }
        Ok(())
    }

    fn verify_real_non_proxy_port_denied(allocation: &ProxyNetnsAllocation) -> Result<(), String> {
        let denied_port = allocation
            .proxy_addr
            .port()
            .checked_add(1)
            .ok_or_else(|| "proxy port has no adjacent denied port".to_string())?;
        let listener = bind_real_host_listener(allocation, denied_port)?;

        let status = run_netns_python(
            &allocation.namespace,
            &format!(
                "import socket; s=socket.create_connection(('{}', {}), 1); s.close()",
                allocation.host_addr, denied_port
            ),
        )?;

        if status.success() {
            return Err(format!("sandbox reached denied host-veth port {denied_port}"));
        }
        if listener_observed_connection(&listener)? {
            return Err(format!(
                "host listener observed denied port {denied_port} connection"
            ));
        }
        Ok(())
    }

    fn verify_real_ipv6_denied(allocation: &ProxyNetnsAllocation) -> Result<(), String> {
        let status = run_netns_python(
            &allocation.namespace,
            "import socket; s=socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.settimeout(1); s.connect(('::1', 1)); s.close()",
        )?;
        if status.success() {
            Err("sandbox completed IPv6 connection attempt despite IPv6 disable".into())
        } else {
            Ok(())
        }
    }

    fn bind_real_host_listener(
        allocation: &ProxyNetnsAllocation,
        port: u16,
    ) -> Result<std::net::TcpListener, String> {
        let listener = std::net::TcpListener::bind(SocketAddr::new(
            allocation.host_addr.into(),
            port,
        ))
        .map_err(|e| format!("host listener bind {port}: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("host listener nonblocking: {e}"))?;
        Ok(listener)
    }

    fn run_netns_python(
        namespace: &str,
        code: &str,
    ) -> Result<std::process::ExitStatus, String> {
        Command::new("ip")
            .args(["netns", "exec", namespace, "python3", "-c", code])
            .status()
            .map_err(|e| format!("failed to run python3 in netns: {e}"))
    }

    fn listener_observed_connection(listener: &std::net::TcpListener) -> Result<bool, String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        loop {
            match listener.accept() {
                Ok((_stream, _addr)) => return Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return Ok(false);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => return Err(format!("host listener accept: {e}")),
            }
        }
    }
}
