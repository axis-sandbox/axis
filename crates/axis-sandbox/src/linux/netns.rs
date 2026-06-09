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

use axis_core::policy::{FilesystemPolicy, ProcessPolicy};
use axis_core::types::SandboxId;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::RawFd;
use std::process::Command;
use std::str::FromStr;

const PROXY_NET_A: u8 = 10;
const PROXY_PREFIX_LEN: u8 = 30;
const PROXY_SUBNET_COUNT: u32 = 1 << 22;
const AXIS_NETNS_HELPER_PATH: &str = "/usr/libexec/axis/axis-netns-helper";
const HELPER_STATE_DIR: &str = "/run/axis/netns";
const HELPER_SYNC_OK: &str = "OK\n";
const MAX_ACTIVE_HELPER_NETNS_PER_UID: usize = 32;
const HELPER_PGROUP_DRAIN_TIMEOUT_MS: u64 = 500;
const HELPER_PGROUP_DRAIN_INTERVAL_MS: u64 = 20;
const MXC_EXECUTOR_NAME: &str = "lxc-exec";
const MXC_HELPER_EXECUTOR_DIRS: &[&str] = &["/usr/local/bin", "/usr/bin", "/bin"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyNetnsAllocation {
    pub sandbox_id: SandboxId,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HelperLaunchSpec {
    #[serde(default)]
    pub launch_kind: HelperLaunchKind,
    #[serde(default)]
    pub mxc_config_fd: Option<RawFd>,
    pub workspace_dir: std::path::PathBuf,
    pub filesystem: FilesystemPolicy,
    pub process: ProcessPolicy,
    pub rlimits: HelperRlimits,
    pub command: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub destroy_token: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HelperLaunchKind {
    #[default]
    DirectProcess,
    MxcExecutor,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HelperRlimits {
    pub address_space_bytes: Option<u64>,
    pub max_processes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetnsCommand {
    program: String,
    args: Vec<String>,
    ignore_missing_link: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetnsCommandPaths {
    ip: String,
    iptables: String,
    sysctl: String,
}

impl NetnsCommandPaths {
    #[cfg(test)]
    fn path_names() -> Self {
        Self {
            ip: "ip".into(),
            iptables: "iptables".into(),
            sysctl: "sysctl".into(),
        }
    }

    fn fixed_system_paths() -> Result<Self, String> {
        Ok(Self {
            ip: fixed_system_command("ip")?,
            iptables: fixed_system_command("iptables")?,
            sysctl: fixed_system_command("sysctl")?,
        })
    }
}

trait CommandRunner {
    fn run(&mut self, command: &NetnsCommand) -> Result<(), String>;
}

struct ProcessCommandRunner;

impl CommandRunner for ProcessCommandRunner {
    fn run(&mut self, command: &NetnsCommand) -> Result<(), String> {
        run_cmd_cleared_env(&command.program, &command.args)
    }
}

struct PrivilegedCommandRunner {
    paths: NetnsCommandPaths,
}

impl PrivilegedCommandRunner {
    fn new() -> Result<Self, String> {
        ensure_helper_privileged()?;
        set_no_new_privs()?;
        Ok(Self {
            paths: NetnsCommandPaths::fixed_system_paths()?,
        })
    }
}

impl CommandRunner for PrivilegedCommandRunner {
    fn run(&mut self, command: &NetnsCommand) -> Result<(), String> {
        run_cmd_cleared_env(&command.program, &command.args)
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
            let paths = NetnsCommandPaths::fixed_system_paths()?;
            let mut runner = ProcessCommandRunner;
            match create_with_runner_and_paths(&allocation, &paths, &mut runner) {
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
        sandbox_id,
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

#[cfg(test)]
fn create_with_runner(
    allocation: &ProxyNetnsAllocation,
    runner: &mut dyn CommandRunner,
) -> Result<String, String> {
    create_with_runner_and_paths(allocation, &NetnsCommandPaths::path_names(), runner)
}

fn create_with_runner_and_paths(
    allocation: &ProxyNetnsAllocation,
    paths: &NetnsCommandPaths,
    runner: &mut dyn CommandRunner,
) -> Result<String, String> {
    for command in create_command_plan_with_paths(allocation, paths) {
        if let Err(e) = runner.run(&command) {
            if let Err(cleanup) =
                destroy_with_runner_and_paths(&allocation.namespace, paths, runner)
            {
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

#[cfg(test)]
fn create_command_plan(allocation: &ProxyNetnsAllocation) -> Vec<NetnsCommand> {
    create_command_plan_with_paths(allocation, &NetnsCommandPaths::path_names())
}

fn create_command_plan_with_paths(
    allocation: &ProxyNetnsAllocation,
    paths: &NetnsCommandPaths,
) -> Vec<NetnsCommand> {
    let ns = &allocation.namespace;
    let host = &allocation.veth_host;
    let sandbox = &allocation.veth_sandbox;
    let proxy_port = allocation.proxy_addr.port().to_string();
    let bypass_log_prefix = super::bypass_audit::bypass_log_prefix(allocation.sandbox_id);
    vec![
        ip_with_paths(paths, ["netns", "add", ns]),
        ip_with_paths(
            paths,
            ["link", "add", host, "type", "veth", "peer", "name", sandbox],
        ),
        ip_with_paths(paths, ["link", "set", sandbox, "netns", ns]),
        ip_with_paths(paths, ["addr", "add", &allocation.host_cidr, "dev", host]),
        ip_with_paths(paths, ["link", "set", host, "up"]),
        ip_with_paths(
            paths,
            [
                "netns",
                "exec",
                ns,
                &paths.ip,
                "addr",
                "add",
                &allocation.sandbox_cidr,
                "dev",
                sandbox,
            ],
        ),
        ip_with_paths(
            paths,
            ["netns", "exec", ns, &paths.ip, "link", "set", sandbox, "up"],
        ),
        ip_with_paths(
            paths,
            ["netns", "exec", ns, &paths.ip, "link", "set", "lo", "up"],
        ),
        ip_with_paths(
            paths,
            [
                "netns",
                "exec",
                ns,
                &paths.sysctl,
                "-w",
                "net.ipv6.conf.all.disable_ipv6=1",
            ],
        ),
        ip_with_paths(
            paths,
            [
                "netns",
                "exec",
                ns,
                &paths.sysctl,
                "-w",
                "net.ipv6.conf.default.disable_ipv6=1",
            ],
        ),
        ip_with_paths(
            paths,
            [
                "netns",
                "exec",
                ns,
                &paths.ip,
                "route",
                "add",
                "default",
                "via",
                &allocation.host_addr.to_string(),
            ],
        ),
        ip_with_paths(
            paths,
            ["netns", "exec", ns, &paths.iptables, "-P", "OUTPUT", "DROP"],
        ),
        ip_with_paths(
            paths,
            [
                "netns",
                "exec",
                ns,
                &paths.iptables,
                "-A",
                "OUTPUT",
                "-o",
                "lo",
                "-j",
                "ACCEPT",
            ],
        ),
        ip_with_paths(
            paths,
            [
                "netns",
                "exec",
                ns,
                &paths.iptables,
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
            ],
        ),
        ip_with_paths(
            paths,
            [
                "netns",
                "exec",
                ns,
                &paths.iptables,
                "-A",
                "OUTPUT",
                "-j",
                "LOG",
                "--log-prefix",
                &bypass_log_prefix,
                "--log-level",
                "4",
            ],
        ),
        ip_with_paths(
            paths,
            [
                "netns",
                "exec",
                ns,
                &paths.iptables,
                "-A",
                "OUTPUT",
                "-j",
                "REJECT",
            ],
        ),
    ]
}

/// Destroy a network namespace and clean up its veth pair.
pub fn destroy_netns(ns_name: &str) -> Result<(), String> {
    match detect_strategy() {
        NetnsStrategy::IpNetns => {
            let paths = NetnsCommandPaths::fixed_system_paths()?;
            let mut runner = ProcessCommandRunner;
            destroy_with_runner_and_paths(ns_name, &paths, &mut runner)
        }
        NetnsStrategy::Bubblewrap | NetnsStrategy::Unavailable => {
            Err("no network namespace cleanup strategy available".into())
        }
    }
}

#[cfg(test)]
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

#[cfg(test)]
fn destroy_command_plan(ns_name: &str, sandbox_name: &str) -> Vec<NetnsCommand> {
    destroy_command_plan_with_paths(ns_name, sandbox_name, &NetnsCommandPaths::path_names())
}

fn destroy_command_plan_with_paths(
    ns_name: &str,
    sandbox_name: &str,
    paths: &NetnsCommandPaths,
) -> Vec<NetnsCommand> {
    vec![
        ip_with_paths(paths, ["netns", "del", ns_name]),
        ip_ignore_missing_link_with_paths(paths, ["link", "del", &veth_host_name(sandbox_name)]),
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
#[cfg(test)]
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

fn run_cmd_cleared_env(program: &str, args: &[String]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .env_clear()
        .stdin(std::process::Stdio::null())
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
    if let Ok(paths) = NetnsCommandPaths::fixed_system_paths()
        && let Ok(output) = Command::new(&paths.ip)
            .args(["netns", "list"])
            .env_clear()
            .output()
        && output.status.success()
    {
        return NetnsStrategy::IpNetns;
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

pub fn helper_available() -> bool {
    let helper = helper_path();
    if !safe_root_executable(helper) {
        return false;
    }

    Command::new(helper)
        .arg("check")
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

pub(crate) fn helper_path() -> &'static std::path::Path {
    std::path::Path::new(AXIS_NETNS_HELPER_PATH)
}

pub(super) fn fixed_system_tool_available(binary: &str) -> bool {
    fixed_system_command(binary).is_ok()
}

pub(crate) fn new_destroy_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

pub(crate) fn create_launch_spec_fd(spec: &HelperLaunchSpec) -> Result<RawFd, String> {
    let bytes = serde_json::to_vec(spec).map_err(|e| format!("helper launch spec: {e}"))?;
    create_sealed_memfd("axis-netns-launch", "helper launch spec", &bytes)
}

pub(crate) fn create_mxc_config_fd(bytes: &[u8]) -> Result<RawFd, String> {
    create_sealed_memfd("axis-mxc-config", "MXC helper config", bytes)
}

fn create_sealed_memfd(name: &str, label: &str, bytes: &[u8]) -> Result<RawFd, String> {
    let name = std::ffi::CString::new(name).map_err(|e| format!("{label} memfd name: {e}"))?;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        ) as RawFd
    };
    if fd < 0 {
        return Err(format!(
            "{label} memfd_create failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    if let Err(errno) = super::write_all_fd(fd, bytes) {
        unsafe {
            libc::close(fd);
        }
        return Err(format!(
            "{label} write failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ));
    }

    let offset = unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    if offset < 0 {
        let error = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(format!("{label} rewind failed: {error}"));
    }

    if let Err(e) = seal_memfd(fd, label) {
        unsafe {
            libc::close(fd);
        }
        return Err(e);
    }

    Ok(fd)
}

fn seal_memfd(fd: RawFd, label: &str) -> Result<(), String> {
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    let ret = unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) };
    if ret < 0 {
        Err(format!(
            "{label} seal failed: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn read_helper_sync(read_fd: RawFd) -> Result<(), String> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 256];
    loop {
        let ret = unsafe {
            libc::read(
                read_fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
            )
        };
        if ret < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(read_fd);
            }
            return Err(format!("helper sync read failed: {error}"));
        }
        if ret == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..ret as usize]);
        if bytes.len() > 4096 {
            unsafe {
                libc::close(read_fd);
            }
            return Err("helper sync message exceeded 4096 bytes".into());
        }
    }
    unsafe {
        libc::close(read_fd);
    }

    let message = String::from_utf8_lossy(&bytes);
    if message == HELPER_SYNC_OK {
        Ok(())
    } else if let Some(error) = message.strip_prefix("ERR ") {
        Err(error.trim_end().to_string())
    } else if message.is_empty() {
        Err("helper exited before reporting setup status".into())
    } else {
        Err(format!("invalid helper setup status: {message:?}"))
    }
}

pub(crate) fn destroy_netns_with_helper_token(
    sandbox_id: SandboxId,
    destroy_token: &str,
) -> Result<(), String> {
    if !valid_destroy_token(destroy_token) {
        return Err("invalid helper destroy token".into());
    }
    let id = sandbox_id.to_string();
    let args = vec!["destroy-token".to_string(), id, destroy_token.to_string()];
    run_cmd_cleared_env(helper_path().to_string_lossy().as_ref(), &args)
}

pub(crate) fn helper_cleanup_already_done(error: &str) -> bool {
    error.contains("read helper state") && error.contains("No such file")
}

fn valid_destroy_token(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
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

fn ip_with_paths(
    paths: &NetnsCommandPaths,
    args: impl IntoIterator<Item = impl AsRef<str>>,
) -> NetnsCommand {
    NetnsCommand {
        program: paths.ip.clone(),
        args: args
            .into_iter()
            .map(|arg| arg.as_ref().to_string())
            .collect(),
        ignore_missing_link: false,
    }
}

fn ip_ignore_missing_link_with_paths(
    paths: &NetnsCommandPaths,
    args: impl IntoIterator<Item = impl AsRef<str>>,
) -> NetnsCommand {
    NetnsCommand {
        ignore_missing_link: true,
        ..ip_with_paths(paths, args)
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

pub fn helper_main_from_env() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run_helper_from_args(&args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("axis-netns-helper: {e}");
            1
        }
    }
}

fn run_helper_from_args(args: &[String]) -> Result<(), String> {
    let action = parse_helper_action(args)?;
    if matches!(action, HelperAction::Check) {
        ensure_helper_effective_root()?;
        NetnsCommandPaths::fixed_system_paths()?;
        return Ok(());
    }
    let mut runner = PrivilegedCommandRunner::new()?;
    let paths = runner.paths.clone();
    run_helper_action_with_runner(action, &paths, &mut runner)
}

#[cfg(test)]
fn run_helper_with_runner(
    args: &[String],
    paths: &NetnsCommandPaths,
    runner: &mut dyn CommandRunner,
) -> Result<(), String> {
    let action = parse_helper_action(args)?;
    run_helper_action_with_runner(action, paths, runner)
}

fn run_helper_action_with_runner(
    action: HelperAction,
    paths: &NetnsCommandPaths,
    runner: &mut dyn CommandRunner,
) -> Result<(), String> {
    match action {
        HelperAction::Check => Ok(()),
        HelperAction::Create {
            sandbox_id,
            proxy_port,
        } => {
            ensure_helper_real_root()?;
            let allocation = proxy_netns_allocation(sandbox_id, proxy_port);
            for command in create_command_plan_with_paths(&allocation, paths) {
                if let Err(e) = runner.run(&command) {
                    if let Err(cleanup) =
                        destroy_with_runner_and_paths(&allocation.namespace, paths, runner)
                    {
                        tracing::warn!(
                            "netns helper cleanup after create failure failed: {cleanup}"
                        );
                    }
                    return Err(e);
                }
            }
            Ok(())
        }
        HelperAction::Destroy { sandbox_id } => {
            ensure_helper_real_root()?;
            let namespace = format!("axis-{sandbox_id}");
            destroy_with_runner_and_paths(&namespace, paths, runner)
        }
        HelperAction::DestroyToken {
            sandbox_id,
            destroy_token,
        } => destroy_helper_owned_netns(sandbox_id, &destroy_token, paths, runner),
        HelperAction::Launch {
            sandbox_id,
            proxy_port,
            spec_fd,
            sync_fd,
            cgroup_procs_fd,
        } => launch_with_helper_action(
            sandbox_id,
            proxy_port,
            spec_fd,
            sync_fd,
            cgroup_procs_fd,
            paths,
            runner,
        ),
    }
}

fn destroy_with_runner_and_paths(
    ns_name: &str,
    paths: &NetnsCommandPaths,
    runner: &mut dyn CommandRunner,
) -> Result<(), String> {
    let sandbox_name = sandbox_name_from_netns(ns_name);
    let mut failures = Vec::new();
    for command in destroy_command_plan_with_paths(ns_name, sandbox_name, paths) {
        if let Err(e) = runner.run(&command) {
            if command.ignore_missing_link && is_missing_link_error(&e) {
                continue;
            }
            failures.push(e);
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HelperAction {
    Check,
    Create {
        sandbox_id: SandboxId,
        proxy_port: u16,
    },
    Destroy {
        sandbox_id: SandboxId,
    },
    DestroyToken {
        sandbox_id: SandboxId,
        destroy_token: String,
    },
    Launch {
        sandbox_id: SandboxId,
        proxy_port: u16,
        spec_fd: RawFd,
        sync_fd: RawFd,
        cgroup_procs_fd: Option<RawFd>,
    },
}

fn parse_helper_action(args: &[String]) -> Result<HelperAction, String> {
    let Some(action) = args.first().map(String::as_str) else {
        return Err(helper_usage());
    };

    match action {
        "check" if args.len() == 1 => Ok(HelperAction::Check),
        "create" if args.len() == 3 => {
            let sandbox_id = parse_canonical_sandbox_id(&args[1])?;
            let proxy_port = parse_proxy_port(&args[2])?;
            Ok(HelperAction::Create {
                sandbox_id,
                proxy_port,
            })
        }
        "destroy" if args.len() == 2 => {
            let sandbox_id = parse_canonical_sandbox_id(&args[1])?;
            Ok(HelperAction::Destroy { sandbox_id })
        }
        "destroy-token" if args.len() == 3 => {
            let sandbox_id = parse_canonical_sandbox_id(&args[1])?;
            let destroy_token = parse_destroy_token(&args[2])?;
            Ok(HelperAction::DestroyToken {
                sandbox_id,
                destroy_token,
            })
        }
        "launch" if args.len() == 6 => {
            let sandbox_id = parse_canonical_sandbox_id(&args[1])?;
            let proxy_port = parse_proxy_port(&args[2])?;
            let spec_fd = parse_fd_arg("spec fd", &args[3])?;
            let sync_fd = parse_fd_arg("sync fd", &args[4])?;
            let cgroup_procs_fd = parse_optional_fd_arg("cgroup procs fd", &args[5])?;
            Ok(HelperAction::Launch {
                sandbox_id,
                proxy_port,
                spec_fd,
                sync_fd,
                cgroup_procs_fd,
            })
        }
        "check" | "create" | "destroy" | "destroy-token" | "launch" => Err(helper_usage()),
        other => Err(format!("unknown action '{other}'; {}", helper_usage())),
    }
}

fn helper_usage() -> String {
    "usage: axis-netns-helper check | create <sandbox-uuid> <proxy-port> | destroy <sandbox-uuid> | destroy-token <sandbox-uuid> <token> | launch <sandbox-uuid> <proxy-port> <spec-fd> <sync-fd> <cgroup-procs-fd-or--1>"
        .into()
}

fn parse_canonical_sandbox_id(value: &str) -> Result<SandboxId, String> {
    let id = SandboxId::from_str(value).map_err(|e| format!("invalid sandbox id: {e}"))?;
    if id.to_string() != value {
        return Err("sandbox id must be a canonical lowercase UUID".into());
    }
    Ok(id)
}

fn parse_proxy_port(value: &str) -> Result<u16, String> {
    let port = value
        .parse::<u16>()
        .map_err(|e| format!("invalid proxy port '{value}': {e}"))?;
    if port == 0 {
        return Err("proxy port must be non-zero".into());
    }
    Ok(port)
}

fn parse_destroy_token(value: &str) -> Result<String, String> {
    if valid_destroy_token(value) {
        Ok(value.to_string())
    } else {
        Err("destroy token must be 64 hexadecimal characters".into())
    }
}

fn parse_fd_arg(label: &str, value: &str) -> Result<RawFd, String> {
    let fd = value
        .parse::<RawFd>()
        .map_err(|e| format!("invalid {label} '{value}': {e}"))?;
    if fd < 3 {
        return Err(format!("{label} must be an inherited fd >= 3"));
    }
    Ok(fd)
}

fn parse_optional_fd_arg(label: &str, value: &str) -> Result<Option<RawFd>, String> {
    if value == "-1" {
        Ok(None)
    } else {
        parse_fd_arg(label, value).map(Some)
    }
}

fn launch_with_helper_action(
    sandbox_id: SandboxId,
    proxy_port: u16,
    spec_fd: RawFd,
    sync_fd: RawFd,
    cgroup_procs_fd: Option<RawFd>,
    paths: &NetnsCommandPaths,
    runner: &mut dyn CommandRunner,
) -> Result<(), String> {
    let spec = read_launch_spec(spec_fd)?;
    let owner = helper_owner();
    validate_launch_spec(sandbox_id, proxy_port, owner, &spec)?;
    if let Some(fd) = cgroup_procs_fd {
        validate_cgroup_procs_fd(fd, sandbox_id)?;
    }
    ensure_helper_launch_authorized(owner)?;
    create_helper_state(sandbox_id, owner.uid, &spec.destroy_token)?;

    let allocation = proxy_netns_allocation(sandbox_id, proxy_port);
    if let Err(e) = create_helper_allocation_with_state(sandbox_id, &allocation, paths, runner) {
        write_helper_error(sync_fd, &e);
        return Err(e);
    }

    if unsafe { libc::setpgid(0, 0) } < 0 {
        let e = errno_message("set helper process group");
        cleanup_helper_allocation_after_failure(
            sandbox_id,
            &allocation,
            paths,
            runner,
            "process-group failure",
        );
        write_helper_error(sync_fd, &e);
        return Err(e);
    }
    let helper_pgid = unsafe { libc::getpgrp() };
    if let Err(e) = record_helper_process_group(sandbox_id, helper_pgid) {
        cleanup_helper_allocation_after_failure(
            sandbox_id,
            &allocation,
            paths,
            runner,
            "process-group state failure",
        );
        write_helper_error(sync_fd, &e);
        return Err(e);
    }

    let child = unsafe { libc::fork() };
    if child < 0 {
        let e = errno_message("fork helper target");
        cleanup_helper_allocation_after_failure(
            sandbox_id,
            &allocation,
            paths,
            runner,
            "fork failure",
        );
        write_helper_error(sync_fd, &e);
        return Err(e);
    }

    if child == 0 {
        let setup_result = match spec.launch_kind {
            HelperLaunchKind::DirectProcess => {
                apply_helper_launch_isolation(&allocation.namespace, owner, cgroup_procs_fd, &spec)
            }
            HelperLaunchKind::MxcExecutor => apply_mxc_helper_launch_isolation(
                &allocation.namespace,
                owner,
                cgroup_procs_fd,
                &spec,
            ),
        };
        if let Err(e) = setup_result {
            write_helper_error(sync_fd, &e);
            unsafe {
                libc::_exit(126);
            }
        }
        if let Err(e) = write_helper_ok(sync_fd) {
            eprintln!("axis-netns-helper: {e}");
            unsafe {
                libc::_exit(126);
            }
        }
        let e = exec_helper_target(&spec).unwrap_err();
        eprintln!("axis-netns-helper: {e}");
        unsafe {
            libc::_exit(127);
        }
    }

    unsafe {
        libc::close(sync_fd);
        if let Some(fd) = spec.mxc_config_fd {
            libc::close(fd);
        }
        if let Some(fd) = cgroup_procs_fd {
            libc::close(fd);
        }
    }
    let exit_code = wait_for_helper_child(child);
    if let Err(cleanup) = cleanup_helper_allocation_after_target_exit(
        sandbox_id,
        helper_pgid,
        &allocation,
        paths,
        runner,
    ) {
        tracing::warn!(
            "netns helper cleanup after target exit failed; preserving helper state for retry: {cleanup}"
        );
    }
    std::process::exit(exit_code);
}

fn create_helper_allocation_with_state(
    sandbox_id: SandboxId,
    allocation: &ProxyNetnsAllocation,
    paths: &NetnsCommandPaths,
    runner: &mut dyn CommandRunner,
) -> Result<(), String> {
    for command in create_command_plan_with_paths(allocation, paths) {
        if let Err(e) = runner.run(&command) {
            cleanup_helper_allocation_after_failure(
                sandbox_id,
                allocation,
                paths,
                runner,
                "create failure",
            );
            return Err(e);
        }
    }
    Ok(())
}

fn cleanup_helper_allocation_after_failure(
    sandbox_id: SandboxId,
    allocation: &ProxyNetnsAllocation,
    paths: &NetnsCommandPaths,
    runner: &mut dyn CommandRunner,
    reason: &str,
) {
    if let Err(cleanup) = destroy_with_runner_and_paths(&allocation.namespace, paths, runner) {
        tracing::warn!(
            "netns helper cleanup after {reason} failed; preserving helper state for retry: {cleanup}"
        );
    } else {
        remove_helper_state(sandbox_id);
    }
}

fn cleanup_helper_allocation_after_target_exit(
    sandbox_id: SandboxId,
    helper_pgid: libc::pid_t,
    allocation: &ProxyNetnsAllocation,
    paths: &NetnsCommandPaths,
    runner: &mut dyn CommandRunner,
) -> Result<(), String> {
    cleanup_helper_allocation_after_target_exit_with(
        HelperCleanupContext {
            sandbox_id,
            helper_pgid,
            allocation,
            paths,
            runner,
        },
        DefaultHelperCleanupHooks,
    )
}

struct HelperCleanupContext<'a> {
    sandbox_id: SandboxId,
    helper_pgid: libc::pid_t,
    allocation: &'a ProxyNetnsAllocation,
    paths: &'a NetnsCommandPaths,
    runner: &'a mut dyn CommandRunner,
}

trait HelperCleanupHooks {
    fn kill_process_group(&mut self, pgid: libc::pid_t) -> Result<(), String>;

    fn kill_network_namespace_members(&mut self, namespace: &str) -> Result<(), String>;

    fn destroy_namespace(
        &mut self,
        namespace: &str,
        paths: &NetnsCommandPaths,
        runner: &mut dyn CommandRunner,
    ) -> Result<(), String>;
}

struct DefaultHelperCleanupHooks;

impl HelperCleanupHooks for DefaultHelperCleanupHooks {
    fn kill_process_group(&mut self, pgid: libc::pid_t) -> Result<(), String> {
        kill_helper_process_group_members(pgid)
    }

    fn kill_network_namespace_members(&mut self, namespace: &str) -> Result<(), String> {
        kill_helper_network_namespace_members(namespace)
    }

    fn destroy_namespace(
        &mut self,
        namespace: &str,
        paths: &NetnsCommandPaths,
        runner: &mut dyn CommandRunner,
    ) -> Result<(), String> {
        destroy_with_runner_and_paths(namespace, paths, runner)
    }
}

fn cleanup_helper_allocation_after_target_exit_with<H>(
    ctx: HelperCleanupContext<'_>,
    mut hooks: H,
) -> Result<(), String>
where
    H: HelperCleanupHooks,
{
    hooks.kill_process_group(ctx.helper_pgid)?;
    hooks.kill_network_namespace_members(&ctx.allocation.namespace)?;
    hooks.destroy_namespace(&ctx.allocation.namespace, ctx.paths, ctx.runner)?;
    remove_helper_state(ctx.sandbox_id);
    Ok(())
}

fn destroy_helper_owned_netns(
    sandbox_id: SandboxId,
    destroy_token: &str,
    paths: &NetnsCommandPaths,
    runner: &mut dyn CommandRunner,
) -> Result<(), String> {
    let owner = helper_owner();
    let state = validate_helper_state(sandbox_id, owner.uid, destroy_token)?;
    let namespace = format!("axis-{sandbox_id}");
    if let Some(process_group) = state.process_group {
        kill_helper_process_group_members(process_group)?;
    }
    kill_helper_network_namespace_members(&namespace)?;
    let destroy_result = destroy_with_runner_and_paths(&namespace, paths, runner);
    if destroy_result.is_ok() {
        remove_helper_state(sandbox_id);
    }
    destroy_result
}

fn read_launch_spec(fd: RawFd) -> Result<HelperLaunchSpec, String> {
    validate_sealed_launch_spec_fd(fd)?;
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let ret = unsafe { libc::read(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len()) };
        if ret < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(format!("helper launch spec read failed: {error}"));
        }
        if ret == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..ret as usize]);
        if bytes.len() > 1024 * 1024 {
            unsafe {
                libc::close(fd);
            }
            return Err("helper launch spec exceeded 1 MiB".into());
        }
    }
    unsafe {
        libc::close(fd);
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("helper launch spec parse failed: {e}"))
}

fn validate_sealed_launch_spec_fd(fd: RawFd) -> Result<(), String> {
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    if seals < 0 {
        return Err(format!(
            "helper launch spec fd must support seals: {}",
            std::io::Error::last_os_error()
        ));
    }
    let required = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if seals & required != required {
        return Err("helper launch spec fd must be sealed against writes and size changes".into());
    }
    Ok(())
}

const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;

fn validate_cgroup_procs_fd(fd: RawFd, sandbox_id: SandboxId) -> Result<(), String> {
    let mut statfs = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    let ret = unsafe { libc::fstatfs(fd, statfs.as_mut_ptr()) };
    if ret < 0 {
        return Err(format!(
            "inspect cgroup procs fd {fd} filesystem: {}",
            std::io::Error::last_os_error()
        ));
    }
    let statfs = unsafe { statfs.assume_init() };
    if statfs.f_type != CGROUP2_SUPER_MAGIC {
        return Err(format!(
            "cgroup procs fd {fd} must reference a cgroup v2 filesystem"
        ));
    }

    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(format!(
            "inspect cgroup procs fd {fd} flags: {}",
            std::io::Error::last_os_error()
        ));
    }
    let access_mode = flags & libc::O_ACCMODE;
    if access_mode != libc::O_WRONLY && access_mode != libc::O_RDWR {
        return Err(format!("cgroup procs fd {fd} must be writable"));
    }

    let path = std::path::PathBuf::from(format!("/proc/self/fd/{fd}"));
    let target =
        std::fs::read_link(&path).map_err(|e| format!("inspect cgroup procs fd {fd}: {e}"))?;
    let expected = std::path::Path::new("/sys/fs/cgroup")
        .join(format!("axis-{sandbox_id}"))
        .join("cgroup.procs");
    if target != expected {
        return Err(format!(
            "cgroup procs fd {fd} must reference {}, got {}",
            expected.display(),
            target.display()
        ));
    }
    Ok(())
}

fn validate_launch_spec(
    sandbox_id: SandboxId,
    proxy_port: u16,
    owner: HelperOwner,
    spec: &HelperLaunchSpec,
) -> Result<(), String> {
    if spec.command.is_empty() {
        return Err("helper launch command must not be empty".into());
    }
    if !valid_destroy_token(&spec.destroy_token) {
        return Err("helper launch destroy token is invalid".into());
    }
    if spec.process.run_as_user.is_some() {
        return Err("helper launch with run_as_user is not implemented yet".into());
    }
    if super::landlock::policy_uses_tmpdir(&spec.filesystem) {
        return Err("helper launch with {tmpdir} filesystem policy is not implemented yet".into());
    }
    if proxy_netns_allocation(sandbox_id, proxy_port)
        .proxy_addr
        .port()
        != proxy_port
    {
        return Err("helper launch proxy allocation mismatch".into());
    }
    match spec.launch_kind {
        HelperLaunchKind::DirectProcess => {
            if spec.mxc_config_fd.is_some() {
                return Err("direct helper launch must not inherit an MXC config fd".into());
            }
            Ok(())
        }
        HelperLaunchKind::MxcExecutor => validate_mxc_helper_launch_spec(owner, spec),
    }
}

fn validate_mxc_helper_launch_spec(
    _owner: HelperOwner,
    spec: &HelperLaunchSpec,
) -> Result<(), String> {
    if spec.args.len() != 3 || spec.args[0] != "--experimental" || spec.args[1] != "--config" {
        return Err(
            "MXC helper launch must execute lxc-exec with '--experimental --config <file>'".into(),
        );
    }
    let config_fd = spec
        .mxc_config_fd
        .ok_or_else(|| "MXC helper launch requires a sealed config fd".to_string())?;
    if config_fd < 3 {
        return Err("MXC helper config fd must be an inherited fd >= 3".into());
    }
    let expected_config_path = format!("/proc/self/fd/{config_fd}");
    if spec.args[2] != expected_config_path {
        return Err(format!(
            "MXC helper launch config path must be {expected_config_path}"
        ));
    }
    validate_sealed_fd(config_fd, "MXC helper config fd")?;
    validate_mxc_executor_path(std::path::Path::new(&spec.command))?;
    for (key, _) in &spec.env {
        if axis_core::sandbox_env::is_secret_env_key(key)
            || axis_core::sandbox_env::is_proxy_env_key(key)
        {
            return Err(format!(
                "MXC helper launch environment contains forbidden key '{key}'"
            ));
        }
    }
    Ok(())
}

fn validate_sealed_fd(fd: RawFd, label: &str) -> Result<(), String> {
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    if seals < 0 {
        return Err(format!(
            "{label} must support seals: {}",
            std::io::Error::last_os_error()
        ));
    }
    let required = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if seals & required != required {
        return Err(format!(
            "{label} must be sealed against writes and size changes"
        ));
    }
    Ok(())
}

fn validate_helper_executable_path(path: &std::path::Path, label: &str) -> Result<(), String> {
    validate_helper_path_components(path, label)
}

fn validate_mxc_executor_path(path: &std::path::Path) -> Result<(), String> {
    validate_helper_executable_path(path, "MXC executor")?;
    if !mxc_executor_helper_path_allowed(path) {
        return Err(format!(
            "MXC executor path {} must be a trusted lxc-exec install path",
            path.display()
        ));
    }
    Ok(())
}

fn mxc_executor_helper_path_allowed(path: &std::path::Path) -> bool {
    path.file_name()
        .is_some_and(|name| name == std::ffi::OsStr::new(MXC_EXECUTOR_NAME))
        && path.parent().is_some_and(|parent| {
            MXC_HELPER_EXECUTOR_DIRS
                .iter()
                .any(|dir| parent == std::path::Path::new(dir))
        })
}

fn validate_helper_path_components(path: &std::path::Path, label: &str) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("{label} path must be absolute"));
    }

    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&current)
            .map_err(|e| format!("{label} path component {}: {e}", current.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "{label} path component {} must not be a symlink",
                current.display()
            ));
        }

        if current == path {
            validate_helper_leaf(path, &metadata, label)?;
        } else if !metadata.is_dir() {
            return Err(format!(
                "{label} path component {} must be a directory",
                current.display()
            ));
        } else {
            let mode = metadata.permissions().mode();
            if current != std::path::Path::new("/") && metadata.uid() != 0 {
                return Err(format!(
                    "{label} path component {} must be owned by root",
                    current.display()
                ));
            }
            if mode & 0o022 != 0 {
                return Err(format!(
                    "{label} path component {} must not be group- or world-writable",
                    current.display()
                ));
            }
        }
    }

    Ok(())
}

fn validate_helper_leaf(
    path: &std::path::Path,
    metadata: &std::fs::Metadata,
    label: &str,
) -> Result<(), String> {
    if !metadata.is_file() {
        return Err(format!(
            "{label} path {} must be a regular file",
            path.display()
        ));
    }

    let mode = metadata.permissions().mode();
    if metadata.uid() != 0 {
        return Err(format!(
            "{label} path {} must be owned by root",
            path.display()
        ));
    }
    if mode & 0o111 == 0 {
        return Err(format!(
            "{label} path {} must be executable",
            path.display()
        ));
    }
    if mode & 0o022 != 0 {
        return Err(format!(
            "{label} path {} must not be group- or world-writable",
            path.display()
        ));
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HelperOwner {
    uid: u32,
    gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HelperState {
    owner_uid: u32,
    destroy_token: String,
    process_group: Option<libc::pid_t>,
}

fn helper_owner() -> HelperOwner {
    HelperOwner {
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    }
}

fn ensure_helper_launch_authorized(owner: HelperOwner) -> Result<(), String> {
    validate_helper_launch_authorization(owner.uid, unsafe { libc::geteuid() })
}

fn validate_helper_launch_authorization(real_uid: u32, effective_uid: u32) -> Result<(), String> {
    if effective_uid != 0 {
        return Err(format!(
            "axis-netns-helper launch requires effective UID 0; current effective UID is {effective_uid}"
        ));
    }
    if real_uid == 0 {
        return Err(
            "axis-netns-helper launch requires a non-root real UID; root callers must use native netns setup".into(),
        );
    }
    Ok(())
}

fn apply_helper_launch_isolation(
    namespace: &str,
    owner: HelperOwner,
    cgroup_procs_fd: Option<RawFd>,
    spec: &HelperLaunchSpec,
) -> Result<(), String> {
    if let Some(fd) = cgroup_procs_fd {
        if let Err(errno) = super::enter_cgroup_from_child_fd(fd) {
            unsafe {
                libc::close(fd);
            }
            return Err(format!(
                "enter cgroup failed: {}",
                std::io::Error::from_raw_os_error(errno)
            ));
        }
        unsafe {
            libc::close(fd);
        }
    }

    let netns_fd = enter_netns(namespace)?;
    let setns_ret = unsafe { libc::setns(netns_fd, libc::CLONE_NEWNET) };
    unsafe {
        libc::close(netns_fd);
    }
    if setns_ret < 0 {
        return Err(errno_message("enter network namespace"));
    }

    let prepared_landlock =
        super::landlock::prepare_landlock(&spec.filesystem, &spec.workspace_dir)?;
    let seccomp_options = super::seccomp::SeccompOptions::default();
    let prepared_seccomp =
        super::seccomp::prepare_seccomp_with_options(&spec.process, seccomp_options)?;

    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        return Err(errno_message("set no_new_privs"));
    }
    if let Err(errno) = prepared_landlock.restrict_current_process() {
        return Err(format!(
            "apply Landlock failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ));
    }

    drop_to_owner(owner)?;

    if let Err(errno) = apply_helper_rlimits(spec.rlimits) {
        return Err(format!(
            "apply resource limits failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ));
    }
    if let Err(errno) = super::drop_process_capabilities() {
        return Err(format!(
            "drop capabilities failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ));
    }
    if let Err(errno) = super::mark_unexpected_child_fds_close_on_exec() {
        return Err(format!(
            "mark inherited fds close-on-exec failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ));
    }
    if let Err(errno) = prepared_seccomp.apply_current_process() {
        return Err(format!(
            "apply seccomp failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ));
    }
    Ok(())
}

fn apply_mxc_helper_launch_isolation(
    namespace: &str,
    owner: HelperOwner,
    cgroup_procs_fd: Option<RawFd>,
    spec: &HelperLaunchSpec,
) -> Result<(), String> {
    if let Some(fd) = cgroup_procs_fd {
        if let Err(errno) = super::enter_cgroup_from_child_fd(fd) {
            unsafe {
                libc::close(fd);
            }
            return Err(format!(
                "enter cgroup failed: {}",
                std::io::Error::from_raw_os_error(errno)
            ));
        }
        unsafe {
            libc::close(fd);
        }
    }

    let netns_fd = enter_netns(namespace)?;
    let setns_ret = unsafe { libc::setns(netns_fd, libc::CLONE_NEWNET) };
    unsafe {
        libc::close(netns_fd);
    }
    if setns_ret < 0 {
        return Err(errno_message("enter network namespace"));
    }

    drop_to_owner(owner)?;

    set_no_new_privs()?;
    if let Err(errno) = apply_helper_rlimits(spec.rlimits) {
        return Err(format!(
            "apply resource limits failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ));
    }
    if let Err(errno) = super::drop_process_capabilities() {
        return Err(format!(
            "drop capabilities failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ));
    }
    if let Err(errno) = super::mark_unexpected_child_fds_close_on_exec() {
        return Err(format!(
            "mark inherited fds close-on-exec failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ));
    }
    if let Some(fd) = spec.mxc_config_fd
        && let Err(errno) = super::clear_fd_cloexec(fd)
    {
        return Err(format!(
            "preserve MXC config fd for exec failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ));
    }

    Ok(())
}

fn apply_helper_rlimits(limits: HelperRlimits) -> Result<(), i32> {
    if let Some(value) = limits.address_space_bytes {
        set_helper_resource_limit(libc::RLIMIT_AS, value)?;
    }
    if let Some(value) = limits.max_processes {
        set_helper_resource_limit(libc::RLIMIT_NPROC, value)?;
    }
    Ok(())
}

fn set_helper_resource_limit(resource: libc::__rlimit_resource_t, value: u64) -> Result<(), i32> {
    if u128::from(value) > libc::rlim_t::MAX as u128 {
        return Err(libc::EINVAL);
    }
    let limit = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    let ret = unsafe { libc::setrlimit(resource, &limit as *const libc::rlimit) };
    if ret < 0 {
        Err(super::current_errno())
    } else {
        Ok(())
    }
}

fn drop_to_owner(owner: HelperOwner) -> Result<(), String> {
    if unsafe { libc::setgroups(0, std::ptr::null()) } < 0 {
        return Err(errno_message("clear supplementary groups"));
    }
    if unsafe { libc::setgid(owner.gid) } < 0 {
        return Err(errno_message("drop group id"));
    }
    if unsafe { libc::setuid(owner.uid) } < 0 {
        return Err(errno_message("drop user id"));
    }
    Ok(())
}

fn exec_helper_target(spec: &HelperLaunchSpec) -> Result<(), String> {
    use std::os::unix::process::CommandExt;

    let err = Command::new(&spec.command)
        .args(&spec.args)
        .env_clear()
        .envs(spec.env.iter().map(|(key, value)| (key, value)))
        .exec();
    Err(format!("exec target '{}': {err}", spec.command))
}

fn wait_for_helper_child(pid: libc::pid_t) -> i32 {
    let mut status = 0;
    loop {
        let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
        if ret == pid {
            break;
        }
        if ret < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return 127;
        }
    }
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        127
    }
}

fn kill_helper_process_group_members(pgid: libc::pid_t) -> Result<(), String> {
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_millis(HELPER_PGROUP_DRAIN_TIMEOUT_MS);
    loop {
        let members = helper_process_group_members(pgid)?;
        if members.is_empty() {
            return Ok(());
        }
        for pid in &members {
            let ret = unsafe { libc::kill(*pid, libc::SIGKILL) };
            if ret < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
                return Err(format!(
                    "kill helper process group member {pid}: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "helper process group {pgid} still has member processes: {members:?}"
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(
            HELPER_PGROUP_DRAIN_INTERVAL_MS,
        ));
    }
}

fn helper_process_group_members(pgid: libc::pid_t) -> Result<Vec<libc::pid_t>, String> {
    let self_pid = unsafe { libc::getpid() };
    let entries = std::fs::read_dir("/proc").map_err(|e| format!("read /proc: {e}"))?;
    let mut members = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<libc::pid_t>().ok())
        else {
            continue;
        };
        if pid == self_pid {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        if parse_process_stat_pgrp(&stat) == Some(pgid) {
            members.push(pid);
        }
    }
    Ok(members)
}

fn kill_helper_network_namespace_members(namespace: &str) -> Result<(), String> {
    let metadata = std::fs::metadata(netns_path(namespace))
        .map_err(|e| format!("stat network namespace '{namespace}': {e}"))?;
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_millis(HELPER_PGROUP_DRAIN_TIMEOUT_MS);
    loop {
        let members = network_namespace_members(metadata.dev(), metadata.ino(), true)?;
        if members.is_empty() {
            return Ok(());
        }
        for pid in &members {
            let ret = unsafe { libc::kill(*pid, libc::SIGKILL) };
            if ret < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
                return Err(format!(
                    "kill network namespace member {pid}: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "network namespace '{namespace}' still has member processes: {members:?}"
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(
            HELPER_PGROUP_DRAIN_INTERVAL_MS,
        ));
    }
}

fn network_namespace_members(
    namespace_dev: u64,
    namespace_ino: u64,
    skip_self: bool,
) -> Result<Vec<libc::pid_t>, String> {
    let self_pid = unsafe { libc::getpid() };
    let entries = std::fs::read_dir("/proc").map_err(|e| format!("read /proc: {e}"))?;
    let mut members = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<libc::pid_t>().ok())
        else {
            continue;
        };
        if skip_self && pid == self_pid {
            continue;
        }
        let Ok(metadata) = std::fs::metadata(entry.path().join("ns/net")) else {
            continue;
        };
        if metadata.dev() == namespace_dev && metadata.ino() == namespace_ino {
            members.push(pid);
        }
    }
    Ok(members)
}

fn netns_path(namespace: &str) -> std::path::PathBuf {
    std::path::Path::new("/var/run/netns").join(namespace)
}

fn parse_process_stat_pgrp(stat: &str) -> Option<libc::pid_t> {
    let end = stat.rfind(") ")?;
    let mut fields = stat[end + 2..].split_whitespace();
    let _state = fields.next()?;
    let _ppid = fields.next()?;
    fields.next()?.parse().ok()
}

fn write_helper_ok(sync_fd: RawFd) -> Result<(), String> {
    let result = super::write_all_fd(sync_fd, HELPER_SYNC_OK.as_bytes()).map_err(|errno| {
        format!(
            "helper sync success write failed: {}",
            std::io::Error::from_raw_os_error(errno)
        )
    });
    unsafe {
        libc::close(sync_fd);
    }
    result
}

fn write_helper_error(sync_fd: RawFd, message: &str) {
    let mut rendered = String::from("ERR ");
    rendered.push_str(message);
    rendered.push('\n');
    let _ = super::write_all_fd(sync_fd, rendered.as_bytes());
    unsafe {
        libc::close(sync_fd);
    }
}

fn errno_message(label: &str) -> String {
    format!("{label} failed: {}", std::io::Error::last_os_error())
}

fn helper_state_path(sandbox_id: SandboxId) -> std::path::PathBuf {
    std::path::Path::new(HELPER_STATE_DIR).join(sandbox_id.to_string())
}

fn create_helper_state(
    sandbox_id: SandboxId,
    owner_uid: u32,
    destroy_token: &str,
) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    if !valid_destroy_token(destroy_token) {
        return Err("invalid helper destroy token".into());
    }
    ensure_helper_state_dir()?;
    let _lock = lock_helper_state_dir()?;
    enforce_active_namespace_quota_locked(owner_uid)?;
    let path = helper_state_path(sandbox_id);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("create helper state {}: {e}", path.display()))?;
    writeln!(file, "{owner_uid}")
        .and_then(|_| writeln!(file, "{destroy_token}"))
        .map_err(|e| format!("write helper state {}: {e}", path.display()))
}

fn record_helper_process_group(
    sandbox_id: SandboxId,
    process_group: libc::pid_t,
) -> Result<(), String> {
    let path = helper_state_path(sandbox_id);
    let mut state = read_helper_state_file(&path)?;
    state.process_group = Some(process_group);
    write_helper_state_file(&path, &state)
}

fn validate_helper_state(
    sandbox_id: SandboxId,
    owner_uid: u32,
    destroy_token: &str,
) -> Result<HelperState, String> {
    ensure_helper_state_dir()?;
    let path = helper_state_path(sandbox_id);
    let state = read_helper_state_file(&path)?;
    if state.owner_uid != owner_uid {
        return Err("helper destroy owner does not match namespace owner".into());
    }
    if state.destroy_token != destroy_token {
        return Err("helper destroy token does not match namespace owner".into());
    }
    Ok(state)
}

fn read_helper_state_file(path: &std::path::Path) -> Result<HelperState, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("read helper state {}: {e}", path.display()))?;
    let mut lines = contents.lines();
    let recorded_uid = lines
        .next()
        .ok_or_else(|| format!("helper state {} is missing owner uid", path.display()))?
        .parse::<u32>()
        .map_err(|e| format!("helper state {} owner uid: {e}", path.display()))?;
    let recorded_token = lines
        .next()
        .ok_or_else(|| format!("helper state {} is missing destroy token", path.display()))?
        .to_string();
    let process_group = lines
        .next()
        .map(|line| {
            line.parse::<libc::pid_t>()
                .map_err(|e| format!("helper state {} process group: {e}", path.display()))
        })
        .transpose()?;
    Ok(HelperState {
        owner_uid: recorded_uid,
        destroy_token: recorded_token,
        process_group,
    })
}

fn write_helper_state_file(path: &std::path::Path, state: &HelperState) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("open helper state {}: {e}", path.display()))?;
    writeln!(file, "{}", state.owner_uid)
        .and_then(|_| writeln!(file, "{}", state.destroy_token))
        .and_then(|_| {
            if let Some(process_group) = state.process_group {
                writeln!(file, "{process_group}")
            } else {
                Ok(())
            }
        })
        .map_err(|e| format!("write helper state {}: {e}", path.display()))
}

fn remove_helper_state(sandbox_id: SandboxId) {
    let _ = std::fs::remove_file(helper_state_path(sandbox_id));
}

fn ensure_helper_state_dir() -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;

    let state_dir = std::path::Path::new(HELPER_STATE_DIR);
    let mut current = std::path::PathBuf::new();
    for component in state_dir.components() {
        current.push(component.as_os_str());
        if std::fs::symlink_metadata(&current).is_err() {
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            builder
                .create(&current)
                .map_err(|e| format!("create helper state dir {}: {e}", current.display()))?;
        }
        let metadata = std::fs::symlink_metadata(&current)
            .map_err(|e| format!("helper state dir {}: {e}", current.display()))?;
        if !safe_root_metadata(&metadata, SafePathKind::AncestorDirectory) {
            return Err(format!(
                "helper state dir component {} must be a root-owned non-writable real directory",
                current.display()
            ));
        }
    }
    Ok(())
}

fn lock_helper_state_dir() -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    let lock_path = std::path::Path::new(HELPER_STATE_DIR).join(".lock");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)
        .map_err(|e| format!("open helper state lock {}: {e}", lock_path.display()))?;
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if ret < 0 {
        Err(format!(
            "lock helper state dir {}: {}",
            lock_path.display(),
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(file)
    }
}

fn enforce_active_namespace_quota_locked(owner_uid: u32) -> Result<(), String> {
    let active = std::fs::read_dir(HELPER_STATE_DIR)
        .map_err(|e| format!("read helper state dir {HELPER_STATE_DIR}: {e}"))?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name() != ".lock")
        .filter(|entry| {
            let Ok(contents) = std::fs::read_to_string(entry.path()) else {
                return false;
            };
            contents
                .lines()
                .next()
                .and_then(|line| line.parse::<u32>().ok())
                == Some(owner_uid)
        })
        .count();

    if active >= MAX_ACTIVE_HELPER_NETNS_PER_UID {
        Err(format!(
            "helper netns quota exceeded for UID {owner_uid}: {active} active, limit {MAX_ACTIVE_HELPER_NETNS_PER_UID}"
        ))
    } else {
        Ok(())
    }
}

fn ensure_helper_effective_root() -> Result<(), String> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        Err(format!(
            "axis-netns-helper requires effective UID 0; current effective UID is {euid}"
        ))
    } else {
        Ok(())
    }
}

fn ensure_helper_real_root() -> Result<(), String> {
    let ruid = unsafe { libc::getuid() };
    if ruid != 0 {
        Err(format!(
            "axis-netns-helper create/destroy require real UID 0; current real UID is {ruid}"
        ))
    } else {
        Ok(())
    }
}

fn ensure_helper_privileged() -> Result<(), String> {
    ensure_helper_effective_root()
}

fn set_no_new_privs() -> Result<(), String> {
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret < 0 {
        Err(format!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

const FIXED_COMMAND_DIRS: &[&str] = &["/usr/sbin", "/sbin", "/usr/bin", "/bin"];

fn fixed_system_command(binary: &str) -> Result<String, String> {
    if binary.contains('/') {
        return Err(format!(
            "system command name must not contain '/': {binary}"
        ));
    }

    for dir in FIXED_COMMAND_DIRS {
        let candidate = std::path::Path::new(dir).join(binary);
        if safe_root_executable(&candidate) {
            return Ok(candidate.to_string_lossy().into_owned());
        }
    }

    Err(format!(
        "cannot find safe root-owned executable for {binary} in fixed system paths"
    ))
}

fn safe_root_executable(path: &std::path::Path) -> bool {
    if !path.is_absolute() {
        return false;
    }

    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let Ok(metadata) = std::fs::symlink_metadata(&current) else {
            return false;
        };
        let kind = if current == path {
            SafePathKind::ExecutableFile
        } else {
            SafePathKind::AncestorDirectory
        };
        if !safe_root_metadata(&metadata, kind) {
            return false;
        }
        if current == path {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SafePathKind {
    AncestorDirectory,
    ExecutableFile,
}

fn safe_root_metadata(metadata: &std::fs::Metadata, kind: SafePathKind) -> bool {
    if metadata.file_type().is_symlink()
        || !safe_root_owner_and_mode(metadata.uid(), metadata.mode())
    {
        return false;
    }

    match kind {
        SafePathKind::AncestorDirectory => metadata.is_dir(),
        SafePathKind::ExecutableFile => metadata.is_file() && metadata.mode() & 0o111 != 0,
    }
}

fn safe_root_owner_and_mode(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & 0o022 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::os::unix::io::AsRawFd;
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
        assert_eq!(
            first_alloc.proxy_addr,
            SocketAddr::new(first_alloc.host_addr.into(), 3128)
        );
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
        assert_ne!(
            first_alloc.proxy_addr.ip(),
            same_prefix_alloc.proxy_addr.ip()
        );
    }

    #[test]
    fn helper_action_parser_accepts_only_typed_canonical_arguments() {
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let token = valid_test_token();

        assert_eq!(
            parse_helper_action(&strings(["check"])).unwrap(),
            HelperAction::Check
        );
        assert_eq!(
            parse_helper_action(&strings([
                "create",
                "00000000-0000-4000-8000-000000000001",
                "3128",
            ]))
            .unwrap(),
            HelperAction::Create {
                sandbox_id,
                proxy_port: 3128,
            }
        );
        assert_eq!(
            parse_helper_action(&strings([
                "destroy",
                "00000000-0000-4000-8000-000000000001"
            ]))
            .unwrap(),
            HelperAction::Destroy { sandbox_id }
        );
        assert_eq!(
            parse_helper_action(&strings([
                "destroy-token",
                "00000000-0000-4000-8000-000000000001",
                &token,
            ]))
            .unwrap(),
            HelperAction::DestroyToken {
                sandbox_id,
                destroy_token: token.clone(),
            }
        );
        assert_eq!(
            parse_helper_action(&strings([
                "launch",
                "00000000-0000-4000-8000-000000000001",
                "3128",
                "3",
                "4",
                "-1",
            ]))
            .unwrap(),
            HelperAction::Launch {
                sandbox_id,
                proxy_port: 3128,
                spec_fd: 3,
                sync_fd: 4,
                cgroup_procs_fd: None,
            }
        );
        assert_eq!(
            parse_helper_action(&strings([
                "launch",
                "00000000-0000-4000-8000-000000000001",
                "3128",
                "3",
                "4",
                "5",
            ]))
            .unwrap(),
            HelperAction::Launch {
                sandbox_id,
                proxy_port: 3128,
                spec_fd: 3,
                sync_fd: 4,
                cgroup_procs_fd: Some(5),
            }
        );
    }

    #[test]
    fn helper_action_parser_rejects_malicious_or_ambiguous_arguments() {
        for args in [
            strings([]),
            strings(["check", "extra"]),
            strings(["unknown"]),
            strings(["create", "00000000000040008000000000000001", "3128"]),
            strings(["create", "00000000-0000-4000-8000-000000000001", "0"]),
            strings(["create", "00000000-0000-4000-8000-000000000001", "65536"]),
            strings([
                "create",
                "00000000-0000-4000-8000-000000000001",
                "3128",
                "extra",
            ]),
            strings([
                "create",
                "00000000-0000-4000-8000-000000000001/../../x",
                "3128",
            ]),
            strings(["destroy", "axis-00000000-0000-4000-8000-000000000001"]),
            strings(["destroy", "00000000-0000-4000-8000-000000000001", "extra"]),
            strings([
                "destroy-token",
                "00000000-0000-4000-8000-000000000001",
                "not-token",
            ]),
            strings([
                "launch",
                "00000000-0000-4000-8000-000000000001",
                "3128",
                "2",
                "4",
                "-1",
            ]),
            strings([
                "launch",
                "00000000-0000-4000-8000-000000000001",
                "3128",
                "3",
                "1",
                "-1",
            ]),
            strings([
                "launch",
                "00000000-0000-4000-8000-000000000001",
                "0",
                "3",
                "4",
                "-1",
            ]),
            strings([
                "launch",
                "00000000-0000-4000-8000-000000000001",
                "3128",
                "3",
                "4",
                "2",
            ]),
            strings([
                "launch",
                "00000000-0000-4000-8000-000000000001",
                "3128",
                "3",
                "4",
            ]),
        ] {
            assert!(
                parse_helper_action(&args).is_err(),
                "helper args should be rejected: {args:?}"
            );
        }
    }

    #[test]
    fn helper_launch_spec_validation_rejects_unsafe_or_unsupported_specs() {
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let owner = helper_owner();
        let mut spec = helper_launch_spec();

        validate_launch_spec(sandbox_id, 3128, owner, &spec).unwrap();

        spec.command.clear();
        assert!(
            validate_launch_spec(sandbox_id, 3128, owner, &spec)
                .unwrap_err()
                .contains("command")
        );

        spec = helper_launch_spec();
        spec.destroy_token = "bad".into();
        assert!(
            validate_launch_spec(sandbox_id, 3128, owner, &spec)
                .unwrap_err()
                .contains("destroy token")
        );

        spec = helper_launch_spec();
        spec.process.run_as_user = Some("sandbox-user".into());
        assert!(
            validate_launch_spec(sandbox_id, 3128, owner, &spec)
                .unwrap_err()
                .contains("run_as_user")
        );

        spec = helper_launch_spec();
        spec.filesystem.read_write = vec!["{tmpdir}".into()];
        assert!(
            validate_launch_spec(sandbox_id, 3128, owner, &spec)
                .unwrap_err()
                .contains("{tmpdir}")
        );

        spec = helper_launch_spec();
        spec.mxc_config_fd = Some(42);
        assert!(
            validate_launch_spec(sandbox_id, 3128, owner, &spec)
                .unwrap_err()
                .contains("direct helper launch")
        );
    }

    #[test]
    fn mxc_helper_launch_spec_validation_requires_safe_executor_and_private_config() {
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let owner = helper_owner();
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let executor = root.path().join("lxc-exec");
        std::fs::write(&executor, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&executor, std::fs::Permissions::from_mode(0o700)).unwrap();
        let config_fd = create_mxc_config_fd(b"{}").unwrap();
        let mut spec = helper_launch_spec();
        spec.launch_kind = HelperLaunchKind::MxcExecutor;
        spec.mxc_config_fd = Some(config_fd);
        spec.command = executor.to_string_lossy().into_owned();
        spec.args = vec![
            "--experimental".into(),
            "--config".into(),
            format!("/proc/self/fd/{config_fd}"),
        ];
        spec.env = vec![("PATH".into(), "/usr/bin:/bin".into())];

        let owner_executable_error = validate_launch_spec(sandbox_id, 3128, owner, &spec)
            .expect_err("owner-controlled MXC executor must be rejected");
        assert!(
            owner_executable_error.contains("owned by root")
                || owner_executable_error.contains("group- or world-writable"),
            "unexpected owner executable error: {owner_executable_error}"
        );

        let root_non_mxc_executor = std::path::Path::new("/usr/bin/true");
        if safe_root_executable(root_non_mxc_executor) {
            spec.command = root_non_mxc_executor.to_string_lossy().into_owned();
            assert!(
                validate_launch_spec(sandbox_id, 3128, owner, &spec)
                    .unwrap_err()
                    .contains("trusted lxc-exec")
            );
        }

        let root_executor = MXC_HELPER_EXECUTOR_DIRS
            .iter()
            .map(|dir| std::path::Path::new(dir).join(MXC_EXECUTOR_NAME))
            .find(|path| safe_root_executable(path));
        let Some(root_executor) = root_executor else {
            eprintln!("root-owned lxc-exec unavailable (test remainder skipped)");
            unsafe {
                libc::close(config_fd);
            }
            return;
        };
        spec.command = root_executor.to_string_lossy().into_owned();
        validate_launch_spec(sandbox_id, 3128, owner, &spec).unwrap();

        let mut bad_args = spec.clone();
        bad_args.args = vec![format!("/proc/self/fd/{config_fd}")];
        assert!(
            validate_launch_spec(sandbox_id, 3128, owner, &bad_args)
                .unwrap_err()
                .contains("--experimental --config")
        );

        let mut bad_config_path = spec.clone();
        bad_config_path.args[2] = format!("/proc/self/fd/{}", config_fd + 1);
        assert!(
            validate_launch_spec(sandbox_id, 3128, owner, &bad_config_path)
                .unwrap_err()
                .contains("config path")
        );

        let mut missing_config_fd = spec.clone();
        missing_config_fd.mxc_config_fd = None;
        assert!(
            validate_launch_spec(sandbox_id, 3128, owner, &missing_config_fd)
                .unwrap_err()
                .contains("sealed config fd")
        );

        let (unsealed_read_fd, unsealed_write_fd) = test_pipe();
        let mut unsealed_config = spec.clone();
        unsealed_config.mxc_config_fd = Some(unsealed_read_fd);
        unsealed_config.args[2] = format!("/proc/self/fd/{unsealed_read_fd}");
        assert!(
            validate_launch_spec(sandbox_id, 3128, owner, &unsealed_config)
                .unwrap_err()
                .contains("must support seals")
        );
        unsafe {
            libc::close(unsealed_read_fd);
            libc::close(unsealed_write_fd);
        }

        let mut bad_env = spec.clone();
        bad_env.env = vec![("HTTPS_PROXY".into(), "http://proxy-with-creds".into())];
        assert!(
            validate_launch_spec(sandbox_id, 3128, owner, &bad_env)
                .unwrap_err()
                .contains("forbidden key")
        );

        unsafe {
            libc::close(config_fd);
        }
    }

    #[test]
    fn mxc_helper_executor_path_allowlist_requires_lxc_exec_in_stable_dirs() {
        assert!(mxc_executor_helper_path_allowed(std::path::Path::new(
            "/usr/local/bin/lxc-exec"
        )));
        assert!(mxc_executor_helper_path_allowed(std::path::Path::new(
            "/usr/bin/lxc-exec"
        )));
        assert!(mxc_executor_helper_path_allowed(std::path::Path::new(
            "/bin/lxc-exec"
        )));
        assert!(!mxc_executor_helper_path_allowed(std::path::Path::new(
            "/usr/bin/true"
        )));
        assert!(!mxc_executor_helper_path_allowed(std::path::Path::new(
            "/opt/axis/bin/lxc-exec"
        )));
        assert!(!mxc_executor_helper_path_allowed(std::path::Path::new(
            "lxc-exec"
        )));
    }

    #[test]
    fn helper_launch_spec_fd_requires_memfd_seals() {
        let (read_fd, write_fd) = test_pipe();

        assert!(
            validate_sealed_launch_spec_fd(read_fd)
                .unwrap_err()
                .contains("seals")
        );

        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
    }

    #[test]
    fn cgroup_fd_validation_rejects_non_cgroup_paths() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();

        assert!(
            validate_cgroup_procs_fd(file.as_file().as_raw_fd(), sandbox_id)
                .unwrap_err()
                .contains("cgroup v2")
        );
    }

    #[test]
    fn gated_cgroup_fd_validation_accepts_axis_cgroup_procs_fd() {
        if std::env::var("AXIS_REAL_CGROUP_TESTS").as_deref() != Ok("1") {
            eprintln!("AXIS_REAL_CGROUP_TESTS=1 not set (test skipped)");
            return;
        }

        let sandbox_id = SandboxId::new();
        let policy = ProcessPolicy {
            cpu_rate_percent: 0,
            ..ProcessPolicy::default()
        };
        let handle = super::super::resources::create_cgroup(sandbox_id, &policy)
            .expect("AXIS_REAL_CGROUP_TESTS=1 requires writable cgroup v2");
        let fd = handle.open_procs_fd().unwrap();

        let validation = validate_cgroup_procs_fd(fd, sandbox_id);
        unsafe {
            libc::close(fd);
        }
        let cleanup = handle.cleanup();

        assert!(
            validation.is_ok(),
            "cgroup fd validation failed: {validation:?}"
        );
        assert!(cleanup.is_ok(), "cgroup cleanup failed: {cleanup:?}");
    }

    #[test]
    fn helper_launch_authorization_allows_only_setuid_root_for_non_root_callers() {
        validate_helper_launch_authorization(1000, 0).unwrap();

        assert!(
            validate_helper_launch_authorization(1000, 1000)
                .unwrap_err()
                .contains("effective UID 0")
        );
        assert!(
            validate_helper_launch_authorization(0, 0)
                .unwrap_err()
                .contains("non-root real UID")
        );
    }

    #[test]
    fn helper_no_new_privs_setup_sets_sticky_exec_boundary_in_child() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let ok = set_no_new_privs().is_ok()
                && unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } == 1;
            unsafe {
                libc::_exit(if ok { 0 } else { 1 });
            }
        }

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "child did not set no_new_privs: status={status}"
        );
    }

    #[test]
    fn helper_state_round_trips_optional_process_group() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path();
        let state = HelperState {
            owner_uid: 1000,
            destroy_token: valid_test_token(),
            process_group: None,
        };

        write_helper_state_file(path, &state).unwrap();
        assert_eq!(read_helper_state_file(path).unwrap(), state);

        let state = HelperState {
            process_group: Some(4242),
            ..state
        };
        write_helper_state_file(path, &state).unwrap();
        assert_eq!(read_helper_state_file(path).unwrap(), state);
    }

    #[test]
    fn network_namespace_member_scan_can_find_current_process() {
        let metadata = std::fs::metadata("/proc/self/ns/net").unwrap();
        let current_pid = unsafe { libc::getpid() };

        let members = network_namespace_members(metadata.dev(), metadata.ino(), false).unwrap();
        assert!(
            members.contains(&current_pid),
            "current process should be in its own network namespace member scan"
        );

        let members_without_self =
            network_namespace_members(metadata.dev(), metadata.ino(), true).unwrap();
        assert!(
            !members_without_self.contains(&current_pid),
            "skip_self must exclude the helper process from namespace cleanup"
        );
    }

    #[test]
    fn helper_target_exit_cleanup_kills_pgroup_then_netns_members_then_destroys() {
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let allocation = proxy_netns_allocation(sandbox_id, 3128);
        let paths = fixed_test_paths();
        let mut runner = FakeRunner::default();
        let events = RefCell::new(Vec::new());

        cleanup_helper_allocation_after_target_exit_with(
            HelperCleanupContext {
                sandbox_id,
                helper_pgid: 4242,
                allocation: &allocation,
                paths: &paths,
                runner: &mut runner,
            },
            RecordingCleanupHooks {
                events: &events,
                fail_netns_members: false,
            },
        )
        .unwrap();

        assert_eq!(
            events.into_inner(),
            vec![
                "pgroup 4242".to_string(),
                format!("netns {}", allocation.namespace),
                format!("destroy {}", allocation.namespace),
            ]
        );
    }

    #[test]
    fn helper_target_exit_cleanup_stops_before_destroy_when_netns_members_survive() {
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let allocation = proxy_netns_allocation(sandbox_id, 3128);
        let paths = fixed_test_paths();
        let mut runner = FakeRunner::default();
        let events = RefCell::new(Vec::new());

        let err = cleanup_helper_allocation_after_target_exit_with(
            HelperCleanupContext {
                sandbox_id,
                helper_pgid: 4242,
                allocation: &allocation,
                paths: &paths,
                runner: &mut runner,
            },
            RecordingCleanupHooks {
                events: &events,
                fail_netns_members: true,
            },
        )
        .unwrap_err();

        assert!(err.contains("network namespace still has members"));
        assert_eq!(
            events.into_inner(),
            vec![
                "pgroup 4242".to_string(),
                format!("netns {}", allocation.namespace),
            ]
        );
    }

    struct RecordingCleanupHooks<'a> {
        events: &'a RefCell<Vec<String>>,
        fail_netns_members: bool,
    }

    impl HelperCleanupHooks for RecordingCleanupHooks<'_> {
        fn kill_process_group(&mut self, pgid: libc::pid_t) -> Result<(), String> {
            self.events.borrow_mut().push(format!("pgroup {pgid}"));
            Ok(())
        }

        fn kill_network_namespace_members(&mut self, namespace: &str) -> Result<(), String> {
            self.events.borrow_mut().push(format!("netns {namespace}"));
            if self.fail_netns_members {
                Err("network namespace still has members".into())
            } else {
                Ok(())
            }
        }

        fn destroy_namespace(
            &mut self,
            namespace: &str,
            _paths: &NetnsCommandPaths,
            _runner: &mut dyn CommandRunner,
        ) -> Result<(), String> {
            self.events
                .borrow_mut()
                .push(format!("destroy {namespace}"));
            Ok(())
        }
    }

    #[test]
    fn process_stat_parser_handles_command_names_with_spaces() {
        assert_eq!(
            parse_process_stat_pgrp("123 (cmd with spaces) S 1 456 456 0"),
            Some(456)
        );
        assert_eq!(parse_process_stat_pgrp("malformed"), None);
    }

    #[test]
    fn helper_sync_reader_accepts_ok_and_reports_errors() {
        let (read_fd, write_fd) = test_pipe();
        super::super::write_all_fd(write_fd, HELPER_SYNC_OK.as_bytes()).unwrap();
        unsafe {
            libc::close(write_fd);
        }
        read_helper_sync(read_fd).unwrap();

        let (read_fd, write_fd) = test_pipe();
        super::super::write_all_fd(write_fd, b"ERR setup failed\n").unwrap();
        unsafe {
            libc::close(write_fd);
        }
        assert_eq!(read_helper_sync(read_fd).unwrap_err(), "setup failed");

        let (read_fd, write_fd) = test_pipe();
        unsafe {
            libc::close(write_fd);
        }
        assert!(
            read_helper_sync(read_fd)
                .unwrap_err()
                .contains("before reporting")
        );
    }

    #[test]
    fn helper_create_uses_fixed_paths_for_programs_and_nested_execs() {
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let allocation = proxy_netns_allocation(sandbox_id, 3128);
        let paths = fixed_test_paths();
        let mut runner = FakeRunner::default();

        create_with_runner_and_paths(&allocation, &paths, &mut runner).unwrap();

        let rendered: Vec<String> = runner
            .commands
            .iter()
            .map(|command| format!("{} {}", command.program, command.args.join(" ")))
            .collect();

        assert!(!rendered.is_empty());
        assert!(
            runner
                .commands
                .iter()
                .all(|command| command.program == "/usr/sbin/ip")
        );
        assert!(rendered.iter().any(|cmd| cmd.contains(
            "netns exec axis-00000000-0000-4000-8000-000000000001 /usr/sbin/ip addr add"
        )));
        assert!(rendered
            .iter()
            .any(|cmd| cmd.contains("netns exec axis-00000000-0000-4000-8000-000000000001 /usr/sbin/sysctl -w net.ipv6.conf.all.disable_ipv6=1")));
        assert!(rendered.iter().any(|cmd| cmd.contains(
            "netns exec axis-00000000-0000-4000-8000-000000000001 /usr/sbin/iptables -P OUTPUT DROP"
        )));
    }

    #[test]
    fn helper_create_cleans_up_with_fixed_paths_after_failure() {
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let allocation = proxy_netns_allocation(sandbox_id, 3128);
        let paths = fixed_test_paths();
        let mut runner = FakeRunner {
            fail_at: Some(2),
            ..Default::default()
        };

        let err = create_with_runner_and_paths(&allocation, &paths, &mut runner).unwrap_err();
        let rendered: Vec<String> = runner
            .commands
            .iter()
            .map(|command| format!("{} {}", command.program, command.args.join(" ")))
            .collect();

        assert!(err.contains("forced failure"));
        assert!(rendered.iter().any(|cmd| {
            cmd == "/usr/sbin/ip netns del axis-00000000-0000-4000-8000-000000000001"
        }));
        assert!(
            rendered
                .iter()
                .any(|cmd| { cmd == "/usr/sbin/ip link del axh000000000000" })
        );
    }

    #[test]
    fn legacy_helper_create_destroy_reject_non_root_callers() {
        if unsafe { libc::getuid() } == 0 {
            eprintln!("running as root (test skipped)");
            return;
        }

        let paths = fixed_test_paths();
        let mut runner = FakeRunner::default();
        let err = run_helper_with_runner(
            &strings(["create", "00000000-0000-4000-8000-000000000001", "3128"]),
            &paths,
            &mut runner,
        )
        .unwrap_err();

        assert!(err.contains("real UID 0"));
        assert!(runner.commands.is_empty());
    }

    #[test]
    fn safe_root_executable_rejects_group_or_world_writable_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let candidate = dir.path().join("ip");
        std::fs::write(&candidate, b"#!/bin/sh\n").unwrap();
        let mut permissions = std::fs::metadata(&candidate).unwrap().permissions();
        permissions.set_mode(0o777);
        std::fs::set_permissions(&candidate, permissions).unwrap();

        assert!(!safe_root_executable(&candidate));
    }

    #[test]
    fn safe_root_owner_and_mode_accepts_only_root_owned_non_writable_paths() {
        assert!(safe_root_owner_and_mode(0, 0o755));
        assert!(safe_root_owner_and_mode(0, 0o500));
        assert!(!safe_root_owner_and_mode(1000, 0o755));
        assert!(!safe_root_owner_and_mode(0, 0o775));
        assert!(!safe_root_owner_and_mode(0, 0o777));
    }

    #[test]
    fn safe_root_metadata_checks_path_kind_and_symlink_state() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("ip");
        let non_executable = dir.path().join("iptables");
        let link = dir.path().join("sysctl");
        std::fs::write(&executable, b"#!/bin/sh\n").unwrap();
        std::fs::write(&non_executable, b"#!/bin/sh\n").unwrap();
        symlink(&executable, &link).unwrap();

        let mut executable_permissions = std::fs::metadata(&executable).unwrap().permissions();
        executable_permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, executable_permissions).unwrap();

        let mut non_executable_permissions =
            std::fs::metadata(&non_executable).unwrap().permissions();
        non_executable_permissions.set_mode(0o644);
        std::fs::set_permissions(&non_executable, non_executable_permissions).unwrap();

        let executable_metadata = std::fs::symlink_metadata(&executable).unwrap();
        let non_executable_metadata = std::fs::symlink_metadata(&non_executable).unwrap();
        let directory_metadata = std::fs::symlink_metadata(dir.path()).unwrap();
        let link_metadata = std::fs::symlink_metadata(&link).unwrap();

        assert!(!safe_root_metadata(
            &directory_metadata,
            SafePathKind::ExecutableFile
        ));
        assert!(!safe_root_metadata(
            &executable_metadata,
            SafePathKind::AncestorDirectory
        ));
        assert!(!safe_root_metadata(
            &non_executable_metadata,
            SafePathKind::ExecutableFile
        ));
        assert!(!safe_root_metadata(
            &link_metadata,
            SafePathKind::ExecutableFile
        ));
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
        assert!(
            rendered
                .iter()
                .any(|cmd| cmd.contains(&allocation.host_cidr))
        );
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
        let bypass_prefix = crate::linux::bypass_audit::bypass_log_prefix(sandbox_id);
        assert!(rendered.iter().any(|cmd| {
            cmd.contains(&format!(
                "iptables -A OUTPUT -j LOG --log-prefix {bypass_prefix}"
            ))
        }));
        assert!(
            bypass_prefix.len() <= crate::linux::bypass_audit::IPTABLES_LOG_PREFIX_LIMIT,
            "iptables log prefix exceeded kernel limit"
        );
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
            return Err(format!(
                "sandbox reached denied host-veth port {denied_port}"
            ));
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
        let listener =
            std::net::TcpListener::bind(SocketAddr::new(allocation.host_addr.into(), port))
                .map_err(|e| format!("host listener bind {port}: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("host listener nonblocking: {e}"))?;
        Ok(listener)
    }

    fn run_netns_python(namespace: &str, code: &str) -> Result<std::process::ExitStatus, String> {
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

    fn strings<const N: usize>(values: [&str; N]) -> Vec<String> {
        values.into_iter().map(str::to_string).collect()
    }

    fn fixed_test_paths() -> NetnsCommandPaths {
        NetnsCommandPaths {
            ip: "/usr/sbin/ip".into(),
            iptables: "/usr/sbin/iptables".into(),
            sysctl: "/usr/sbin/sysctl".into(),
        }
    }

    fn valid_test_token() -> String {
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into()
    }

    fn helper_launch_spec() -> HelperLaunchSpec {
        HelperLaunchSpec {
            launch_kind: HelperLaunchKind::DirectProcess,
            mxc_config_fd: None,
            workspace_dir: tempfile::tempdir().unwrap().path().to_path_buf(),
            filesystem: FilesystemPolicy::default(),
            process: ProcessPolicy {
                cpu_rate_percent: 0,
                ..ProcessPolicy::default()
            },
            rlimits: HelperRlimits::default(),
            command: "true".into(),
            args: Vec::new(),
            env: Vec::new(),
            destroy_token: valid_test_token(),
        }
    }

    fn test_pipe() -> (RawFd, RawFd) {
        let mut fds = [0; 2];
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "pipe failed: {}", std::io::Error::last_os_error());
        (fds[0], fds[1])
    }
}
