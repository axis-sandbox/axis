// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Binary identity via SHA256 Trust-on-First-Use (TOFU) fingerprinting.
//!
//! When a process makes a network request through the proxy, we identify
//! the calling binary by resolving /proc/[pid]/net/tcp → socket inode →
//! /proc/[pid]/fd → /proc/[pid]/exe and computing a SHA256 hash. The first
//! time a binary is seen, its hash is recorded. Subsequent requests verify
//! the hash matches.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::fs::File;
use std::io::Read;
#[cfg(target_os = "linux")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("failed to resolve binary for pid {pid}: {reason}")]
    ResolveFailed { pid: u32, reason: String },

    #[error("binary hash mismatch for {path}: expected {expected}, got {actual}")]
    HashMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// SHA256 fingerprint of a binary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BinaryFingerprint {
    pub path: PathBuf,
    pub sha256: String,
}

/// Trust-on-First-Use binary identity store.
pub struct TofuStore {
    /// Known binary fingerprints: path → sha256.
    known: HashMap<PathBuf, String>,
}

impl TofuStore {
    pub fn new() -> Self {
        Self {
            known: HashMap::new(),
        }
    }

    /// Verify a binary's identity. On first use, records the hash.
    /// On subsequent uses, verifies the hash matches.
    pub fn verify(&mut self, path: &Path) -> Result<BinaryFingerprint, IdentityError> {
        let hash = hash_file(path)?;
        let fingerprint = BinaryFingerprint {
            path: path.to_path_buf(),
            sha256: hash,
        };
        self.verify_fingerprint(&fingerprint)?;
        Ok(fingerprint)
    }

    /// Verify an already-observed binary fingerprint. This is used when Linux
    /// identity resolution hashes /proc/[pid]/exe directly, avoiding a second
    /// path-based open that could race replacement of the executable path.
    pub fn verify_fingerprint(
        &mut self,
        fingerprint: &BinaryFingerprint,
    ) -> Result<(), IdentityError> {
        if let Some(expected) = self.known.get(&fingerprint.path) {
            if *expected != fingerprint.sha256 {
                return Err(IdentityError::HashMismatch {
                    path: fingerprint.path.clone(),
                    expected: expected.clone(),
                    actual: fingerprint.sha256.clone(),
                });
            }
        } else {
            tracing::info!(
                "TOFU: first use of binary {}, hash={}",
                fingerprint.path.display(),
                &fingerprint.sha256[..16]
            );
            self.known
                .insert(fingerprint.path.clone(), fingerprint.sha256.clone());
        }
        Ok(())
    }

    /// Resolve the binary path for a PID via /proc/[pid]/exe.
    pub fn resolve_binary(pid: u32) -> Result<PathBuf, IdentityError> {
        let exe_link = format!("/proc/{pid}/exe");
        std::fs::read_link(&exe_link).map_err(|e| IdentityError::ResolveFailed {
            pid,
            reason: e.to_string(),
        })
    }
}

/// Resolve which binary owns a TCP connection from a peer address.
///
/// Algorithm (Linux-specific):
/// 1. Parse /proc/[pid]/net/tcp and tcp6 tables to find the client-side
///    socket matching peer_addr -> proxy_addr. Reading through each PID is
///    intentional because the proxy may be outside the sandbox network
///    namespace while the client socket is inside it.
/// 2. Record the network namespace where the socket table was observed.
/// 3. Scan /proc/*/fd/ for the socket inode, accepting only owners in the
///    same network namespace.
/// 4. Open /proc/[pid]/exe once, derive the display path from that opened
///    file descriptor, and hash the same file object.
#[cfg(target_os = "linux")]
pub fn resolve_peer_binary(
    peer_addr: SocketAddr,
    proxy_addr: SocketAddr,
) -> Result<PathBuf, IdentityError> {
    resolve_peer_identity(peer_addr, proxy_addr).map(|identity| identity.path)
}

#[cfg(target_os = "linux")]
pub fn resolve_peer_identity(
    peer_addr: SocketAddr,
    proxy_addr: SocketAddr,
) -> Result<BinaryFingerprint, IdentityError> {
    resolve_peer_identity_in_proc(Path::new("/proc"), peer_addr, proxy_addr)
}

#[cfg(target_os = "linux")]
fn resolve_peer_identity_in_proc(
    proc_root: &Path,
    peer_addr: SocketAddr,
    proxy_addr: SocketAddr,
) -> Result<BinaryFingerprint, IdentityError> {
    let candidates = find_socket_candidates(proc_root, peer_addr, proxy_addr)?;
    let mut identities = Vec::new();
    for candidate in candidates {
        if let Some(identity) =
            resolve_inode_owner_identity_in_netns(proc_root, candidate.inode, &candidate.netns)?
        {
            if !identities.contains(&identity) {
                identities.push(identity);
            }
        }
    }

    match identities.len() {
        0 => Err(IdentityError::ResolveFailed {
            pid: 0,
            reason: format!(
                "no process in matching network namespace owns socket for {peer_addr} -> {proxy_addr}"
            ),
        }),
        1 => Ok(identities.remove(0)),
        _ => Err(IdentityError::ResolveFailed {
            pid: 0,
            reason: format!("multiple binaries match socket for {peer_addr} -> {proxy_addr}"),
        }),
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SocketCandidate {
    inode: u64,
    netns: String,
}

#[cfg(target_os = "linux")]
fn find_socket_candidates(
    proc_root: &Path,
    peer_addr: SocketAddr,
    proxy_addr: SocketAddr,
) -> Result<Vec<SocketCandidate>, IdentityError> {
    let mut candidates = Vec::new();

    for pid in list_pids(proc_root)? {
        let netns = match read_proc_netns(proc_root, pid) {
            Ok(netns) => netns,
            Err(_) => continue,
        };

        for table in ["tcp", "tcp6"] {
            let table_path = proc_pid_path(proc_root, pid).join("net").join(table);
            let table_data = match std::fs::read_to_string(table_path) {
                Ok(data) => data,
                Err(_) => continue,
            };
            let is_ipv6 = table == "tcp6";

            for line in table_data.lines().skip(1) {
                let Some(entry) = parse_tcp_entry(line, is_ipv6) else {
                    continue;
                };
                if entry.inode == 0 || entry.state != "01" {
                    continue;
                }
                if !socket_addr_matches(entry.local, peer_addr)
                    || !socket_addr_matches(entry.remote, proxy_addr)
                {
                    continue;
                }

                let candidate = SocketCandidate {
                    inode: entry.inode,
                    netns: netns.clone(),
                };
                if !candidates.contains(&candidate) {
                    candidates.push(candidate);
                }
            }
        }
    }

    if candidates.is_empty() {
        return Err(IdentityError::ResolveFailed {
            pid: 0,
            reason: format!("no client socket found for {peer_addr} -> {proxy_addr}"),
        });
    }

    Ok(candidates)
}

#[cfg(target_os = "linux")]
fn resolve_inode_owner_identity_in_netns(
    proc_root: &Path,
    target_inode: u64,
    expected_netns: &str,
) -> Result<Option<BinaryFingerprint>, IdentityError> {
    let owners = find_pids_for_inode_in_netns(proc_root, target_inode, expected_netns)?;
    if owners.is_empty() {
        return Ok(None);
    }

    let mut owner_identities = Vec::new();
    for pid in owners {
        let identity = resolve_binary_fingerprint_in_proc(proc_root, pid)?;
        if !owner_identities.contains(&identity) {
            owner_identities.push(identity);
        }
    }

    if owner_identities.len() == 1 {
        Ok(owner_identities.pop())
    } else {
        Err(IdentityError::ResolveFailed {
            pid: 0,
            reason: format!(
                "socket inode {target_inode} is owned by multiple binaries in network namespace {expected_netns}"
            ),
        })
    }
}

/// Scan /proc/*/fd/ to find which PIDs own a socket inode in the expected
/// network namespace.
#[cfg(target_os = "linux")]
fn find_pids_for_inode_in_netns(
    proc_root: &Path,
    target_inode: u64,
    expected_netns: &str,
) -> Result<Vec<u32>, IdentityError> {
    let target_link = format!("socket:[{target_inode}]");
    let mut owners = Vec::new();

    for pid in list_pids(proc_root)? {
        let Ok(owner_netns) = read_proc_netns(proc_root, pid) else {
            continue;
        };
        if owner_netns != expected_netns {
            continue;
        }

        let fd_dir = proc_pid_path(proc_root, pid).join("fd");
        let fds = match std::fs::read_dir(fd_dir) {
            Ok(d) => d,
            Err(_) => continue, // Permission denied for other users' procs.
        };

        for fd_entry in fds.flatten() {
            let link = match std::fs::read_link(fd_entry.path()) {
                Ok(l) => l,
                Err(_) => continue,
            };
            if link.to_string_lossy() == target_link {
                owners.push(pid);
                break;
            }
        }
    }

    Ok(owners)
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct TcpEntry {
    local: SocketAddr,
    remote: SocketAddr,
    state: String,
    inode: u64,
}

/// Parse a /proc/[pid]/net/tcp or tcp6 data line.
///
/// Format (whitespace-separated):
///   sl  local_address rem_address   st tx_queue rx_queue ...  inode
///   0:  0100007F:33A4 0100007F:0CEA  01 ...                   12345
///
/// Addresses are hex: IP (little-endian) : port (big-endian).
#[cfg(target_os = "linux")]
fn parse_tcp_entry(line: &str, is_ipv6: bool) -> Option<TcpEntry> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 10 {
        return None;
    }

    let local = parse_proc_socket_addr(fields[1], is_ipv6)?;
    let remote = parse_proc_socket_addr(fields[2], is_ipv6)?;
    let inode = fields[9].parse::<u64>().ok()?;

    Some(TcpEntry {
        local,
        remote,
        state: fields[3].to_string(),
        inode,
    })
}

#[cfg(target_os = "linux")]
fn parse_proc_socket_addr(raw: &str, is_ipv6: bool) -> Option<SocketAddr> {
    let (ip_hex, port_hex) = raw.rsplit_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = if is_ipv6 {
        IpAddr::V6(parse_proc_ipv6(ip_hex)?)
    } else {
        IpAddr::V4(parse_proc_ipv4(ip_hex)?)
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg(target_os = "linux")]
fn parse_proc_ipv4(raw: &str) -> Option<Ipv4Addr> {
    if raw.len() != 8 {
        return None;
    }
    let value = u32::from_str_radix(raw, 16).ok()?;
    Some(Ipv4Addr::from(value.to_le_bytes()))
}

#[cfg(target_os = "linux")]
fn parse_proc_ipv6(raw: &str) -> Option<Ipv6Addr> {
    if raw.len() != 32 {
        return None;
    }

    let mut octets = [0u8; 16];
    for (index, chunk) in raw.as_bytes().chunks_exact(8).enumerate() {
        let chunk = std::str::from_utf8(chunk).ok()?;
        let value = u32::from_str_radix(chunk, 16).ok()?;
        octets[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    Some(Ipv6Addr::from(octets))
}

#[cfg(target_os = "linux")]
fn socket_addr_matches(left: SocketAddr, right: SocketAddr) -> bool {
    left.port() == right.port() && ip_addr_matches(left.ip(), right.ip())
}

#[cfg(target_os = "linux")]
fn ip_addr_matches(left: IpAddr, right: IpAddr) -> bool {
    if left == right {
        return true;
    }

    match (left, right) {
        (IpAddr::V6(left), IpAddr::V4(right)) => left.to_ipv4_mapped() == Some(right),
        (IpAddr::V4(left), IpAddr::V6(right)) => right.to_ipv4_mapped() == Some(left),
        _ => false,
    }
}

#[cfg(target_os = "linux")]
fn list_pids(proc_root: &Path) -> Result<Vec<u32>, IdentityError> {
    let proc_dir = std::fs::read_dir(proc_root).map_err(|e| IdentityError::ResolveFailed {
        pid: 0,
        reason: format!("cannot read {}: {e}", proc_root.display()),
    })?;

    let mut pids = Vec::new();
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Ok(pid) = name.parse::<u32>() {
            pids.push(pid);
        }
    }
    Ok(pids)
}

#[cfg(target_os = "linux")]
fn read_proc_netns(proc_root: &Path, pid: u32) -> std::io::Result<String> {
    std::fs::read_link(proc_pid_path(proc_root, pid).join("ns/net"))
        .map(|path| path.to_string_lossy().into_owned())
}

#[cfg(target_os = "linux")]
fn resolve_binary_fingerprint_in_proc(
    proc_root: &Path,
    pid: u32,
) -> Result<BinaryFingerprint, IdentityError> {
    let exe_link = proc_pid_path(proc_root, pid).join("exe");
    let mut exe_file = File::open(&exe_link).map_err(|e| IdentityError::ResolveFailed {
        pid,
        reason: e.to_string(),
    })?;
    let fd_path = PathBuf::from(format!("/proc/self/fd/{}", exe_file.as_raw_fd()));
    let path = std::fs::read_link(&fd_path).map_err(|e| IdentityError::ResolveFailed {
        pid,
        reason: e.to_string(),
    })?;
    let sha256 = hash_reader(&mut exe_file).map_err(|e| IdentityError::ResolveFailed {
        pid,
        reason: e.to_string(),
    })?;
    Ok(BinaryFingerprint { path, sha256 })
}

#[cfg(target_os = "linux")]
fn proc_pid_path(proc_root: &Path, pid: u32) -> PathBuf {
    proc_root.join(pid.to_string())
}

/// Compute SHA256 hash of a file.
fn hash_file(path: &Path) -> Result<String, IdentityError> {
    let mut file = std::fs::File::open(path)?;
    hash_reader(&mut file)
}

/// Compute SHA256 hash of a reader.
fn hash_reader(reader: &mut impl Read) -> Result<String, IdentityError> {
    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;
    let hash = Sha256::digest(&data);
    Ok(hex::encode(hash))
}

/// Minimal hex encoding (avoids adding the `hex` crate dependency).
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[cfg(target_os = "linux")]
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    #[cfg(target_os = "linux")]
    use std::path::Path;

    #[test]
    fn tofu_first_use_records_hash() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test-binary");
        std::fs::File::create(&file)
            .unwrap()
            .write_all(b"fake binary content")
            .unwrap();

        let mut store = TofuStore::new();
        let fp = store.verify(&file).unwrap();
        assert!(!fp.sha256.is_empty());
        assert_eq!(fp.path, file);
    }

    #[test]
    fn tofu_same_hash_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test-binary");
        std::fs::File::create(&file)
            .unwrap()
            .write_all(b"fake binary content")
            .unwrap();

        let mut store = TofuStore::new();
        let fp1 = store.verify(&file).unwrap();
        let fp2 = store.verify(&file).unwrap();
        assert_eq!(fp1.sha256, fp2.sha256);
    }

    #[test]
    fn tofu_changed_hash_fails() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test-binary");
        std::fs::File::create(&file)
            .unwrap()
            .write_all(b"original content")
            .unwrap();

        let mut store = TofuStore::new();
        store.verify(&file).unwrap();

        // Modify the file.
        std::fs::File::create(&file)
            .unwrap()
            .write_all(b"modified content")
            .unwrap();

        let err = store.verify(&file).unwrap_err();
        assert!(matches!(err, IdentityError::HashMismatch { .. }));
    }

    #[test]
    fn tofu_fingerprint_hash_mismatch_fails_without_rehashing_path() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test-binary");
        std::fs::write(&file, b"same path").unwrap();

        let mut store = TofuStore::new();
        let first = BinaryFingerprint {
            path: file.clone(),
            sha256: "0".repeat(64),
        };
        let second = BinaryFingerprint {
            path: file,
            sha256: "1".repeat(64),
        };

        store.verify_fingerprint(&first).unwrap();
        let err = store.verify_fingerprint(&second).unwrap_err();
        assert!(matches!(err, IdentityError::HashMismatch { .. }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_peer_binary_from_fake_proc_netns_socket() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = dir.path().join("proc");
        std::fs::create_dir(&proc_root).unwrap();
        let binary = write_binary(dir.path(), "curl");
        let peer = socket_v4([10, 200, 0, 2], 49152);
        let proxy = socket_v4([10, 200, 0, 1], 3128);
        let inode = 4242;

        create_proc_process(&proc_root, 100, "net:[4026533000]", &binary);
        write_tcp_table(&proc_root, 100, peer, proxy, inode);
        link_socket_fd(&proc_root, 100, 3, inode);

        let resolved = resolve_peer_identity_in_proc(&proc_root, peer, proxy).unwrap();
        assert_eq!(resolved.path, binary);
        assert_eq!(resolved.sha256, hash_file(&resolved.path).unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_peer_binary_finds_fd_owner_in_same_netns() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = dir.path().join("proc");
        std::fs::create_dir(&proc_root).unwrap();
        let table_binary = write_binary(dir.path(), "table-process");
        let owner_binary = write_binary(dir.path(), "owner-process");
        let peer = socket_v4([10, 200, 0, 2], 49153);
        let proxy = socket_v4([10, 200, 0, 1], 3128);
        let inode = 5252;

        create_proc_process(&proc_root, 100, "net:[4026533001]", &table_binary);
        write_tcp_table(&proc_root, 100, peer, proxy, inode);
        create_proc_process(&proc_root, 101, "net:[4026533001]", &owner_binary);
        write_empty_tcp_tables(&proc_root, 101);
        link_socket_fd(&proc_root, 101, 4, inode);

        let resolved = resolve_peer_identity_in_proc(&proc_root, peer, proxy).unwrap();
        assert_eq!(resolved.path, owner_binary);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_peer_binary_allows_multiple_owners_for_same_binary() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = dir.path().join("proc");
        std::fs::create_dir(&proc_root).unwrap();
        let binary = write_binary(dir.path(), "shared-owner");
        let peer = socket_v4([10, 200, 0, 2], 49156);
        let proxy = socket_v4([10, 200, 0, 1], 3128);
        let inode = 5656;

        create_proc_process(&proc_root, 100, "net:[4026533010]", &binary);
        write_tcp_table(&proc_root, 100, peer, proxy, inode);
        link_socket_fd(&proc_root, 100, 3, inode);
        create_proc_process(&proc_root, 101, "net:[4026533010]", &binary);
        write_empty_tcp_tables(&proc_root, 101);
        link_socket_fd(&proc_root, 101, 4, inode);

        let resolved = resolve_peer_identity_in_proc(&proc_root, peer, proxy).unwrap();
        assert_eq!(resolved.path, binary);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_peer_binary_rejects_multiple_owner_binaries() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = dir.path().join("proc");
        std::fs::create_dir(&proc_root).unwrap();
        let table_binary = write_binary(dir.path(), "table-process");
        let first_owner = write_binary(dir.path(), "first-owner");
        let second_owner = write_binary(dir.path(), "second-owner");
        let peer = socket_v4([10, 200, 0, 2], 49157);
        let proxy = socket_v4([10, 200, 0, 1], 3128);
        let inode = 5757;

        create_proc_process(&proc_root, 100, "net:[4026533011]", &table_binary);
        write_tcp_table(&proc_root, 100, peer, proxy, inode);
        create_proc_process(&proc_root, 101, "net:[4026533011]", &first_owner);
        write_empty_tcp_tables(&proc_root, 101);
        link_socket_fd(&proc_root, 101, 4, inode);
        create_proc_process(&proc_root, 102, "net:[4026533011]", &second_owner);
        write_empty_tcp_tables(&proc_root, 102);
        link_socket_fd(&proc_root, 102, 5, inode);

        let err = resolve_peer_identity_in_proc(&proc_root, peer, proxy).unwrap_err();
        assert!(matches!(err, IdentityError::ResolveFailed { .. }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_peer_binary_allows_duplicate_candidates_with_same_identity() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = dir.path().join("proc");
        std::fs::create_dir(&proc_root).unwrap();
        let binary = write_binary(dir.path(), "shared-candidate");
        let peer = socket_v4([10, 200, 0, 2], 49159);
        let proxy = socket_v4([10, 200, 0, 1], 3128);

        create_proc_process(&proc_root, 100, "net:[4026533012]", &binary);
        write_tcp_table(&proc_root, 100, peer, proxy, 5959);
        link_socket_fd(&proc_root, 100, 3, 5959);
        create_proc_process(&proc_root, 200, "net:[4026533013]", &binary);
        write_tcp_table(&proc_root, 200, peer, proxy, 6969);
        link_socket_fd(&proc_root, 200, 3, 6969);

        let resolved = resolve_peer_identity_in_proc(&proc_root, peer, proxy).unwrap();
        assert_eq!(resolved.path, binary);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_peer_binary_rejects_duplicate_candidates_with_different_binaries() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = dir.path().join("proc");
        std::fs::create_dir(&proc_root).unwrap();
        let first_binary = write_binary(dir.path(), "first-candidate");
        let second_binary = write_binary(dir.path(), "second-candidate");
        let peer = socket_v4([10, 200, 0, 2], 49160);
        let proxy = socket_v4([10, 200, 0, 1], 3128);

        create_proc_process(&proc_root, 100, "net:[4026533014]", &first_binary);
        write_tcp_table(&proc_root, 100, peer, proxy, 6060);
        link_socket_fd(&proc_root, 100, 3, 6060);
        create_proc_process(&proc_root, 200, "net:[4026533015]", &second_binary);
        write_tcp_table(&proc_root, 200, peer, proxy, 7070);
        link_socket_fd(&proc_root, 200, 3, 7070);

        let err = resolve_peer_identity_in_proc(&proc_root, peer, proxy).unwrap_err();
        assert!(matches!(err, IdentityError::ResolveFailed { .. }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_peer_binary_rejects_owner_in_different_netns() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = dir.path().join("proc");
        std::fs::create_dir(&proc_root).unwrap();
        let table_binary = write_binary(dir.path(), "table-process");
        let owner_binary = write_binary(dir.path(), "owner-process");
        let peer = socket_v4([10, 200, 0, 2], 49154);
        let proxy = socket_v4([10, 200, 0, 1], 3128);
        let inode = 6262;

        create_proc_process(&proc_root, 100, "net:[4026533002]", &table_binary);
        write_tcp_table(&proc_root, 100, peer, proxy, inode);
        create_proc_process(&proc_root, 200, "net:[4026531993]", &owner_binary);
        write_empty_tcp_tables(&proc_root, 200);
        link_socket_fd(&proc_root, 200, 5, inode);

        let err = resolve_peer_identity_in_proc(&proc_root, peer, proxy).unwrap_err();
        assert!(matches!(err, IdentityError::ResolveFailed { .. }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_peer_binary_requires_exact_proxy_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = dir.path().join("proc");
        std::fs::create_dir(&proc_root).unwrap();
        let binary = write_binary(dir.path(), "curl");
        let peer = socket_v4([127, 0, 0, 1], 49155);
        let actual_proxy = socket_v4([127, 0, 0, 1], 3129);
        let queried_proxy = socket_v4([127, 0, 0, 1], 3128);
        let inode = 7272;

        create_proc_process(&proc_root, 100, "net:[4026533003]", &binary);
        write_tcp_table(&proc_root, 100, peer, actual_proxy, inode);
        link_socket_fd(&proc_root, 100, 3, inode);

        let err = resolve_peer_identity_in_proc(&proc_root, peer, queried_proxy).unwrap_err();
        assert!(matches!(err, IdentityError::ResolveFailed { .. }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_peer_binary_ignores_non_established_socket_state() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = dir.path().join("proc");
        std::fs::create_dir(&proc_root).unwrap();
        let binary = write_binary(dir.path(), "curl");
        let peer = socket_v4([127, 0, 0, 1], 49158);
        let proxy = socket_v4([127, 0, 0, 1], 3128);
        let inode = 8282;

        create_proc_process(&proc_root, 100, "net:[4026533004]", &binary);
        write_tcp_table_with_state(&proc_root, 100, peer, proxy, inode, "0A");
        link_socket_fd(&proc_root, 100, 3, inode);

        let err = resolve_peer_identity_in_proc(&proc_root, peer, proxy).unwrap_err();
        assert!(matches!(err, IdentityError::ResolveFailed { .. }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_peer_binary_fails_when_owner_exe_cannot_be_read() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = dir.path().join("proc");
        std::fs::create_dir(&proc_root).unwrap();
        let table_binary = write_binary(dir.path(), "table-process");
        let peer = socket_v4([127, 0, 0, 1], 49161);
        let proxy = socket_v4([127, 0, 0, 1], 3128);
        let inode = 8383;

        create_proc_process(&proc_root, 100, "net:[4026533005]", &table_binary);
        write_tcp_table(&proc_root, 100, peer, proxy, inode);
        create_proc_process_without_exe(&proc_root, 101, "net:[4026533005]");
        write_empty_tcp_tables(&proc_root, 101);
        link_socket_fd(&proc_root, 101, 3, inode);

        let err = resolve_peer_identity_in_proc(&proc_root, peer, proxy).unwrap_err();
        assert!(matches!(err, IdentityError::ResolveFailed { .. }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_tcp_entry_ignores_malformed_rows() {
        assert!(parse_tcp_entry("not enough fields", false).is_none());
        assert!(parse_tcp_entry("0: not-an-address 0100007F:0C38 01 0 0 0 0 0 1", false).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_socket_addr_decodes_ipv4_little_endian() {
        let parsed = parse_proc_socket_addr("0100007F:C001", false).unwrap();
        assert_eq!(parsed, socket_v4([127, 0, 0, 1], 49153));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_socket_addr_decodes_ipv6_little_endian_words() {
        let parsed = parse_proc_socket_addr("00000000000000000000000001000000:0C38", true).unwrap();
        assert_eq!(parsed, "[::1]:3128".parse::<SocketAddr>().unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_addr_matches_ipv4_mapped_ipv6() {
        let mapped = "[::ffff:127.0.0.1]:3128".parse::<SocketAddr>().unwrap();
        assert!(socket_addr_matches(mapped, socket_v4([127, 0, 0, 1], 3128)));
    }

    #[cfg(target_os = "linux")]
    fn write_binary(dir: &Path, name: &str) -> PathBuf {
        let file = dir.join(name);
        std::fs::write(&file, format!("{name}\n")).unwrap();
        file
    }

    #[cfg(target_os = "linux")]
    fn create_proc_process(proc_root: &Path, pid: u32, netns: &str, exe: &Path) {
        let pid_root = proc_root.join(pid.to_string());
        std::fs::create_dir_all(pid_root.join("fd")).unwrap();
        std::fs::create_dir_all(pid_root.join("net")).unwrap();
        std::fs::create_dir_all(pid_root.join("ns")).unwrap();
        std::os::unix::fs::symlink(exe, pid_root.join("exe")).unwrap();
        std::os::unix::fs::symlink(netns, pid_root.join("ns/net")).unwrap();
    }

    #[cfg(target_os = "linux")]
    fn create_proc_process_without_exe(proc_root: &Path, pid: u32, netns: &str) {
        let pid_root = proc_root.join(pid.to_string());
        std::fs::create_dir_all(pid_root.join("fd")).unwrap();
        std::fs::create_dir_all(pid_root.join("net")).unwrap();
        std::fs::create_dir_all(pid_root.join("ns")).unwrap();
        std::os::unix::fs::symlink(netns, pid_root.join("ns/net")).unwrap();
    }

    #[cfg(target_os = "linux")]
    fn write_tcp_table(
        proc_root: &Path,
        pid: u32,
        local: SocketAddr,
        remote: SocketAddr,
        inode: u64,
    ) {
        write_tcp_table_with_state(proc_root, pid, local, remote, inode, "01");
    }

    #[cfg(target_os = "linux")]
    fn write_tcp_table_with_state(
        proc_root: &Path,
        pid: u32,
        local: SocketAddr,
        remote: SocketAddr,
        inode: u64,
        state: &str,
    ) {
        let line = format!(
            "   0: {} {} {} 00000000:00000000 00:00000000 00000000 1000 0 {} 1 0000000000000000 100 0 0 10 0\n",
            proc_socket_addr(local),
            proc_socket_addr(remote),
            state,
            inode
        );
        let table = format!(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n{line}"
        );
        std::fs::write(proc_pid_path(proc_root, pid).join("net/tcp"), table).unwrap();
        std::fs::write(
            proc_pid_path(proc_root, pid).join("net/tcp6"),
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        )
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    fn write_empty_tcp_tables(proc_root: &Path, pid: u32) {
        let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
        std::fs::write(proc_pid_path(proc_root, pid).join("net/tcp"), header).unwrap();
        std::fs::write(proc_pid_path(proc_root, pid).join("net/tcp6"), header).unwrap();
    }

    #[cfg(target_os = "linux")]
    fn link_socket_fd(proc_root: &Path, pid: u32, fd: u32, inode: u64) {
        std::os::unix::fs::symlink(
            format!("socket:[{inode}]"),
            proc_pid_path(proc_root, pid)
                .join("fd")
                .join(fd.to_string()),
        )
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    fn socket_v4(octets: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::from(octets), port))
    }

    #[cfg(target_os = "linux")]
    fn proc_socket_addr(addr: SocketAddr) -> String {
        match addr.ip() {
            IpAddr::V4(ip) => {
                let encoded = u32::from_le_bytes(ip.octets());
                format!("{encoded:08X}:{:04X}", addr.port())
            }
            IpAddr::V6(_) => panic!("test helper only supports IPv4"),
        }
    }
}
