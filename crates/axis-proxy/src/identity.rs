// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Binary identity via SHA256 Trust-on-First-Use (TOFU) fingerprinting.
//!
//! When a process makes a network request through the proxy, we identify
//! the calling binary by resolving /proc/net/tcp → PID → /proc/[pid]/exe
//! and computing a SHA256 hash. The first time a binary is seen, its hash
//! is recorded. Subsequent requests verify the hash matches.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
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

        if let Some(expected) = self.known.get(path) {
            if *expected != hash {
                return Err(IdentityError::HashMismatch {
                    path: path.to_path_buf(),
                    expected: expected.clone(),
                    actual: hash,
                });
            }
        } else {
            tracing::info!("TOFU: first use of binary {}, hash={}", path.display(), &hash[..16]);
            self.known.insert(path.to_path_buf(), hash.clone());
        }

        Ok(BinaryFingerprint {
            path: path.to_path_buf(),
            sha256: hash,
        })
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
/// 1. Parse /proc/net/tcp to find the socket inode matching the peer's
///    source port on loopback (127.0.0.1).
/// 2. Scan /proc/*/fd/ to find the PID that owns that inode.
/// 3. readlink /proc/[pid]/exe to get the binary path.
#[cfg(target_os = "linux")]
pub fn resolve_peer_binary(peer: std::net::SocketAddr) -> Result<PathBuf, IdentityError> {
    let peer_port = peer.port();

    // Step 1: Find inode from /proc/net/tcp.
    let inode = find_socket_inode(peer_port)?;

    // Step 2: Find PID from inode.
    let pid = find_pid_for_inode(inode)?;

    // Step 3: readlink /proc/[pid]/exe.
    TofuStore::resolve_binary(pid)
}

/// Parse /proc/net/tcp to find the socket inode for a given local port.
///
/// /proc/net/tcp format (whitespace-separated):
///   sl  local_address rem_address   st tx_queue rx_queue ...  inode
///   0:  0100007F:33A4 0100007F:0CEA  01 ...                   12345
///
/// Addresses are hex: IP (little-endian) : port (big-endian).
#[cfg(target_os = "linux")]
fn find_socket_inode(port: u16) -> Result<u64, IdentityError> {
    let tcp = std::fs::read_to_string("/proc/net/tcp").map_err(|e| {
        IdentityError::ResolveFailed {
            pid: 0,
            reason: format!("cannot read /proc/net/tcp: {e}"),
        }
    })?;

    let port_hex = format!("{:04X}", port);

    for line in tcp.lines().skip(1) {
        // Skip header line.
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        let local_addr = fields[1]; // e.g. "0100007F:33A4"
        if let Some((_ip, local_port)) = local_addr.rsplit_once(':') {
            if local_port == port_hex {
                // Field 9 is the inode.
                if let Ok(inode) = fields[9].parse::<u64>() {
                    if inode != 0 {
                        return Ok(inode);
                    }
                }
            }
        }
    }

    // Also check /proc/net/tcp6 for IPv6/dual-stack sockets.
    if let Ok(tcp6) = std::fs::read_to_string("/proc/net/tcp6") {
        for line in tcp6.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            let local_addr = fields[1];
            if let Some((_ip, local_port)) = local_addr.rsplit_once(':') {
                if local_port == port_hex {
                    if let Ok(inode) = fields[9].parse::<u64>() {
                        if inode != 0 {
                            return Ok(inode);
                        }
                    }
                }
            }
        }
    }

    Err(IdentityError::ResolveFailed {
        pid: 0,
        reason: format!("no socket found for port {port}"),
    })
}

/// Scan /proc/*/fd/ to find which PID owns a socket inode.
#[cfg(target_os = "linux")]
fn find_pid_for_inode(target_inode: u64) -> Result<u32, IdentityError> {
    let target_link = format!("socket:[{target_inode}]");

    let proc_dir = std::fs::read_dir("/proc").map_err(|e| IdentityError::ResolveFailed {
        pid: 0,
        reason: format!("cannot read /proc: {e}"),
    })?;

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only look at numeric directories (PIDs).
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let fd_dir = format!("/proc/{pid}/fd");
        let fds = match std::fs::read_dir(&fd_dir) {
            Ok(d) => d,
            Err(_) => continue, // Permission denied for other users' procs.
        };

        for fd_entry in fds.flatten() {
            let link = match std::fs::read_link(fd_entry.path()) {
                Ok(l) => l,
                Err(_) => continue,
            };
            if link.to_string_lossy() == target_link {
                return Ok(pid);
            }
        }
    }

    Err(IdentityError::ResolveFailed {
        pid: 0,
        reason: format!("no process found for inode {target_inode}"),
    })
}

/// Compute SHA256 hash of a file.
fn hash_file(path: &Path) -> Result<String, IdentityError> {
    let data = std::fs::read(path)?;
    let hash = Sha256::digest(&data);
    Ok(hex::encode(hash))
}

/// Minimal hex encoding (avoids adding the `hex` crate dependency).
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

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
}
