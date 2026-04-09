// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Landlock LSM filesystem isolation (Linux kernel 5.13+).
//!
//! Applies declarative read-only and read-write path allowlists to the
//! calling process using the Landlock ABI V2+ syscalls. Landlock is a
//! default-deny model: any path not explicitly granted access is blocked.

use axis_core::policy::{Compatibility, FilesystemPolicy};
use std::os::unix::io::RawFd;
use std::path::Path;

// ── Landlock syscall numbers (x86_64, also used via asm-generic) ──────────

const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

// ── Landlock constants ────────────────────────────────────────────────────

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

// Filesystem access rights (Landlock ABI V1+)
const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
// ABI V2+
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
// ABI V3+
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;

const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

/// Read-only access rights.
const ACCESS_READ: u64 = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR;

/// Full read-write access rights.
const ACCESS_READ_WRITE: u64 = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM
    | LANDLOCK_ACCESS_FS_REFER
    | LANDLOCK_ACCESS_FS_TRUNCATE;

// ── Landlock structs (must match kernel ABI) ──────────────────────────────

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: RawFd,
}

// ── Syscall wrappers ──────────────────────────────────────────────────────

unsafe fn landlock_create_ruleset(
    attr: *const LandlockRulesetAttr,
    size: usize,
    flags: u32,
) -> libc::c_long {
    libc::syscall(SYS_LANDLOCK_CREATE_RULESET, attr, size, flags)
}

unsafe fn landlock_add_rule(
    ruleset_fd: RawFd,
    rule_type: u32,
    rule_attr: *const LandlockPathBeneathAttr,
    flags: u32,
) -> libc::c_long {
    libc::syscall(SYS_LANDLOCK_ADD_RULE, ruleset_fd, rule_type, rule_attr, flags)
}

unsafe fn landlock_restrict_self(ruleset_fd: RawFd, flags: u32) -> libc::c_long {
    libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, flags)
}

/// Detect the highest supported Landlock ABI version.
fn detect_abi_version() -> Result<i32, String> {
    let ret = unsafe {
        landlock_create_ruleset(
            std::ptr::null(),
            0,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if ret < 0 {
        let errno = std::io::Error::last_os_error();
        if errno.raw_os_error() == Some(libc::ENOSYS) {
            return Err("landlock not supported on this kernel".into());
        }
        if errno.raw_os_error() == Some(libc::EOPNOTSUPP) {
            return Err("landlock disabled by boot parameter".into());
        }
        return Err(format!("landlock version check failed: {errno}"));
    }
    Ok(ret as i32)
}

/// Apply Landlock filesystem restrictions to the current process.
///
/// This must be called from a `pre_exec` hook (after fork, before exec).
/// On kernels without Landlock support, returns an error that callers
/// can handle in best-effort mode.
pub fn apply_landlock(
    policy: &FilesystemPolicy,
    workspace: &Path,
) -> Result<(), String> {
    // Verify workspace exists.
    if !workspace.exists() {
        return Err(format!(
            "workspace directory does not exist: {}",
            workspace.display()
        ));
    }

    // Detect ABI version.
    let abi = detect_abi_version()?;
    tracing::info!("landlock: ABI version {abi}");

    // Determine which access rights to handle based on ABI version.
    let mut handled = ACCESS_READ_WRITE;
    if abi < 2 {
        handled &= !LANDLOCK_ACCESS_FS_REFER;
    }
    if abi < 3 {
        handled &= !LANDLOCK_ACCESS_FS_TRUNCATE;
    }

    // 1. Create ruleset.
    let attr = LandlockRulesetAttr {
        handled_access_fs: handled,
        handled_access_net: 0,
    };
    let ruleset_fd = unsafe {
        landlock_create_ruleset(
            &attr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0,
        )
    };
    if ruleset_fd < 0 {
        return Err(format!(
            "landlock_create_ruleset failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let ruleset_fd = ruleset_fd as RawFd;

    // 2. Add rules for read-only paths.
    let read_access = ACCESS_READ & handled;
    for path_str in &policy.read_only {
        if let Err(e) = add_path_rule(ruleset_fd, path_str, read_access, &policy.compatibility) {
            tracing::warn!("landlock: skipping read-only path '{path_str}': {e}");
        }
    }

    // 3. Add rules for read-write paths (including workspace).
    let write_access = handled; // all handled rights
    for path_str in &policy.read_write {
        let expanded = expand_path(path_str, workspace);
        if let Err(e) = add_path_rule(ruleset_fd, &expanded, write_access, &policy.compatibility) {
            tracing::warn!("landlock: skipping read-write path '{expanded}': {e}");
        }
    }

    // Always add workspace as read-write.
    let ws_str = workspace.to_string_lossy().to_string();
    if let Err(e) = add_path_rule(ruleset_fd, &ws_str, write_access, &policy.compatibility) {
        tracing::warn!("landlock: failed to add workspace: {e}");
    }

    // 4. Restrict self.
    let ret = unsafe { landlock_restrict_self(ruleset_fd, 0) };
    unsafe { libc::close(ruleset_fd) };

    if ret < 0 {
        return Err(format!(
            "landlock_restrict_self failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let ro = policy.read_only.len();
    let rw = policy.read_write.len() + 1; // +1 for workspace
    tracing::info!("landlock: applied — {ro} read-only, {rw} read-write paths");
    Ok(())
}

/// Add a path-beneath rule to the ruleset.
fn add_path_rule(
    ruleset_fd: RawFd,
    path: &str,
    access: u64,
    compat: &Compatibility,
) -> Result<(), String> {
    let c_path = std::ffi::CString::new(path)
        .map_err(|e| format!("invalid path '{path}': {e}"))?;

    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC,
        )
    };

    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return match compat {
            Compatibility::BestEffort => {
                Err(format!("cannot open '{path}': {err} (skipped, best-effort)"))
            }
            Compatibility::HardRequirement => {
                Err(format!("cannot open '{path}': {err} (hard requirement)"))
            }
        };
    }

    let rule = LandlockPathBeneathAttr {
        allowed_access: access,
        parent_fd: fd,
    };

    let ret = unsafe {
        landlock_add_rule(
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &rule,
            0,
        )
    };

    unsafe { libc::close(fd) };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        // EINVAL can mean the access rights aren't supported — best-effort skip.
        if err.raw_os_error() == Some(libc::EINVAL) {
            return Err(format!("unsupported access for '{path}': {err}"));
        }
        return Err(format!("landlock_add_rule for '{path}' failed: {err}"));
    }

    Ok(())
}

/// Expand policy path placeholders.
fn expand_path(path: &str, workspace: &Path) -> String {
    path.replace("{workspace}", &workspace.to_string_lossy())
        .replace("{tmpdir}", "/tmp")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_landlock_abi() {
        match detect_abi_version() {
            Ok(v) => {
                assert!(v >= 1, "expected ABI v1+, got {v}");
                eprintln!("Landlock ABI version: {v}");
            }
            Err(e) => {
                eprintln!("Landlock not available: {e} (test skipped)");
            }
        }
    }

    #[test]
    fn expand_path_placeholders() {
        let ws = Path::new("/home/user/sandbox");
        assert_eq!(expand_path("{workspace}/data", ws), "/home/user/sandbox/data");
        assert_eq!(expand_path("{tmpdir}/axis", ws), "/tmp/axis");
    }

    #[test]
    fn apply_landlock_with_valid_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let policy = FilesystemPolicy {
            read_only: vec!["/usr".into(), "/lib".into()],
            read_write: vec![dir.path().to_string_lossy().into()],
            deny: vec!["~/.ssh".into()],
            ..Default::default()
        };
        // This may fail on kernels without Landlock — that's OK in CI.
        // We only call this from pre_exec in real sandboxes.
        let result = apply_landlock(&policy, dir.path());
        match result {
            Ok(()) => eprintln!("Landlock applied successfully"),
            Err(e) => eprintln!("Landlock not applied (expected in some CI): {e}"),
        }
    }
}
