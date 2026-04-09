// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Seatbelt profile generation from AXIS policy.
//!
//! Generates an Apple Sandbox Profile Language (.sb) file that enforces
//! the AXIS policy using macOS kernel-level sandboxing.

use axis_core::policy::Policy;
use std::path::Path;

/// Generate a Seatbelt profile string from an AXIS policy.
pub fn generate_profile(policy: &Policy, workspace: &Path) -> String {
    let mut sb = String::new();

    sb.push_str("(version 1)\n");
    sb.push_str("\n;; AXIS sandbox profile — auto-generated\n");
    sb.push_str(&format!(";; Policy: {}\n\n", policy.name));

    // Default deny everything.
    sb.push_str("(deny default)\n\n");

    // ── Process execution ──
    sb.push_str(";; Allow process execution\n");
    sb.push_str("(allow process-exec)\n");
    sb.push_str("(allow process-fork)\n");
    sb.push_str("(allow signal (target self))\n\n");

    // ── Filesystem: read-only paths ──
    sb.push_str(";; Filesystem: read-only paths\n");
    for path in &policy.filesystem.read_only {
        let expanded = expand_path(path, workspace);
        sb.push_str(&format!(
            "(allow file-read* (subpath \"{expanded}\"))\n"
        ));
    }

    // Standard system paths always readable.
    for path in &["/usr", "/System", "/Library", "/bin", "/sbin",
                  "/private/var/db", "/dev/null", "/dev/urandom", "/dev/random"] {
        sb.push_str(&format!("(allow file-read* (subpath \"{path}\"))\n"));
    }
    sb.push('\n');

    // ── Filesystem: read-write paths ──
    sb.push_str(";; Filesystem: read-write (workspace)\n");
    let ws = workspace.to_string_lossy();
    sb.push_str(&format!("(allow file-read* file-write* (subpath \"{ws}\"))\n"));
    for path in &policy.filesystem.read_write {
        let expanded = expand_path(path, workspace);
        if expanded != ws.as_ref() {
            sb.push_str(&format!(
                "(allow file-read* file-write* (subpath \"{expanded}\"))\n"
            ));
        }
    }
    sb.push('\n');

    // ── Filesystem: deny paths ──
    if !policy.filesystem.deny.is_empty() {
        sb.push_str(";; Filesystem: explicit deny\n");
        for path in &policy.filesystem.deny {
            let expanded = expand_path(path, workspace);
            sb.push_str(&format!(
                "(deny file-read* file-write* (subpath \"{expanded}\"))\n"
            ));
        }
        sb.push('\n');
    }

    // ── Network ──
    sb.push_str(";; Network\n");
    match policy.network.mode {
        axis_core::policy::NetworkMode::Block => {
            sb.push_str("(deny network*)\n");
        }
        axis_core::policy::NetworkMode::Allow => {
            sb.push_str("(allow network*)\n");
        }
        axis_core::policy::NetworkMode::Proxy => {
            // Allow only loopback connections (to the proxy).
            sb.push_str("(allow network* (remote ip \"localhost:*\"))\n");
            sb.push_str("(deny network* (remote ip \"*:*\"))\n");
        }
    }
    sb.push('\n');

    // ── Misc permissions needed for normal operation ──
    sb.push_str(";; Required for normal operation\n");
    sb.push_str("(allow sysctl-read)\n");
    sb.push_str("(allow mach-lookup)\n");
    sb.push_str("(allow ipc-posix-shm-read-data)\n");
    sb.push_str("(allow ipc-posix-shm-write-data)\n");
    sb.push_str("(allow file-read-metadata)\n");
    sb.push('\n');

    // ── Deny dangerous operations ──
    sb.push_str(";; Security: deny dangerous operations\n");
    sb.push_str("(deny file-write* (subpath \"/System\"))\n");
    sb.push_str("(deny file-write* (subpath \"/usr\"))\n");
    sb.push_str("(deny file-write* (subpath \"/Library\"))\n");
    sb.push_str("(deny process-info* (target others))\n");
    sb.push_str("(deny system-privilege)\n");

    sb
}

fn expand_path(path: &str, workspace: &Path) -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/unknown".into());
    path.replace("{workspace}", &workspace.to_string_lossy())
        .replace("{tmpdir}", "/tmp")
        .replace("~", &home)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axis_core::policy::Policy;

    #[test]
    fn generates_valid_profile() {
        let policy = Policy::from_yaml("version: 1\nname: test\n").unwrap();
        let profile = generate_profile(&policy, Path::new("/tmp/workspace"));
        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("/tmp/workspace"));
        assert!(profile.contains("(allow process-exec)"));
    }

    #[test]
    fn proxy_mode_allows_loopback_only() {
        let yaml = "version: 1\nname: test\nnetwork:\n  mode: proxy\n";
        let policy = Policy::from_yaml(yaml).unwrap();
        let profile = generate_profile(&policy, Path::new("/tmp/ws"));
        assert!(profile.contains("localhost"));
        assert!(profile.contains("(deny network*"));
    }

    #[test]
    fn block_mode_denies_all_network() {
        let yaml = "version: 1\nname: test\nnetwork:\n  mode: block\n";
        let policy = Policy::from_yaml(yaml).unwrap();
        let profile = generate_profile(&policy, Path::new("/tmp/ws"));
        assert!(profile.contains("(deny network*)"));
    }
}
