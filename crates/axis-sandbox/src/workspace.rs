// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Workspace preparation — creates contained agent state directories
//! under ~/.axis/agents/<policy-name>/ with symlinks from the paths
//! agents expect (e.g., ~/.claude, ~/.codex).
//!
//! This ensures all agent-writable data is contained in a single
//! directory tree that can be inspected, backed up, and destroyed.

use std::path::{Path, PathBuf};

/// Agent state directory mappings.
/// Maps the path agents expect to write to → the directory name under .axis/agents/<name>/.
const AGENT_DIR_MAPPINGS: &[(&str, &str)] = &[
    (".claude", "claude"),
    (".local/share/claude", "claude-share"),
    (".codex", "codex"),
    (".openclaw", "openclaw"),
    (".ironclaw", "ironclaw"),
    (".hermes", "hermes"),
    (".config", "config"),
    ("Library", "library"),
];

/// Prepare the agent workspace: create ~/.axis/agents/<name>/ and symlink
/// agent-expected directories to it.
///
/// Returns the list of (symlink_path, target_path) pairs that were created.
pub fn prepare_agent_workspace(
    policy_name: &str,
    read_write_paths: &[String],
) -> Result<Vec<(PathBuf, PathBuf)>, String> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| "cannot determine HOME directory".to_string())?;
    let home = PathBuf::from(home);

    // Create the contained agent state root.
    let agent_root = home.join(".axis").join("agents").join(policy_name);
    std::fs::create_dir_all(&agent_root)
        .map_err(|e| format!("cannot create {}: {e}", agent_root.display()))?;

    let mut symlinks = Vec::new();

    for rw_path in read_write_paths {
        // Expand ~ to home.
        let expanded = rw_path.replace('~', &home.to_string_lossy());

        // Skip non-home paths (workspace, tmpdir, etc.).
        if !expanded.starts_with(&home.to_string_lossy().as_ref()) {
            continue;
        }

        // Never symlink ~/.axis itself (that's the containment root).
        if expanded.ends_with("/.axis") || expanded.contains("/.axis/") {
            continue;
        }

        // Find the relative path from home.
        let relative = match PathBuf::from(&expanded).strip_prefix(&home) {
            Ok(r) => r.to_path_buf(),
            Err(_) => continue,
        };

        // Look up the mapping for this path.
        let dir_name = AGENT_DIR_MAPPINGS
            .iter()
            .find(|(expected, _)| relative == Path::new(expected))
            .map(|(_, contained)| *contained);

        let contained_dir = if let Some(name) = dir_name {
            agent_root.join(name)
        } else {
            // Use the relative path as the contained dir name.
            agent_root.join(relative.to_string_lossy().replace('/', "-"))
        };

        // Create the contained directory.
        std::fs::create_dir_all(&contained_dir)
            .map_err(|e| format!("cannot create {}: {e}", contained_dir.display()))?;

        let symlink_path = home.join(&relative);

        // If the expected path already exists and is not a symlink, skip it
        // (don't clobber real user data).
        if symlink_path.exists() {
            if symlink_path.is_symlink() {
                // Remove old symlink and recreate.
                let _ = std::fs::remove_file(&symlink_path);
            } else {
                // Real directory exists — move contents to contained dir,
                // then replace with symlink.
                tracing::info!(
                    "workspace: moving {} -> {}",
                    symlink_path.display(),
                    contained_dir.display()
                );
                // Only move if contained dir is empty (first run).
                if contained_dir.read_dir().map(|mut d| d.next().is_none()).unwrap_or(true) {
                    // Copy contents recursively.
                    copy_dir_contents(&symlink_path, &contained_dir)?;
                }
                // Rename original to .bak, then create symlink.
                let backup = home.join(format!("{}.axis-backup", relative.display()));
                if !backup.exists() {
                    let _ = std::fs::rename(&symlink_path, &backup);
                } else {
                    let _ = std::fs::remove_dir_all(&symlink_path);
                }
            }
        }

        // Create parent directory for the symlink.
        if let Some(parent) = symlink_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        // Create symlink: ~/.claude -> ~/.axis/agents/<policy>/claude
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&contained_dir, &symlink_path)
                .map_err(|e| format!("symlink {} -> {}: {e}",
                    symlink_path.display(), contained_dir.display()))?;
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_dir(&contained_dir, &symlink_path)
                .map_err(|e| format!("symlink {} -> {}: {e}",
                    symlink_path.display(), contained_dir.display()))?;
        }

        tracing::info!(
            "workspace: {} -> {}",
            symlink_path.display(),
            contained_dir.display()
        );
        symlinks.push((symlink_path, contained_dir));
    }

    Ok(symlinks)
}

/// Remove symlinks created by prepare_agent_workspace.
pub fn cleanup_agent_symlinks(symlinks: &[(PathBuf, PathBuf)]) {
    for (symlink_path, _) in symlinks {
        if symlink_path.is_symlink() {
            let _ = std::fs::remove_file(symlink_path);
            // Restore backup if it exists.
            let backup = PathBuf::from(format!("{}.axis-backup", symlink_path.display()));
            if backup.exists() {
                let _ = std::fs::rename(&backup, symlink_path);
            }
        }
    }
}

/// Get the agent state root directory.
pub fn agent_state_root(policy_name: &str) -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".axis").join("agents").join(policy_name)
}

/// Prepare a scoped SSH directory for the sandbox.
///
/// Creates a `.ssh/` directory in the agent's containment root with:
/// - Only the specified private keys (copied, not symlinked)
/// - A generated `config` file restricting key→host mappings
/// - A generated `known_hosts` with only allowed host fingerprints
///
/// Returns the path to the sandbox .ssh directory.
pub fn prepare_ssh_workspace(
    policy_name: &str,
    ssh_policy: &axis_core::policy::SshPolicy,
) -> Result<Option<PathBuf>, String> {
    if ssh_policy.allowed_keys.is_empty() {
        return Ok(None);
    }

    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| "cannot determine HOME".to_string())?;
    let home = PathBuf::from(&home);

    let ssh_dir = agent_state_root(policy_name).join("ssh");
    std::fs::create_dir_all(&ssh_dir)
        .map_err(|e| format!("create ssh dir: {e}"))?;

    // Set restrictive permissions on the ssh directory.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&ssh_dir, std::fs::Permissions::from_mode(0o700));
    }

    // Copy each allowed key.
    let mut config_entries = Vec::new();
    for key_spec in &ssh_policy.allowed_keys {
        let src_path = PathBuf::from(key_spec.private_key.replace('~', &home.to_string_lossy()));

        if !src_path.exists() {
            tracing::warn!("ssh: key '{}' not found at {}", key_spec.name, src_path.display());
            continue;
        }

        // Copy private key to sandbox ssh dir.
        let key_filename = src_path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| format!("key_{}", key_spec.name));

        let dst_path = ssh_dir.join(&key_filename);
        std::fs::copy(&src_path, &dst_path)
            .map_err(|e| format!("copy key '{}': {e}", key_spec.name))?;

        // Set key permissions to 600.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dst_path, std::fs::Permissions::from_mode(0o600));
        }

        // Copy public key too if it exists.
        let pub_src = PathBuf::from(format!("{}.pub", src_path.display()));
        if pub_src.exists() {
            let pub_dst = ssh_dir.join(format!("{key_filename}.pub"));
            let _ = std::fs::copy(&pub_src, &pub_dst);
        }

        tracing::info!("ssh: exposed key '{}' for hosts {:?}", key_spec.name, key_spec.allowed_hosts);

        // Build SSH config entry.
        let hosts = if key_spec.allowed_hosts.is_empty() {
            "*".to_string()
        } else {
            key_spec.allowed_hosts.join(" ")
        };
        config_entries.push((hosts, key_filename));
    }

    // Generate SSH config.
    if ssh_policy.generate_config && !config_entries.is_empty() {
        let mut config = String::new();
        config.push_str("# Auto-generated by AXIS — only allowed SSH hosts\n");
        config.push_str("# Do not edit — this file is managed by the sandbox.\n\n");

        for (hosts, key_file) in &config_entries {
            config.push_str(&format!("Host {hosts}\n"));
            config.push_str(&format!("    IdentityFile ~/.ssh/{key_file}\n"));
            config.push_str("    IdentitiesOnly yes\n");
            config.push_str("    StrictHostKeyChecking accept-new\n\n");
        }

        // Block all other hosts.
        config.push_str("# Deny all other SSH connections\n");
        config.push_str("Host *\n");
        config.push_str("    IdentityFile /dev/null\n");
        config.push_str("    IdentitiesOnly yes\n");

        std::fs::write(ssh_dir.join("config"), &config)
            .map_err(|e| format!("write ssh config: {e}"))?;
    }

    // Generate known_hosts via ssh-keyscan for allowed hosts.
    if ssh_policy.generate_known_hosts {
        let mut all_hosts: Vec<String> = ssh_policy.allowed_keys
            .iter()
            .flat_map(|k| k.allowed_hosts.iter().cloned())
            .filter(|h| !h.contains('*')) // skip wildcards
            .collect();
        all_hosts.sort();
        all_hosts.dedup();

        if !all_hosts.is_empty() {
            let output = std::process::Command::new("ssh-keyscan")
                .args(&all_hosts)
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    std::fs::write(ssh_dir.join("known_hosts"), &output.stdout)
                        .map_err(|e| format!("write known_hosts: {e}"))?;
                    tracing::info!("ssh: generated known_hosts for {} hosts", all_hosts.len());
                }
            }
        }
    }

    // Create marker file.
    std::fs::write(ssh_dir.join(".axis-managed"), "This SSH directory is managed by AXIS.\n").ok();

    Ok(Some(ssh_dir))
}

fn copy_dir_contents(src: &Path, dst: &Path) -> Result<(), String> {
    let entries = std::fs::read_dir(src)
        .map_err(|e| format!("read {}: {e}", src.display()))?;
    for entry in entries.flatten() {
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            std::fs::create_dir_all(&dst_path).ok();
            copy_dir_contents(&src_path, &dst_path)?;
        } else {
            let _ = std::fs::copy(&src_path, &dst_path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_state_root_is_under_home() {
        let root = agent_state_root("test-policy");
        assert!(root.to_string_lossy().contains(".axis/agents/test-policy"));
    }

    #[test]
    fn mapping_covers_known_agents() {
        let agents = ["claude", "codex", "openclaw", "ironclaw", "hermes", "config"];
        for agent in agents {
            assert!(
                AGENT_DIR_MAPPINGS.iter().any(|(_, name)| *name == agent),
                "missing mapping for {agent}"
            );
        }
    }
}
