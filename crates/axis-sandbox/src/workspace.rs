// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Workspace preparation — creates contained agent state directories
//! under ~/.axis/agents/<policy-name>/ with symlinks from the paths
//! agents expect (e.g., ~/.claude, ~/.codex).
//!
//! This ensures all agent-writable data is contained in a single
//! directory tree that can be inspected, backed up, and destroyed.

use std::path::{Component, Path, PathBuf};

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
];

/// Paths that should NEVER be symlinked — too large or contain circular links.
const NEVER_SYMLINK: &[&str] = &[
    "Library", // macOS ~/Library is huge and has circular revlinks
    ".local",  // Too broad — contains many unrelated things
    "AppData", // Windows equivalent of ~/Library
    "Documents",
    "Desktop",
    "Downloads",
];

/// Prepare the agent workspace: create ~/.axis/agents/<name>/ and symlink
/// agent-expected directories to it.
///
/// Returns the list of (symlink_path, target_path) pairs that were created.
pub fn prepare_agent_workspace(
    policy_name: &str,
    read_write_paths: &[String],
) -> Result<Vec<(PathBuf, PathBuf)>, String> {
    let home = user_home()?;

    let agent_root = agent_state_root_checked(policy_name)?;

    let mut symlinks = Vec::new();

    for rw_path in read_write_paths {
        let Some((symlink_path, contained_dir)) =
            agent_state_mapping_for_policy_path_with_home(rw_path, &home, &agent_root)?
        else {
            continue;
        };

        // Create the contained directory.
        std::fs::create_dir_all(&contained_dir)
            .map_err(|e| format!("cannot create {}: {e}", contained_dir.display()))?;

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
                if contained_dir
                    .read_dir()
                    .map(|mut d| d.next().is_none())
                    .unwrap_or(true)
                {
                    // Copy contents recursively.
                    copy_dir_contents(&symlink_path, &contained_dir)?;
                }
                // Rename original to .bak, then create symlink.
                let relative = symlink_path.strip_prefix(&home).unwrap_or(&symlink_path);
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
            std::os::unix::fs::symlink(&contained_dir, &symlink_path).map_err(|e| {
                format!(
                    "symlink {} -> {}: {e}",
                    symlink_path.display(),
                    contained_dir.display()
                )
            })?;
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_dir(&contained_dir, &symlink_path).map_err(|e| {
                format!(
                    "symlink {} -> {}: {e}",
                    symlink_path.display(),
                    contained_dir.display()
                )
            })?;
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

fn contained_agent_dir_for_relative(relative: &Path, agent_root: &Path) -> Option<PathBuf> {
    AGENT_DIR_MAPPINGS
        .iter()
        .find(|(expected, _)| relative == Path::new(expected))
        .map(|(_, contained)| agent_root.join(contained))
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
    agent_state_root_checked(policy_name).unwrap_or_else(|_| {
        user_home()
            .unwrap_or_else(|_| PathBuf::from("/tmp"))
            .join(".axis")
            .join("agents")
            .join("invalid-policy-name")
    })
}

/// Get the scoped SSH directory for a policy.
pub fn ssh_workspace_path(policy_name: &str) -> PathBuf {
    agent_state_root(policy_name).join("ssh")
}

/// Create ~/.ssh as a symlink to the scoped SSH directory.
///
/// This refuses to replace any existing ~/.ssh path, including an existing
/// symlink, because doing so could hide or disturb the user's real SSH state.
pub fn link_scoped_ssh_workspace(ssh_dir: &Path) -> Result<(PathBuf, PathBuf), String> {
    let home = user_home()?;
    let ssh_link = home.join(".ssh");
    if ssh_link.exists() || ssh_link.is_symlink() {
        return Err(format!(
            "refusing to replace existing ~/.ssh at {}",
            ssh_link.display()
        ));
    }
    std::fs::create_dir_all(ssh_dir).map_err(|e| format!("create ssh dir: {e}"))?;

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(ssh_dir, &ssh_link).map_err(|e| {
            format!(
                "symlink {} -> {}: {e}",
                ssh_link.display(),
                ssh_dir.display()
            )
        })?;
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_dir(ssh_dir, &ssh_link).map_err(|e| {
            format!(
                "symlink {} -> {}: {e}",
                ssh_link.display(),
                ssh_dir.display()
            )
        })?;
    }

    Ok((ssh_link, ssh_dir.to_path_buf()))
}

pub(crate) fn expand_home_or_absolute_path(path: &str) -> Result<Option<PathBuf>, String> {
    let home = user_home()?;
    expand_home_or_absolute_path_with_home(path, &home)
}

pub(crate) fn scoped_ssh_link_path() -> Result<PathBuf, String> {
    Ok(user_home()?.join(".ssh"))
}

pub(crate) fn agent_state_mapping_for_policy_path(
    policy_name: &str,
    path: &str,
) -> Result<Option<(PathBuf, PathBuf)>, String> {
    let home = user_home()?;
    let agent_root = agent_state_root_checked(policy_name)?;
    agent_state_mapping_for_policy_path_with_home(path, &home, &agent_root)
}

pub(crate) fn scoped_ssh_link_points_to(ssh_dir: &Path) -> Result<bool, String> {
    let home = user_home()?;
    let ssh_link = home.join(".ssh");
    if !ssh_link.is_symlink() {
        return Ok(false);
    }
    let target = std::fs::read_link(&ssh_link)
        .map_err(|e| format!("read scoped SSH symlink '{}': {e}", ssh_link.display()))?;
    let target = if target.is_absolute() {
        target
    } else {
        ssh_link
            .parent()
            .unwrap_or_else(|| Path::new(std::path::MAIN_SEPARATOR_STR))
            .join(target)
    };
    Ok(normalize_path(target) == normalize_path(ssh_dir.to_path_buf()))
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
    prepare_ssh_workspace_with_permissions(policy_name, ssh_policy, set_private_permissions)
}

fn prepare_ssh_workspace_with_permissions<F>(
    policy_name: &str,
    ssh_policy: &axis_core::policy::SshPolicy,
    mut set_permissions: F,
) -> Result<Option<PathBuf>, String>
where
    F: FnMut(&Path, u32) -> Result<(), String>,
{
    if ssh_policy.allowed_keys.is_empty() {
        return Ok(None);
    }

    let home = user_home()?;

    let ssh_dir = agent_state_root_checked(policy_name)?.join("ssh");
    std::fs::create_dir_all(&ssh_dir).map_err(|e| format!("create ssh dir: {e}"))?;

    set_permissions(&ssh_dir, 0o700)?;

    // Copy each allowed key.
    let mut config_entries = Vec::new();
    for key_spec in &ssh_policy.allowed_keys {
        let src_path = expand_home_or_absolute_path_with_home(&key_spec.private_key, &home)?
            .ok_or_else(|| {
                format!(
                    "ssh: key '{}' path must be absolute or start with ~/; got {}",
                    key_spec.name, key_spec.private_key
                )
            })?;

        if !src_path.exists() {
            tracing::warn!(
                "ssh: key '{}' not found at {}",
                key_spec.name,
                src_path.display()
            );
            continue;
        }

        // Copy private key to sandbox ssh dir.
        let key_filename = src_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| format!("key_{}", key_spec.name));

        let dst_path = ssh_dir.join(&key_filename);
        std::fs::copy(&src_path, &dst_path)
            .map_err(|e| format!("copy key '{}': {e}", key_spec.name))?;

        if let Err(err) = set_permissions(&dst_path, 0o600) {
            let _ = std::fs::remove_file(&dst_path);
            return Err(err);
        }

        // Copy public key too if it exists.
        let pub_src = PathBuf::from(format!("{}.pub", src_path.display()));
        if pub_src.exists() {
            let pub_dst = ssh_dir.join(format!("{key_filename}.pub"));
            let _ = std::fs::copy(&pub_src, &pub_dst);
        }

        tracing::info!(
            "ssh: exposed key '{}' for hosts {:?}",
            key_spec.name,
            key_spec.allowed_hosts
        );

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
        let mut all_hosts: Vec<String> = ssh_policy
            .allowed_keys
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

            if let Ok(output) = output
                && output.status.success()
            {
                std::fs::write(ssh_dir.join("known_hosts"), &output.stdout)
                    .map_err(|e| format!("write known_hosts: {e}"))?;
                tracing::info!("ssh: generated known_hosts for {} hosts", all_hosts.len());
            }
        }
    }

    // Create marker file.
    std::fs::write(
        ssh_dir.join(".axis-managed"),
        "This SSH directory is managed by AXIS.\n",
    )
    .ok();

    Ok(Some(ssh_dir))
}

#[cfg(unix)]
fn set_private_permissions(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("set permissions {mode:o} on '{}': {e}", path.display()))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

fn user_home() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var_os("USERPROFILE").filter(|value| !value.is_empty()))
        .map(PathBuf::from)
        .ok_or_else(|| "cannot determine HOME directory".to_string())?;
    if !home.is_absolute() {
        return Err(format!(
            "HOME directory is not absolute: {}",
            home.display()
        ));
    }
    Ok(normalize_path(home))
}

fn agent_state_root_checked(policy_name: &str) -> Result<PathBuf, String> {
    validate_policy_name_component(policy_name)?;
    Ok(user_home()?.join(".axis").join("agents").join(policy_name))
}

fn validate_policy_name_component(policy_name: &str) -> Result<(), String> {
    axis_core::policy::validate_policy_name_component(policy_name).map_err(|err| err.to_string())
}

fn expand_home_or_absolute_path_with_home(
    path: &str,
    home: &Path,
) -> Result<Option<PathBuf>, String> {
    let expanded = if path == "~" {
        home.to_path_buf()
    } else if let Some(rest) = path.strip_prefix("~/") {
        home.join(rest)
    } else if path.starts_with('~') {
        return Err(format!(
            "unsupported home path '{path}': only '~' and '~/' are supported"
        ));
    } else {
        let path = PathBuf::from(path);
        if path.is_absolute() {
            path
        } else {
            return Ok(None);
        }
    };

    Ok(Some(normalize_path(expanded)))
}

fn agent_state_mapping_for_policy_path_with_home(
    path: &str,
    home: &Path,
    agent_root: &Path,
) -> Result<Option<(PathBuf, PathBuf)>, String> {
    let Some(expanded) = expand_home_or_absolute_path_with_home(path, home)? else {
        return Ok(None);
    };

    // Skip non-home paths (workspace, tmpdir, etc.).
    if !expanded.starts_with(home) {
        return Ok(None);
    }

    // Never symlink ~/.axis itself (that's the containment root).
    if expanded == home.join(".axis") || expanded.starts_with(home.join(".axis")) {
        return Ok(None);
    }

    // Never symlink large/dangerous directories.
    let rel_check = expanded.strip_prefix(home).unwrap_or(&expanded);
    if NEVER_SYMLINK
        .iter()
        .any(|&blocked| rel_check == Path::new(blocked) || rel_check.starts_with(blocked))
    {
        return Ok(None);
    }

    let relative = match expanded.strip_prefix(home) {
        Ok(relative) => relative.to_path_buf(),
        Err(_) => return Ok(None),
    };
    let Some(contained_dir) = contained_agent_dir_for_relative(&relative, agent_root) else {
        return Ok(None);
    };

    Ok(Some((home.join(relative), contained_dir)))
}

fn normalize_path(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

fn copy_dir_contents(src: &Path, dst: &Path) -> Result<(), String> {
    let entries = std::fs::read_dir(src).map_err(|e| format!("read {}: {e}", src.display()))?;
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
    use axis_core::policy::{SshKeySpec, SshPolicy};
    use std::ffi::OsString;
    use std::sync::{Mutex, OnceLock};

    #[test]
    fn agent_state_root_is_under_home() {
        let root = agent_state_root("test-policy");
        let root_str = root.to_string_lossy().replace('\\', "/");
        assert!(
            root_str.contains(".axis/agents/test-policy"),
            "expected .axis/agents/test-policy in {root_str}"
        );
    }

    #[test]
    fn mapping_covers_known_agents() {
        let agents = [
            "claude", "codex", "openclaw", "ironclaw", "hermes", "config",
        ];
        for agent in agents {
            assert!(
                AGENT_DIR_MAPPINGS.iter().any(|(_, name)| *name == agent),
                "missing mapping for {agent}"
            );
        }
    }

    #[test]
    fn only_known_agent_state_paths_are_contained() {
        let agent_root = Path::new("/home/user/.axis/agents/test");

        assert_eq!(
            contained_agent_dir_for_relative(Path::new(".codex"), agent_root),
            Some(agent_root.join("codex"))
        );
        assert_eq!(
            contained_agent_dir_for_relative(Path::new(".config"), agent_root),
            Some(agent_root.join("config"))
        );
        assert_eq!(
            contained_agent_dir_for_relative(Path::new("fixture/project"), agent_root),
            None
        );
    }

    #[test]
    fn workspace_preparation_rejects_unsafe_policy_names() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            for name in [
                ".",
                "..",
                "../escape",
                "/absolute",
                "nested/name",
                "nested\\name",
            ] {
                let err = prepare_agent_workspace(name, &["~/.codex".into()]).unwrap_err();
                assert!(
                    err.contains("policy name"),
                    "expected policy name error for {name:?}, got {err}"
                );
                let mapping_err =
                    agent_state_mapping_for_policy_path(name, "~/.codex").unwrap_err();
                assert!(
                    mapping_err.contains("policy name"),
                    "expected mapping policy name error for {name:?}, got {mapping_err}"
                );
            }
        });
    }

    #[test]
    fn ssh_workspace_preparation_rejects_unsafe_policy_names() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let ssh_policy = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: "/tmp/nonexistent-key".into(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            for name in ["../escape", "/absolute", "nested/name"] {
                let err = prepare_ssh_workspace(name, &ssh_policy).unwrap_err();
                assert!(
                    err.contains("policy name"),
                    "expected policy name error for {name:?}, got {err}"
                );
            }
        });
    }

    #[test]
    fn ssh_workspace_preparation_fails_when_directory_permissions_cannot_be_hardened() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let ssh_policy = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: "/tmp/nonexistent-key".into(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            let err =
                prepare_ssh_workspace_with_permissions("agent-ssh", &ssh_policy, |_path, mode| {
                    Err(format!("permission hook failed for {mode:o}"))
                })
                .unwrap_err();

            assert!(err.contains("permission hook failed for 700"));
        });
    }

    #[test]
    fn ssh_workspace_preparation_fails_and_removes_key_when_key_permissions_cannot_be_hardened() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let key_path = home.path().join("id_ed25519");
            std::fs::write(&key_path, "private-key").unwrap();
            let ssh_policy = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: key_path.to_string_lossy().into_owned(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            let err =
                prepare_ssh_workspace_with_permissions("agent-ssh", &ssh_policy, |_path, mode| {
                    if mode == 0o600 {
                        Err("key permission hook failed".into())
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();

            assert!(err.contains("key permission hook failed"));
            assert!(
                !home
                    .path()
                    .join(".axis/agents/agent-ssh/ssh/id_ed25519")
                    .exists(),
                "copied private key should be removed after chmod failure"
            );
        });
    }

    fn with_home<T>(home: &Path, f: impl FnOnce() -> T) -> T {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();

        struct EnvGuard {
            home: Option<OsString>,
        }

        impl Drop for EnvGuard {
            fn drop(&mut self) {
                unsafe {
                    match &self.home {
                        Some(value) => std::env::set_var("HOME", value),
                        None => std::env::remove_var("HOME"),
                    }
                }
            }
        }

        let previous = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", home);
        }
        let _env_guard = EnvGuard { home: previous };

        f()
    }
}
