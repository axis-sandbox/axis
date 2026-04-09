// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! File watcher for policy hot-reload.
//!
//! Watches policy files and pushes updates to running sandboxes when
//! network or inference policies change. Filesystem and process policies
//! are immutable after sandbox creation (same as OpenShell).

use axis_core::opa::PolicyEngine;
use axis_core::policy::Policy;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// State that can be hot-reloaded in a running proxy.
pub struct ReloadableState {
    pub policy_engine: Arc<Mutex<PolicyEngine>>,
}

/// Watch a policy file and reload the OPA engine when it changes.
///
/// Returns the watcher handle — drop it to stop watching.
pub fn watch_and_reload(
    policy_path: PathBuf,
    state: ReloadableState,
) -> Result<RecommendedWatcher, notify::Error> {
    let (tx, rx) = std::sync::mpsc::channel();

    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        if let Ok(event) = res {
            let _ = tx.send(event);
        }
    })?;

    watcher.watch(&policy_path, RecursiveMode::NonRecursive)?;

    let path_clone = policy_path.clone();
    std::thread::spawn(move || {
        tracing::info!("policy watcher: watching {}", path_clone.display());

        while let Ok(event) = rx.recv() {
            // Only react to modifications and creates (editor save patterns).
            match event.kind {
                EventKind::Modify(_) | EventKind::Create(_) => {}
                _ => continue,
            }

            tracing::info!("policy watcher: file changed, reloading");

            match reload_policy(&path_clone, &state) {
                Ok(name) => {
                    tracing::info!("policy watcher: reloaded policy '{name}' successfully");
                }
                Err(e) => {
                    tracing::error!("policy watcher: reload failed: {e} (keeping old policy)");
                }
            }
        }
    });

    Ok(watcher)
}

/// Reload a policy file and update the OPA engine.
fn reload_policy(path: &Path, state: &ReloadableState) -> Result<String, String> {
    let yaml = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

    let policy = Policy::from_yaml(&yaml)
        .map_err(|e| format!("invalid policy: {e}"))?;

    let name = policy.name.clone();

    // Create a new engine with the updated policy.
    let mut new_engine = PolicyEngine::new()
        .map_err(|e| format!("OPA engine init: {e}"))?;
    new_engine
        .load_policy(&policy)
        .map_err(|e| format!("OPA policy load: {e}"))?;

    // Swap the engine atomically.
    let mut guard = state.policy_engine.lock().unwrap();
    *guard = new_engine;

    Ok(name)
}
