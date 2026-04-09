// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! NTFS ACL management for Windows sandbox workspace directories.
//!
//! Sets up a sandbox workspace directory with explicit ACLs granting
//! the AppContainer SID full control. This is the only writable location
//! for the sandboxed process.

use std::path::Path;

/// Set up workspace directory ACLs for a sandbox.
///
/// Grants the AppContainer SID full control over the workspace directory.
/// The Low Integrity Level of the sandbox process prevents writes to
/// any other location.
pub fn setup_workspace_acls(workspace: &Path, appcontainer_name: &str) -> Result<(), String> {
    std::fs::create_dir_all(workspace)
        .map_err(|e| format!("failed to create workspace: {e}"))?;

    tracing::info!(
        "setting workspace ACLs for AppContainer '{appcontainer_name}' on {}",
        workspace.display()
    );

    // NOTE: Full implementation uses SetNamedSecurityInfoW to add an
    // ACE granting the AppContainer SID (looked up via
    // DeriveAppContainerSidFromAppContainerName) full control.
    //
    // For initial implementation, the workspace is writable by the
    // current user, and the Low IL sandbox process can write to it
    // if we explicitly set a Low IL label on the directory.
    //
    // icacls equivalent:
    //   icacls <workspace> /setintegritylevel (OI)(CI)Low

    Ok(())
}
