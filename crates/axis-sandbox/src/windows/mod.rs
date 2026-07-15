// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Windows containment targets and fail-closed native launcher.
//!
//! The supporting modules contain work toward Job Object, AppContainer,
//! restricted-token, ACL, and ETW integration. The native launcher remains
//! disabled until those controls, proxy routing, and environment isolation can
//! be applied to the initial process before it executes user code.

pub mod acl;
pub mod appcontainer;
pub mod etw;
pub mod job_object;
pub mod restricted;

use crate::sandbox::{SandboxConfig, SandboxError, SandboxImpl};

const NATIVE_CONTAINMENT_UNAVAILABLE: &str = "native Windows process containment is unavailable: the launcher cannot yet apply Job Object, restricted-token/AppContainer, filesystem ACL, proxy, and environment isolation before process creation";

fn containment_unavailable() -> SandboxError {
    SandboxError::Unsupported(NATIVE_CONTAINMENT_UNAVAILABLE.into())
}

pub(crate) fn ensure_containment_available() -> Result<(), SandboxError> {
    Err(containment_unavailable())
}

/// Disabled native Windows backend.
///
/// This type retains the platform trait boundary while ensuring no ordinary
/// process launch can bypass the incomplete containment path.
pub(crate) struct WindowsSandbox;

impl WindowsSandbox {
    pub fn new(_config: &SandboxConfig) -> Result<Self, SandboxError> {
        ensure_containment_available()?;
        Ok(Self)
    }
}

impl SandboxImpl for WindowsSandbox {
    fn start(&mut self) -> Result<u32, SandboxError> {
        Err(containment_unavailable())
    }

    fn wait(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<i32, SandboxError>> + Send + '_>>
    {
        Box::pin(async { Err(containment_unavailable()) })
    }

    fn try_wait(&mut self) -> Result<Option<i32>, SandboxError> {
        Ok(None)
    }

    fn destroy(&mut self) -> Result<(), SandboxError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axis_core::policy::Policy;
    use axis_core::types::SandboxId;

    fn test_config(workspace_dir: std::path::PathBuf) -> SandboxConfig {
        SandboxConfig {
            id: SandboxId::new(),
            policy: Policy::from_yaml("version: 1\nname: windows-fail-closed\n").unwrap(),
            command: "cmd.exe".into(),
            args: vec!["/c".into(), "exit 0".into()],
            working_dir: None,
            workspace_dir,
            env: Vec::new(),
            proxy_port: 0,
            proxy_addr: None,
            connect_attribution: None,
            capture_output: false,
            interactive_terminal: false,
            pty_bridge_helper: None,
            timeout_sec: None,
            backend_preflight: Default::default(),
            startup_trace: None,
        }
    }

    #[test]
    fn native_launcher_rejects_before_workspace_or_process_setup() {
        let parent = tempfile::tempdir().unwrap();
        let workspace = parent.path().join("workspace");
        let config = test_config(workspace.clone());

        let err = match WindowsSandbox::new(&config) {
            Ok(_) => panic!("native Windows containment must remain disabled"),
            Err(err) => err,
        };

        assert!(matches!(err, SandboxError::Unsupported(_)));
        assert!(err.to_string().contains("before process creation"));
        assert!(!workspace.exists());
    }

    #[test]
    fn start_is_fail_closed_if_constructor_gate_is_bypassed() {
        let mut sandbox = WindowsSandbox;

        let err = sandbox.start().unwrap_err();

        assert!(matches!(err, SandboxError::Unsupported(_)));
        assert!(err.to_string().contains("containment is unavailable"));
    }
}
