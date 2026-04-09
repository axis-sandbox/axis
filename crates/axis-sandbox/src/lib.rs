// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! AXIS Sandbox — OS-specific process isolation.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

mod sandbox;
pub use sandbox::{Sandbox, SandboxConfig, SandboxError};
