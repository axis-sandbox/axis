// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Cross-platform pseudoterminal (PTY) allocation for AXIS sandboxes.
//!
//! Provides a unified interface for creating PTY pairs on Linux/macOS (via
//! `openpty(2)`) and Windows (via ConPTY). The master side stays in the daemon
//! for async read/write; the slave side is given to the sandboxed child process.

pub mod session;

#[cfg(unix)]
pub mod unix;

#[cfg(windows)]
pub mod windows;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PtyError {
    #[error("failed to create PTY: {0}")]
    Creation(String),

    #[error("PTY I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PTY resize failed: {0}")]
    Resize(String),

    #[error("PTY not supported on this platform")]
    Unsupported,
}

/// Terminal dimensions.
#[derive(Debug, Clone, Copy)]
pub struct WinSize {
    pub cols: u16,
    pub rows: u16,
}

impl Default for WinSize {
    fn default() -> Self {
        Self { cols: 80, rows: 24 }
    }
}

/// Create a new PTY session with the given initial size.
pub fn create_pty(size: WinSize) -> Result<session::PtySession, PtyError> {
    #[cfg(unix)]
    return unix::create_pty_unix(size);

    #[cfg(windows)]
    return windows::create_pty_windows(size);

    #[cfg(not(any(unix, windows)))]
    {
        let _ = size;
        Err(PtyError::Unsupported)
    }
}
