// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! PTY session types shared across platforms.

use crate::{PtyError, WinSize};

/// A PTY session consisting of a master (for the daemon) and slave info
/// (for the child process).
pub struct PtySession {
    /// The master side — daemon reads/writes here to communicate with the child.
    pub master: PtyMaster,
    /// Platform-specific slave handle to pass to the child process.
    pub slave: PtySlave,
    /// Current terminal dimensions.
    pub size: WinSize,
}

impl PtySession {
    /// Resize the terminal.
    pub fn resize(&mut self, new_size: WinSize) -> Result<(), PtyError> {
        self.master.resize(new_size)?;
        self.size = new_size;
        Ok(())
    }
}

/// The master side of a PTY — owned by the daemon.
pub struct PtyMaster {
    inner: PtyMasterInner,
}

enum PtyMasterInner {
    #[cfg(unix)]
    Unix(crate::unix::UnixPtyMaster),
    #[cfg(windows)]
    Windows(crate::windows::WindowsPtyMaster),
}

impl PtyMaster {
    #[cfg(unix)]
    pub(crate) fn from_unix(inner: crate::unix::UnixPtyMaster) -> Self {
        Self {
            inner: PtyMasterInner::Unix(inner),
        }
    }

    #[cfg(windows)]
    pub(crate) fn from_windows(inner: crate::windows::WindowsPtyMaster) -> Self {
        Self {
            inner: PtyMasterInner::Windows(inner),
        }
    }

    /// Resize the PTY.
    pub fn resize(&self, size: WinSize) -> Result<(), PtyError> {
        match &self.inner {
            #[cfg(unix)]
            PtyMasterInner::Unix(m) => m.resize(size),
            #[cfg(windows)]
            PtyMasterInner::Windows(m) => m.resize(size),
        }
    }

    /// Get the raw file descriptor (Unix) for async I/O integration.
    #[cfg(unix)]
    pub fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        match &self.inner {
            PtyMasterInner::Unix(m) => m.raw_fd(),
        }
    }
}

/// Platform-specific slave handle passed to the child process.
pub enum PtySlave {
    #[cfg(unix)]
    Unix(std::os::unix::io::RawFd),
    #[cfg(windows)]
    Windows(crate::windows::ConPtySlave),
}

impl PtySlave {
    /// Get the raw file descriptor for the slave side (Unix).
    #[cfg(unix)]
    pub fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        match self {
            PtySlave::Unix(fd) => *fd,
        }
    }
}
