// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Unix (Linux/macOS) PTY implementation using openpty(2).

use crate::session::{PtyMaster, PtySession, PtySlave};
use crate::{PtyError, WinSize};
use std::os::unix::io::RawFd;

/// Unix-specific PTY master state.
pub struct UnixPtyMaster {
    fd: RawFd,
}

impl UnixPtyMaster {
    pub fn resize(&self, size: WinSize) -> Result<(), PtyError> {
        let ws = libc::winsize {
            ws_col: size.cols,
            ws_row: size.rows,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let ret = unsafe { libc::ioctl(self.fd, libc::TIOCSWINSZ, &ws) };
        if ret < 0 {
            Err(PtyError::Resize(std::io::Error::last_os_error().to_string()))
        } else {
            Ok(())
        }
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for UnixPtyMaster {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Create a PTY pair on Unix using openpty(2).
pub fn create_pty_unix(size: WinSize) -> Result<PtySession, PtyError> {
    let mut ws = libc::winsize {
        ws_col: size.cols,
        ws_row: size.rows,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    let mut master_fd: RawFd = -1;
    let mut slave_fd: RawFd = -1;

    let ret = unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut ws,
        )
    };

    if ret < 0 {
        return Err(PtyError::Creation(
            std::io::Error::last_os_error().to_string(),
        ));
    }

    // Set master fd to non-blocking for async I/O.
    let flags = unsafe { libc::fcntl(master_fd, libc::F_GETFL) };
    unsafe {
        libc::fcntl(master_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let unix_master = UnixPtyMaster { fd: master_fd };

    tracing::debug!("PTY created: master_fd={master_fd}, slave_fd={slave_fd}");

    Ok(PtySession {
        master: PtyMaster::from_unix(unix_master),
        slave: PtySlave::Unix(slave_fd),
        size,
    })
}
