// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Windows PTY implementation using ConPTY (CreatePseudoConsole).
//!
//! ConPTY provides a pseudoterminal interface on Windows 10 1809+ and Windows 11.
//! Architecture:
//!   - CreatePipe for input/output handles
//!   - CreatePseudoConsole with those handles
//!   - Child process launched with PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
//!   - Daemon reads/writes the pipe handles

use crate::session::{PtyMaster, PtySession, PtySlave};
use crate::{PtyError, WinSize};

/// Windows-specific PTY master using ConPTY pipes.
pub struct WindowsPtyMaster {
    /// Handle to the pseudoconsole (HPCON).
    hpc: isize,
    /// Read handle — reads child output from the console.
    read_handle: std::os::windows::io::OwnedHandle,
    /// Write handle — writes input to the child via console.
    write_handle: std::os::windows::io::OwnedHandle,
}

/// Slave info for Windows ConPTY — the child process needs the HPCON
/// to set up its PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE.
pub struct ConPtySlave {
    /// The pseudoconsole handle (HPCON) that the child must reference.
    pub hpc: isize,
    /// The pipe handle the child reads from (its stdin).
    pub child_read: std::os::windows::io::OwnedHandle,
    /// The pipe handle the child writes to (its stdout/stderr).
    pub child_write: std::os::windows::io::OwnedHandle,
}

impl WindowsPtyMaster {
    pub fn resize(&self, size: WinSize) -> Result<(), PtyError> {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn ResizePseudoConsole(hPC: isize, size: u32) -> i32;
        }

        // COORD is packed as (X=cols, Y=rows) in a single u32 (little-endian).
        let coord: u32 = (size.cols as u32) | ((size.rows as u32) << 16);
        let hr = unsafe { ResizePseudoConsole(self.hpc, coord) };
        if hr < 0 {
            Err(PtyError::Resize(format!("ResizePseudoConsole HRESULT: 0x{hr:08X}")))
        } else {
            Ok(())
        }
    }

    pub fn reader(&self) -> impl tokio::io::AsyncRead + '_ {
        // TODO: Wrap read_handle in a tokio AsyncRead via named pipe or thread-based bridge.
        // For now, return a placeholder that will be implemented with tokio::io::duplex.
        tokio::io::empty()
    }

    pub fn writer(&self) -> impl tokio::io::AsyncWrite + '_ {
        // TODO: Wrap write_handle in a tokio AsyncWrite.
        tokio::io::sink()
    }
}

impl Drop for WindowsPtyMaster {
    fn drop(&mut self) {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn ClosePseudoConsole(hPC: isize);
        }
        unsafe { ClosePseudoConsole(self.hpc); }
    }
}

/// Create a ConPTY pair on Windows.
pub fn create_pty_windows(size: WinSize) -> Result<PtySession, PtyError> {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use std::ptr;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreatePipe(
            hReadPipe: *mut isize,
            hWritePipe: *mut isize,
            lpPipeAttributes: *const u8,
            nSize: u32,
        ) -> i32;

        fn CreatePseudoConsole(
            size: u32,
            hInput: isize,
            hOutput: isize,
            dwFlags: u32,
            phPC: *mut isize,
        ) -> i32;
    }

    // COORD packed as u32: low word = X (cols), high word = Y (rows).
    let coord: u32 = (size.cols as u32) | ((size.rows as u32) << 16);

    // Create the input pipe (daemon writes -> child reads).
    let mut pipe_in_read: isize = 0;
    let mut pipe_in_write: isize = 0;
    let ok = unsafe { CreatePipe(&mut pipe_in_read, &mut pipe_in_write, ptr::null(), 0) };
    if ok == 0 {
        return Err(PtyError::Creation("CreatePipe (input) failed".into()));
    }

    // Create the output pipe (child writes -> daemon reads).
    let mut pipe_out_read: isize = 0;
    let mut pipe_out_write: isize = 0;
    let ok = unsafe { CreatePipe(&mut pipe_out_read, &mut pipe_out_write, ptr::null(), 0) };
    if ok == 0 {
        return Err(PtyError::Creation("CreatePipe (output) failed".into()));
    }

    // Create the pseudoconsole.
    let mut hpc: isize = 0;
    let hr = unsafe {
        CreatePseudoConsole(coord, pipe_in_read, pipe_out_write, 0, &mut hpc)
    };
    if hr < 0 {
        return Err(PtyError::Creation(format!(
            "CreatePseudoConsole HRESULT: 0x{hr:08X}"
        )));
    }

    tracing::debug!("ConPTY created: hpc={hpc}, size={}x{}", size.cols, size.rows);

    let master = WindowsPtyMaster {
        hpc,
        read_handle: unsafe { OwnedHandle::from_raw_handle(pipe_out_read as *mut _) },
        write_handle: unsafe { OwnedHandle::from_raw_handle(pipe_in_write as *mut _) },
    };

    let slave = ConPtySlave {
        hpc,
        child_read: unsafe { OwnedHandle::from_raw_handle(pipe_in_read as *mut _) },
        child_write: unsafe { OwnedHandle::from_raw_handle(pipe_out_write as *mut _) },
    };

    Ok(PtySession {
        master: PtyMaster::from_windows(master),
        slave: PtySlave::Windows(slave),
        size,
    })
}
