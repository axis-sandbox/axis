// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;

pub(crate) fn run(socket: PathBuf, command: Vec<String>) -> Result<i32> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("PTY bridge command must not be empty"))?;

    let mut stream = UnixStream::connect(&socket)
        .with_context(|| format!("connect PTY bridge socket '{}'", socket.display()))?;
    let pty = open_pty().context("open PTY")?;

    let slave_stdin = dup_file(&pty.slave).context("duplicate PTY slave for stdin")?;
    let slave_stdout = dup_file(&pty.slave).context("duplicate PTY slave for stdout")?;
    let slave_stderr = dup_file(&pty.slave).context("duplicate PTY slave for stderr")?;

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::from(slave_stdin))
        .stdout(Stdio::from(slave_stdout))
        .stderr(Stdio::from(slave_stderr))
        .spawn()
        .with_context(|| format!("spawn bridged command '{program}'"))?;

    drop(pty.slave);

    let mut socket_to_pty = stream
        .try_clone()
        .context("clone PTY bridge socket for input")?;
    let mut pty_input = pty
        .master
        .try_clone()
        .context("clone PTY master for input")?;
    let input_thread = thread::spawn(move || {
        let _ = io::copy(&mut socket_to_pty, &mut pty_input);
    });

    copy_pty_output(pty.master, &mut stream);
    let _ = stream.shutdown(std::net::Shutdown::Both);
    let _ = input_thread.join();

    let status = child.wait().context("wait for bridged command")?;
    Ok(status.code().unwrap_or(1))
}

struct PtyFiles {
    master: File,
    slave: File,
}

fn open_pty() -> Result<PtyFiles> {
    let size = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let mut master_fd = -1;
    let mut slave_fd = -1;
    let result = unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &size,
        )
    };
    if result < 0 {
        bail!("{}", io::Error::last_os_error());
    }

    set_close_on_exec(master_fd)?;
    set_close_on_exec(slave_fd)?;

    let master = unsafe { File::from_raw_fd(master_fd) };
    let slave = unsafe { File::from_raw_fd(slave_fd) };
    Ok(PtyFiles { master, slave })
}

fn dup_file(file: &File) -> io::Result<File> {
    file.try_clone()
}

fn set_close_on_exec(fd: i32) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        bail!("{}", io::Error::last_os_error());
    }
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if result < 0 {
        bail!("{}", io::Error::last_os_error());
    }
    Ok(())
}

fn copy_pty_output(mut master: File, stream: &mut UnixStream) {
    let mut buf = [0u8; 8192];
    loop {
        match master.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if stream.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(err) if err.raw_os_error() == Some(libc::EIO) => break,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
}
