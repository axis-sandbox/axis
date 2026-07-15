#!/usr/bin/env python3
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Run argv-only subprocesses with bounded output and process-tree lifetime."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import errno
import os
from pathlib import Path
import signal
import stat

# Commands are argv arrays and never use a shell.
import subprocess  # nosec B404
import sys
import threading
import time
from typing import BinaryIO


PIPE_CHUNK_SIZE = 64 * 1024
TERMINATION_GRACE_SECONDS = 1.5
PIPE_CLOSE_GRACE_SECONDS = 0.5
TREE_CLEANUP_SECONDS = 1.0
CGROUP_CLEANUP_SECONDS = 0.5
PR_SET_PDEATHSIG = 1
PR_SET_CHILD_SUBREAPER = 36
SUPERVISOR_FAILURE_STATUS = 125
CGROUP_ROOT = Path("/sys/fs/cgroup")
BWRAP_CANDIDATES = (Path("/usr/bin/bwrap"), Path("/bin/bwrap"))


class BoundedProcessError(RuntimeError):
    """A subprocess failed, timed out, or exceeded a resource bound."""


@dataclass(frozen=True)
class ProcessResult:
    stdout: bytes
    stderr: bytes


def linux_prctl(option: int, value: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(option, value, 0, 0, 0) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def trusted_bwrap_path() -> Path:
    """Return a non-user-writable Bubblewrap binary or fail closed."""

    for candidate in BWRAP_CANDIDATES:
        try:
            resolved = candidate.resolve(strict=True)
            metadata = resolved.stat()
        except OSError:
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
            continue
        if metadata.st_mode & 0o022 or not os.access(resolved, os.X_OK):
            continue
        trusted = True
        for parent in resolved.parents:
            try:
                parent_metadata = parent.stat()
            except OSError:
                trusted = False
                break
            if parent_metadata.st_uid != 0 or parent_metadata.st_mode & 0o022:
                trusted = False
                break
        if trusted:
            return resolved
    raise OSError(
        "trusted Bubblewrap is required for isolated process-tree supervision"
    )


def isolated_command(bwrap: Path, command: list[str]) -> list[str]:
    """Hide the outer cleanup monitor from the untrusted command's PID view."""

    return [
        str(bwrap),
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-pid",
        "--uid",
        "0",
        "--gid",
        "0",
        "--bind",
        "/",
        "/",
        "--proc",
        "/proc",
        "--dev-bind",
        "/dev",
        "/dev",
        "--chdir",
        os.getcwd(),
        "--",
        *command,
    ]


def current_cgroup_directory() -> Path | None:
    try:
        entries = Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        return None
    unified = [entry[3:] for entry in entries if entry.startswith("0::/")]
    if len(unified) != 1 or ".." in Path(unified[0]).parts:
        return None
    return CGROUP_ROOT / unified[0].lstrip("/")


def create_delegated_cgroup() -> Path | None:
    parent = current_cgroup_directory()
    if parent is None:
        return None
    child = parent / f"axis-bounded-{os.getpid()}-{time.monotonic_ns()}"
    try:
        child.mkdir(mode=0o700)
    except OSError as error:
        if error.errno in (errno.EACCES, errno.EPERM, errno.EROFS, errno.ENOENT):
            return None
        raise
    if not (child / "cgroup.kill").is_file() or not (child / "cgroup.procs").is_file():
        child.rmdir()
        return None
    return child


def cgroup_populated(cgroup: Path) -> bool:
    events = (cgroup / "cgroup.events").read_text(encoding="ascii").splitlines()
    values = dict(line.split(maxsplit=1) for line in events)
    return values.get("populated") == "1"


def direct_child_pids() -> list[int]:
    children_path = Path(f"/proc/self/task/{os.getpid()}/children")
    try:
        data = children_path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as error:
        raise RuntimeError("failed to read kernel child process metadata") from error
    try:
        return [int(value) for value in data.split()]
    except ValueError as error:
        raise RuntimeError("kernel returned invalid child process metadata") from error


def reap_available_children(target: subprocess.Popen[bytes]) -> None:
    target.poll()
    for pid in direct_child_pids():
        if pid == target.pid:
            continue
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass


def kill_adopted_tree(target: subprocess.Popen[bytes], deadline: float) -> bool:
    """Kill only children of the dedicated subreaper, using stable pidfds."""

    while time.monotonic() < deadline:
        reap_available_children(target)
        pids = direct_child_pids()
        if not pids:
            return True
        pidfds = []
        try:
            for pid in pids:
                try:
                    pidfds.append(os.pidfd_open(pid))
                except ProcessLookupError:
                    continue
            for descriptor in pidfds:
                try:
                    signal.pidfd_send_signal(descriptor, signal.SIGSTOP)
                except ProcessLookupError:
                    pass
            for descriptor in pidfds:
                try:
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        finally:
            for descriptor in pidfds:
                os.close(descriptor)
        target.poll()
        for pid in pids:
            if pid == target.pid:
                continue
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass
        time.sleep(0.005)
    reap_available_children(target)
    return not direct_child_pids()


def kill_cgroup_tree(
    cgroup: Path, target: subprocess.Popen[bytes], deadline: float
) -> bool:
    while time.monotonic() < deadline:
        try:
            (cgroup / "cgroup.kill").write_text("1\n", encoding="ascii")
        except FileNotFoundError:
            return False
        reap_available_children(target)
        try:
            if not cgroup_populated(cgroup):
                return kill_adopted_tree(target, deadline)
        except OSError:
            return False
        time.sleep(0.005)
    return False


def cleanup_supervised_tree(
    target: subprocess.Popen[bytes], cgroup: Path | None
) -> bool:
    started = time.monotonic()
    deadline = started + TREE_CLEANUP_SECONDS
    if cgroup is None:
        return kill_adopted_tree(target, deadline)

    cgroup_deadline = min(deadline, started + CGROUP_CLEANUP_SECONDS)
    try:
        cleaned = kill_cgroup_tree(cgroup, target, cgroup_deadline)
    except (OSError, RuntimeError):
        cleaned = False
    if not cleaned:
        cleaned = kill_adopted_tree(target, deadline)
    try:
        cgroup.rmdir()
    except OSError:
        # A command can move out of a delegated cgroup and remove or race its
        # metadata. Always make a final ancestry-based cleanup attempt.
        kill_adopted_tree(target, deadline)
        cleaned = False
    return cleaned


def normalized_exit_status(return_code: int) -> int:
    if return_code < 0:
        return min(255, 128 - return_code)
    return min(255, return_code)


def supervisor_main(command: list[str]) -> int:
    if not command:
        print("bounded supervisor requires a command", file=sys.stderr)
        return SUPERVISOR_FAILURE_STATUS
    interrupted = False

    def request_cleanup(_signal_number, _frame):
        nonlocal interrupted
        interrupted = True

    signal.signal(signal.SIGTERM, request_cleanup)
    signal.signal(signal.SIGINT, request_cleanup)
    parent_pid = os.getppid()
    try:
        linux_prctl(PR_SET_CHILD_SUBREAPER, 1)
        linux_prctl(PR_SET_PDEATHSIG, signal.SIGTERM)
        if os.getppid() != parent_pid:
            raise OSError("bounded subprocess parent exited during supervisor setup")
        if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
            raise OSError("pidfd support is required for process-tree containment")
        self_pidfd = os.pidfd_open(os.getpid())
        os.close(self_pidfd)
        children = Path(f"/proc/self/task/{os.getpid()}/children")
        if not children.is_file():
            raise OSError("Linux procfs child metadata is unavailable")
        bwrap = trusted_bwrap_path()
        cgroup = create_delegated_cgroup()
    except OSError as error:
        print(f"failed to establish process-tree containment: {error}", file=sys.stderr)
        return SUPERVISOR_FAILURE_STATUS
    if interrupted:
        if cgroup is not None:
            try:
                cgroup.rmdir()
            except OSError as error:
                print(f"failed to remove command cgroup: {error}", file=sys.stderr)
                return SUPERVISOR_FAILURE_STATUS
        return 128 + signal.SIGTERM
    supervised_command = isolated_command(bwrap, command)
    if cgroup is not None:
        supervised_command = [
            sys.executable,
            str(Path(__file__).resolve()),
            "--cgroup-exec",
            str(cgroup),
            *supervised_command,
        ]
    try:
        target = subprocess.Popen(  # nosec B603
            supervised_command,
            start_new_session=True,
        )
    except OSError as error:
        if cgroup is not None:
            try:
                cgroup.rmdir()
            except OSError as cleanup_error:
                print(
                    f"failed to remove command cgroup: {cleanup_error}",
                    file=sys.stderr,
                )
        print(f"command failed to start: {command[0]}: {error}", file=sys.stderr)
        return 127

    while target.poll() is None and not interrupted:
        time.sleep(0.005)
    return_code = target.returncode
    try:
        cleaned = cleanup_supervised_tree(target, cgroup)
    except (OSError, RuntimeError) as error:
        print(f"process-tree cleanup failed: {error}", file=sys.stderr)
        return SUPERVISOR_FAILURE_STATUS
    if not cleaned:
        print("failed to terminate the complete command process tree", file=sys.stderr)
        return SUPERVISOR_FAILURE_STATUS
    target.poll()
    if interrupted:
        return 128 + signal.SIGTERM
    if return_code is None:
        return_code = target.returncode
    if return_code is None:
        print("failed to reap the supervised command", file=sys.stderr)
        return SUPERVISOR_FAILURE_STATUS
    return normalized_exit_status(return_code)


def cgroup_exec_main(arguments: list[str]) -> int:
    if len(arguments) < 2:
        print("cgroup executor requires a cgroup and command", file=sys.stderr)
        return SUPERVISOR_FAILURE_STATUS
    cgroup, command = Path(arguments[0]), arguments[1:]
    try:
        (cgroup / "cgroup.procs").write_text(f"{os.getpid()}\n", encoding="ascii")
        # The reviewed command is a structured argv vector and never invokes a shell.
        os.execvp(command[0], command)  # nosec B606
    except OSError as error:
        print(f"failed to enter command cgroup: {error}", file=sys.stderr)
        return 126


def terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    """Ask the dedicated supervisor to terminate and reap its process tree."""

    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        except OSError:
            pass
        deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return
            time.sleep(0.01)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        return

    try:
        process.terminate()
        process.wait(timeout=TERMINATION_GRACE_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
        except OSError:
            pass


def run_bounded(
    command: list[str],
    *,
    cwd: Path | None = None,
    timeout: float,
    stdout_limit: int,
    stderr_limit: int,
    stdout_sink: BinaryIO | None = None,
    retain_stdout: bool = True,
    require_tree_containment: bool = True,
) -> ProcessResult:
    """Run a command while bounding output and the complete process lifetime."""

    if not command or timeout <= 0 or stdout_limit < 0 or stderr_limit < 0:
        raise BoundedProcessError("command and nonnegative bounds are required")
    if require_tree_containment and not sys.platform.startswith("linux"):
        raise BoundedProcessError("complete subprocess tree containment requires Linux")
    supervised_command = command
    if require_tree_containment:
        supervised_command = [
            sys.executable,
            str(Path(__file__).resolve()),
            "--supervise",
            *command,
        ]
    try:
        # Shell execution is disabled and callers provide a structured argv array.
        process = subprocess.Popen(  # nosec B603
            supervised_command,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=(os.name == "posix"),
        )
    except OSError as error:
        raise BoundedProcessError(
            f"command failed to start: {command[0]}: {error}"
        ) from error

    stdout_pipe = process.stdout
    stderr_pipe = process.stderr
    if stdout_pipe is None or stderr_pipe is None:
        terminate_process_group(process)
        raise BoundedProcessError("failed to create bounded command pipes")
    stop_lock = threading.Lock()
    stop_reason: list[str] = []
    buffers = {"stdout": bytearray(), "stderr": bytearray()}

    def stop(reason: str) -> None:
        with stop_lock:
            if stop_reason:
                return
            stop_reason.append(reason)
        terminate_process_group(process)

    def drain(
        label: str,
        source: BinaryIO,
        limit: int,
        sink: BinaryIO | None,
        retain: bool,
    ) -> None:
        total = 0
        try:
            while chunk := source.read(PIPE_CHUNK_SIZE):
                if total + len(chunk) > limit:
                    allowed = max(0, limit - total)
                    if allowed and sink is not None:
                        sink.write(chunk[:allowed])
                    if allowed and retain:
                        buffers[label].extend(chunk[:allowed])
                    stop(f"command {label} exceeds {limit} bytes: {command[0]}")
                    return
                total += len(chunk)
                if sink is not None:
                    sink.write(chunk)
                if retain:
                    buffers[label].extend(chunk)
        except (OSError, ValueError) as error:
            stop(f"failed to read command {label}: {command[0]}: {error}")
        finally:
            try:
                source.close()
            except OSError:
                pass

    threads = [
        threading.Thread(
            target=drain,
            args=("stdout", stdout_pipe, stdout_limit, stdout_sink, retain_stdout),
            daemon=True,
        ),
        threading.Thread(
            target=drain,
            args=("stderr", stderr_pipe, stderr_limit, None, True),
            daemon=True,
        ),
    ]
    for thread in threads:
        thread.start()

    try:
        return_code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        stop(f"command timed out after {timeout:g}s: {command[0]}")
        try:
            return_code = process.wait(timeout=TERMINATION_GRACE_SECONDS + 1)
        except subprocess.TimeoutExpired:
            return_code = -1

    pipe_deadline = time.monotonic() + PIPE_CLOSE_GRACE_SECONDS
    for thread in threads:
        thread.join(max(0, pipe_deadline - time.monotonic()))
    if any(thread.is_alive() for thread in threads):
        stop(f"command descendants kept output pipes open: {command[0]}")
        for thread in threads:
            thread.join(TERMINATION_GRACE_SECONDS + 1)
    if any(thread.is_alive() for thread in threads):
        raise BoundedProcessError(
            f"command output pipes did not close after termination: {command[0]}"
        )
    if stop_reason:
        raise BoundedProcessError(stop_reason[0])
    if return_code != 0:
        detail = bytes(buffers["stderr"]).decode("utf-8", errors="replace").strip()
        raise BoundedProcessError(
            f"command failed with status {return_code}: {command[0]}: {detail}"
        )
    return ProcessResult(bytes(buffers["stdout"]), bytes(buffers["stderr"]))


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--supervise":
        raise SystemExit(supervisor_main(sys.argv[2:]))
    if len(sys.argv) >= 2 and sys.argv[1] == "--cgroup-exec":
        raise SystemExit(cgroup_exec_main(sys.argv[2:]))
    raise SystemExit("bounded_subprocess.py is an internal helper")
