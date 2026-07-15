# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from contextlib import redirect_stderr
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import bounded_subprocess
from bounded_subprocess import BoundedProcessError, run_bounded


class BoundedSubprocessTests(unittest.TestCase):
    def run_python(self, source: str, **overrides):
        arguments = {
            "timeout": 5,
            "stdout_limit": 4096,
            "stderr_limit": 4096,
        }
        arguments.update(overrides)
        return run_bounded([sys.executable, "-c", source], **arguments)

    def marker_processes(self, marker: str) -> list[int]:
        matches = []
        for command_line in Path("/proc").glob("[0-9]*/cmdline"):
            try:
                content = command_line.read_bytes()
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
            if marker.encode("utf-8") in content:
                matches.append(int(command_line.parent.name))
        return matches

    def wait_for_exit(self, marker: str):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if not self.marker_processes(marker):
                return
            time.sleep(0.01)
        self.fail(
            f"processes {self.marker_processes(marker)} with marker {marker!r} "
            "survived bounded subprocess cleanup"
        )

    def detached_source(self, pid_file: Path, parent_action: str = "") -> str:
        return f"""
import os, time
first = os.fork()
if first == 0:
    os.setsid()
    second = os.fork()
    if second:
        os._exit(0)
    null = os.open(os.devnull, os.O_RDWR)
    for descriptor in (0, 1, 2):
        os.dup2(null, descriptor)
    os.close(null)
    with open({str(pid_file)!r}, 'w', encoding='ascii') as output:
        output.write(str(os.getpid()))
    time.sleep(30)
os.waitpid(first, 0)
while not os.path.exists({str(pid_file)!r}):
    time.sleep(0.001)
{parent_action}
"""

    def test_returns_normal_bounded_stdout_and_stderr(self):
        result = self.run_python(
            "import sys; print('output'); print('diagnostic', file=sys.stderr)"
        )
        self.assertEqual(result.stdout, b"output\n")
        self.assertEqual(result.stderr, b"diagnostic\n")

    def test_rejects_infinite_stdout_and_infinite_stderr_promptly(self):
        for stream in (1, 2):
            with self.subTest(stream=stream):
                started = time.monotonic()
                with self.assertRaisesRegex(BoundedProcessError, "exceeds 1024"):
                    self.run_python(
                        f"import os\nwhile True: os.write({stream}, b'x' * 4096)",
                        stdout_limit=1024,
                        stderr_limit=1024,
                    )
                self.assertLess(time.monotonic() - started, 3)

    def test_drains_simultaneous_stdout_and_stderr_without_deadlock(self):
        source = """
import os, threading
def write(fd):
    while True:
        os.write(fd, b'x' * 4096)
threads = [threading.Thread(target=write, args=(fd,)) for fd in (1, 2)]
for thread in threads: thread.start()
for thread in threads: thread.join()
"""
        with self.assertRaisesRegex(BoundedProcessError, "exceeds 2048"):
            self.run_python(source, stdout_limit=2048, stderr_limit=2048)

    def test_timeout_kills_process_group(self):
        started = time.monotonic()
        with self.assertRaisesRegex(BoundedProcessError, "timed out"):
            self.run_python("import time; time.sleep(30)", timeout=0.05)
        self.assertLess(time.monotonic() - started, 3)

    @unittest.skipUnless(os.name == "posix", "process groups are POSIX-specific")
    def test_kills_child_that_inherits_output_pipes(self):
        with tempfile.TemporaryDirectory() as temporary:
            pid_file = Path(temporary) / "pid"
            child_source = f"# {pid_file}\nimport time; time.sleep(30)"
            source = (
                "import subprocess, sys\n"
                f"child=subprocess.Popen([sys.executable,'-c',{child_source!r}])\n"
            )
            self.run_python(source)
            self.wait_for_exit(str(pid_file))

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux subreaping")
    def test_kills_double_fork_setsid_descendant_after_success_and_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, action in enumerate(("", "raise SystemExit(7)")):
                with self.subTest(action=action or "success"):
                    pid_file = root / f"detached-{index}.pid"
                    if action:
                        with self.assertRaisesRegex(BoundedProcessError, "status 7"):
                            self.run_python(self.detached_source(pid_file, action))
                    else:
                        self.run_python(self.detached_source(pid_file))
                    self.wait_for_exit(str(pid_file))

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux subreaping")
    def test_kills_detached_descendant_on_timeout_and_output_cap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            timeout_pid = root / "timeout.pid"
            with self.assertRaisesRegex(BoundedProcessError, "timed out"):
                self.run_python(
                    self.detached_source(timeout_pid, "time.sleep(30)"), timeout=0.1
                )
            self.wait_for_exit(str(timeout_pid))

            output_pid = root / "output.pid"
            with self.assertRaisesRegex(BoundedProcessError, "stdout exceeds"):
                self.run_python(
                    self.detached_source(
                        output_pid,
                        "\nwhile True:\n    os.write(1, b'x' * 4096)",
                    ),
                    stdout_limit=1024,
                )
            self.wait_for_exit(str(output_pid))

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux subreaping")
    def test_repeated_detached_probes_do_not_kill_unrelated_process(self):
        unrelated = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"]
        )
        try:
            with tempfile.TemporaryDirectory() as temporary:
                for index in range(8):
                    pid_file = Path(temporary) / f"probe-{index}.pid"
                    self.run_python(self.detached_source(pid_file))
                    self.wait_for_exit(str(pid_file))
                    self.assertIsNone(unrelated.poll())
        finally:
            unrelated.terminate()
            unrelated.wait(timeout=2)

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux subreaping")
    def test_continuous_fork_stress_is_fully_reaped(self):
        with tempfile.TemporaryDirectory() as temporary:
            pid_file = Path(temporary) / "forks.pid"
            source = f"""
import os, time
leader = os.fork()
if leader == 0:
    os.setsid()
    for _ in range(64):
        child = os.fork()
        if child == 0:
            descriptor = os.open({str(pid_file)!r}, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            os.write(descriptor, (str(os.getpid()) + '\\n').encode('ascii'))
            os.close(descriptor)
            time.sleep(30)
            os._exit(0)
        time.sleep(0.001)
    time.sleep(30)
while not os.path.exists({str(pid_file)!r}):
    time.sleep(0.001)
time.sleep(30)
"""
            with self.assertRaisesRegex(BoundedProcessError, "timed out"):
                self.run_python(source, timeout=0.15)
            self.assertTrue(pid_file.read_text(encoding="ascii").splitlines())
            self.wait_for_exit(str(pid_file))

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux namespaces")
    def test_sigkill_probe_cannot_kill_the_only_cleanup_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            pid_file = Path(temporary) / "adversarial.pid"
            attack = """
import signal
try:
    os.kill(os.getppid(), signal.SIGKILL)
except (PermissionError, ProcessLookupError):
    pass
"""
            self.run_python(self.detached_source(pid_file, attack))
            self.wait_for_exit(str(pid_file))

    def test_pidfds_anchor_signals_against_pid_reuse(self):
        target = mock.Mock(pid=100, returncode=None)
        target.poll.return_value = None
        with mock.patch.object(
            bounded_subprocess,
            "direct_child_pids",
            side_effect=[[100], [100], [], []],
        ), mock.patch.object(
            bounded_subprocess.os, "pidfd_open", return_value=77
        ) as pidfd_open, mock.patch.object(
            bounded_subprocess.signal, "pidfd_send_signal"
        ) as pidfd_signal, mock.patch.object(
            bounded_subprocess.os, "close"
        ), mock.patch.object(
            bounded_subprocess.os, "waitpid", side_effect=ChildProcessError
        ):
            self.assertTrue(
                bounded_subprocess.kill_adopted_tree(target, time.monotonic() + 1)
            )
        pidfd_open.assert_called_once_with(100)
        self.assertEqual(
            [call.args for call in pidfd_signal.call_args_list],
            [
                (77, bounded_subprocess.signal.SIGSTOP),
                (77, bounded_subprocess.signal.SIGKILL),
            ],
        )

    def test_cgroup_failure_always_falls_back_to_adopted_tree_cleanup(self):
        cgroup = mock.Mock(spec=Path)
        target = mock.Mock()
        with mock.patch.object(
            bounded_subprocess, "kill_cgroup_tree", return_value=False
        ) as kill_cgroup, mock.patch.object(
            bounded_subprocess, "kill_adopted_tree", return_value=True
        ) as kill_adopted:
            self.assertTrue(bounded_subprocess.cleanup_supervised_tree(target, cgroup))

        cgroup.rmdir.assert_called_once_with()
        kill_adopted.assert_called_once()
        self.assertIs(kill_adopted.call_args.args[0], target)
        self.assertGreater(
            kill_adopted.call_args.args[1], kill_cgroup.call_args.args[2]
        )

    def test_cgroup_removal_failure_still_attempts_adopted_cleanup(self):
        cgroup = mock.Mock(spec=Path)
        cgroup.rmdir.side_effect = OSError("cgroup remained populated")
        target = mock.Mock()
        with mock.patch.object(
            bounded_subprocess, "kill_cgroup_tree", return_value=True
        ), mock.patch.object(
            bounded_subprocess, "kill_adopted_tree", return_value=True
        ) as kill_adopted:
            self.assertFalse(bounded_subprocess.cleanup_supervised_tree(target, cgroup))
        kill_adopted.assert_called_once()

    def test_cgroup_io_exception_falls_back_to_adopted_tree_cleanup(self):
        cgroup = mock.Mock(spec=Path)
        target = mock.Mock()
        with mock.patch.object(
            bounded_subprocess,
            "kill_cgroup_tree",
            side_effect=OSError("cgroup metadata failed"),
        ), mock.patch.object(
            bounded_subprocess, "kill_adopted_tree", return_value=True
        ) as kill_adopted:
            self.assertTrue(bounded_subprocess.cleanup_supervised_tree(target, cgroup))
        cgroup.rmdir.assert_called_once_with()
        kill_adopted.assert_called_once()

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux supervision")
    def test_supervisor_prefers_delegated_cgroup_wrapper(self):
        cgroup = Path("/sys/fs/cgroup/delegated/axis-test")
        bwrap = Path("/usr/bin/bwrap")
        target = mock.Mock(returncode=0)
        target.poll.return_value = 0
        with mock.patch.object(bounded_subprocess, "linux_prctl"), mock.patch.object(
            bounded_subprocess, "create_delegated_cgroup", return_value=cgroup
        ), mock.patch.object(
            bounded_subprocess, "trusted_bwrap_path", return_value=bwrap
        ), mock.patch.object(
            bounded_subprocess, "cleanup_supervised_tree", return_value=True
        ) as cleanup, mock.patch.object(
            bounded_subprocess.signal, "signal"
        ), mock.patch.object(
            bounded_subprocess.subprocess, "Popen", return_value=target
        ) as popen:
            self.assertEqual(bounded_subprocess.supervisor_main(["tool", "arg"]), 0)
        supervised = popen.call_args.args[0]
        self.assertEqual(
            supervised[:4],
            [
                sys.executable,
                str(Path(bounded_subprocess.__file__).resolve()),
                "--cgroup-exec",
                str(cgroup),
            ],
        )
        isolated = supervised[4:]
        self.assertEqual(isolated[0], str(bwrap))
        self.assertIn("--unshare-user", isolated)
        self.assertIn("--unshare-pid", isolated)
        self.assertEqual(isolated[-3:], ["--", "tool", "arg"])
        cleanup.assert_called_once_with(target, cgroup)

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux supervision")
    def test_missing_trusted_namespace_helper_fails_before_command_spawn(self):
        with mock.patch.object(bounded_subprocess, "linux_prctl"), mock.patch.object(
            bounded_subprocess, "BWRAP_CANDIDATES", (Path("/missing/bwrap"),)
        ), mock.patch.object(
            bounded_subprocess.signal, "signal"
        ), mock.patch.object(
            bounded_subprocess.subprocess, "Popen"
        ) as popen:
            with redirect_stderr(io.StringIO()):
                self.assertEqual(
                    bounded_subprocess.supervisor_main(["must-not-run"]),
                    bounded_subprocess.SUPERVISOR_FAILURE_STATUS,
                )
        popen.assert_not_called()

    def test_non_linux_tree_containment_fails_before_spawn(self):
        with mock.patch.object(
            bounded_subprocess.sys, "platform", "darwin"
        ), mock.patch.object(
            bounded_subprocess.subprocess, "Popen"
        ) as popen, self.assertRaisesRegex(
            BoundedProcessError, "requires Linux"
        ):
            self.run_python("print('not launched')")
        popen.assert_not_called()

    def test_streams_stdout_to_a_bounded_sink(self):
        with tempfile.TemporaryFile() as sink:
            result = self.run_python(
                "import os; os.write(1, b'payload')",
                stdout_sink=sink,
                retain_stdout=False,
            )
            self.assertEqual(result.stdout, b"")
            sink.seek(0)
            self.assertEqual(sink.read(), b"payload")

    def test_rejects_nonzero_exit_with_bounded_error(self):
        with self.assertRaisesRegex(BoundedProcessError, "diagnostic") as error:
            self.run_python("import sys; sys.stderr.write('diagnostic'); sys.exit(7)")
        self.assertLess(len(str(error.exception)), 256)


if __name__ == "__main__":
    unittest.main()
