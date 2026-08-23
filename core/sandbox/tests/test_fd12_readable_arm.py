"""fd 1/2 readable-descriptor arm (extension of the tty write-only
reopen).

The tty fix handed the child a write-only reopen of an inherited
terminal, but the policy was tty-only: an O_RDWR NON-tty descriptor on
stdout/stderr (regular file opened rw, a socket, an rw FIFO) passed
unchecked (``isatty → continue``), handing the sandboxed child read
access the filesystem policy never granted — descriptor capabilities
ride past Landlock and the mount namespace.

Contract under test (uncaptured run_untrusted, caller supplies no
stdout=/stderr=):

* O_WRONLY pass-throughs (the normal shell-redirect shape) stay
  untouched;
* readable regular files are replaced with a write-only reopen at the
  inherited offset;
* readable sockets are plugged with DEVNULL (no write-only reopen
  exists) with a loud warning;
* the reopened fd is closed after the run.
"""

from __future__ import annotations

import fcntl
import os
import socket
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


class _Fd1Swap:
    """Temporarily install *fd* as this process's fd 1."""

    def __init__(self, fd: int):
        self.fd = fd

    def __enter__(self):
        self.saved = os.dup(1)
        os.dup2(self.fd, 1)
        return self

    def __exit__(self, *exc):
        os.dup2(self.saved, 1)
        os.close(self.saved)
        return False


class TestFd12ReadableArm(unittest.TestCase):
    def _run_untrusted_capturing(self):
        import core.sandbox.context as ctx

        captured = {}

        def fake_run(cmd, **kw):
            captured.update(kw)
            # Snapshot the access mode NOW — the finally block closes
            # the reopened fd after run() returns.
            std = kw.get("stdout")
            if isinstance(std, int) and std >= 0:
                captured["_stdout_acc"] = (
                    fcntl.fcntl(std, fcntl.F_GETFL) & os.O_ACCMODE
                )
                captured["_stdout_pos"] = os.lseek(
                    std, 0, os.SEEK_CUR)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with patch.object(ctx, "run", fake_run):
            ctx.run_untrusted(["true"], target="/tmp")
        return captured

    def test_rdwr_regular_file_reopened_write_only_at_offset(self):
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            path = tf.name
        self.addCleanup(os.unlink, path)
        fd = os.open(path, os.O_RDWR)
        self.addCleanup(os.close, fd)
        os.write(fd, b"parent-output-so-far")

        with _Fd1Swap(fd):
            captured = self._run_untrusted_capturing()

        self.assertIsInstance(captured.get("stdout"), int)
        self.assertEqual(captured.get("_stdout_acc"), os.O_WRONLY)
        self.assertEqual(
            captured.get("_stdout_pos"), len(b"parent-output-so-far"),
        )

    def test_readable_socket_plugged_with_devnull(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)

        with _Fd1Swap(a.fileno()):
            captured = self._run_untrusted_capturing()

        self.assertEqual(captured.get("stdout"), subprocess.DEVNULL)

    def test_wronly_file_untouched(self):
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            path = tf.name
        self.addCleanup(os.unlink, path)
        fd = os.open(path, os.O_WRONLY)
        self.addCleanup(os.close, fd)

        with _Fd1Swap(fd):
            captured = self._run_untrusted_capturing()

        # No replacement: the shape is already write-only.
        self.assertNotIn("stdout", captured)

    def test_capture_output_skips_the_arm_entirely(self):
        import core.sandbox.context as ctx

        captured = {}

        def fake_run(cmd, **kw):
            captured.update(kw)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        with _Fd1Swap(a.fileno()), patch.object(ctx, "run", fake_run):
            ctx.run_untrusted(
                ["true"], target="/tmp", capture_output=True,
            )
        self.assertNotIn("stdout", captured)


if __name__ == "__main__":
    unittest.main()
