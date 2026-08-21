"""AF_UNIX connect scoping on the mount-ns spawn path.

Battery shapes pinned here (variant family, not just the exemplar):

- enforcement-mode child connects to a unix socket bound by a HOST
  process inside the rw output bind → must fail (was a live
  bidirectional sandbox<->host channel);
- same via the block_network=False posture (host netns, the
  target_run profile shape);
- symlink bounce: /tmp/link -> output socket → must fail (the
  supervisor refuses symlinked paths wholesale);
- SOCK_DGRAM AF_UNIX creation → EPERM (datagram sendto-with-address
  would bypass the connect chokepoint);
- SOCK_SEQPACKET connect to the output socket → must fail (family
  covers all connection-oriented types);
- the legitimate use stays working: bind + connect a pathname socket
  under the sandbox-private /tmp (the Python >= 3.14 forkserver
  shape), and plain TCP connects still work through the
  execute-on-behalf supervisor;
- fail-closed downgrade: when the supervisor cannot run,
  socket(AF_UNIX) is denied outright.
"""

import os
import shutil
import socket
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="mount-ns spawn path is Linux-only",
)


def _mount_ns_usable() -> bool:
    if not shutil.which("newuidmap") or not shutil.which("newgidmap"):
        return False
    sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    return not (sysctl.exists() and sysctl.read_text().strip() == "1")


def _scope_usable() -> bool:
    from core.sandbox._unix_scope import probe_unix_scope
    return probe_unix_scope()


_SPAWN_DEFAULTS = dict(
    nproc_limit=1024,
    limits={"memory_mb": 0, "max_file_mb": 10240, "cpu_seconds": 300},
    readable_paths=None,
    allowed_tcp_ports=None,
    seccomp_profile="full",
    seccomp_block_udp=False,
    env=None, cwd=None, timeout=30,
    capture_output=True, text=True,
)


class _Base(unittest.TestCase):
    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest("mount-ns unusable here")
        if not _scope_usable():
            self.skipTest("seccomp user-notify connect scoping "
                          "unavailable on this host")
        self._out = tempfile.TemporaryDirectory(prefix="raptor-uscope-")
        self.addCleanup(self._out.cleanup)
        self.out = os.path.realpath(self._out.name)

    def _host_listener(self, name="hostsock"):
        path = os.path.join(self.out, name)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(path)
        srv.listen(4)
        srv.settimeout(0.5)
        self.addCleanup(srv.close)
        return path, srv

    def _spawn(self, prog, *, block_network=True, **overrides):
        from core.sandbox._spawn import run_sandboxed
        kw = dict(_SPAWN_DEFAULTS)
        kw.update(overrides)
        return run_sandboxed(
            ["/usr/bin/python3", "-c", prog],
            target=self.out, output=self.out,
            block_network=block_network,
            writable_paths=[self.out, "/tmp"],
            **kw,
        )

    def _accepted(self, srv) -> bool:
        try:
            conn, _ = srv.accept()
            conn.close()
            return True
        except (TimeoutError, OSError):
            return False


class TestHostSocketInOutputDenied(_Base):
    _CONNECT = textwrap.dedent("""
        import errno, socket, sys
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.connect(sys.argv[1] if len(sys.argv) > 1 else {path!r})
            print("CONNECTED")
        except OSError as e:
            print("DENIED", e.errno)
    """)

    def test_enforcement_child_cannot_reach_host_socket_in_output(self):
        """b4-audit-unix-enforce shape."""
        path, srv = self._host_listener()
        r = self._spawn(self._CONNECT.format(path=path))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DENIED", r.stdout,
                      f"child connected to a host socket in the rw "
                      f"output bind: {r.stdout!r}")
        self.assertFalse(self._accepted(srv),
                         "host listener accepted a connection from the "
                         "sandboxed child")

    def test_host_netns_posture_also_denied(self):
        """b10-path-targetrun shape (block_network=False → host netns)."""
        path, srv = self._host_listener("hostsock-tr")
        r = self._spawn(self._CONNECT.format(path=path),
                        block_network=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DENIED", r.stdout, r.stdout)
        self.assertFalse(self._accepted(srv))

    def test_seqpacket_variant_denied(self):
        path, srv = self._host_listener("hostsock-sq")
        srv2path = os.path.join(self.out, "hostsock-sq2")
        srv2 = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        srv2.bind(srv2path)
        srv2.listen(1)
        srv2.settimeout(0.5)
        self.addCleanup(srv2.close)
        prog = textwrap.dedent(f"""
            import socket
            s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            try:
                s.connect({srv2path!r})
                print("CONNECTED")
            except OSError as e:
                print("DENIED", e.errno)
        """)
        r = self._spawn(prog)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DENIED", r.stdout, r.stdout)

    def test_symlink_bounce_from_private_tmp_denied(self):
        """Child plants /tmp/link -> <output>/hostsock and connects the
        link — the supervisor must refuse symlinked paths."""
        path, srv = self._host_listener("hostsock-sym")
        prog = textwrap.dedent(f"""
            import os, socket
            os.symlink({path!r}, "/tmp/bounce")
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.connect("/tmp/bounce")
                print("CONNECTED")
            except OSError as e:
                print("DENIED", e.errno)
        """)
        r = self._spawn(prog)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DENIED", r.stdout, r.stdout)
        self.assertFalse(self._accepted(srv))

    def test_unix_dgram_socket_denied(self):
        prog = textwrap.dedent("""
            import socket
            try:
                socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                print("CREATED")
            except OSError as e:
                print("DENIED", e.errno)
        """)
        r = self._spawn(prog)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DENIED", r.stdout,
                      f"AF_UNIX SOCK_DGRAM must be denied under connect "
                      f"scoping (sendto-with-address bypass): {r.stdout!r}")


class TestLegitimateUsesKeepWorking(_Base):
    def test_private_tmp_bind_and_connect(self):
        """Forkserver shape: bind + connect inside the sandbox-private
        /tmp must work."""
        prog = textwrap.dedent("""
            import socket
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind("/tmp/fs-listener")
            srv.listen(1)
            c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            c.connect("/tmp/fs-listener")
            conn, _ = srv.accept()
            c.sendall(b"ping")
            print("OK", conn.recv(4).decode())
        """)
        r = self._spawn(prog)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("OK ping", r.stdout,
                      f"private-tmpfs unix IPC must keep working under "
                      f"connect scoping: {r.stdout!r} {r.stderr!r}")

    def test_loopback_tcp_still_works(self):
        """TCP connects are executed on the child's behalf — semantics
        must be unchanged (netns loopback self-connect)."""
        prog = textwrap.dedent("""
            import socket
            srv = socket.socket()
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            port = srv.getsockname()[1]
            c = socket.socket()
            c.settimeout(10)
            c.connect(("127.0.0.1", port))
            conn, _ = srv.accept()
            c.sendall(b"tcp!")
            print("OK", conn.recv(4).decode())
        """)
        r = self._spawn(prog)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("OK tcp!", r.stdout, f"{r.stdout!r} {r.stderr!r}")

    def test_socketpair_untouched(self):
        prog = textwrap.dedent("""
            import socket
            a, b = socket.socketpair()
            a.sendall(b"sp")
            print("OK", b.recv(2).decode())
        """)
        r = self._spawn(prog)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("OK sp", r.stdout)


class TestFailClosedDowngrade(unittest.TestCase):
    def test_af_unix_blocked_when_supervisor_unavailable(self):
        if not _mount_ns_usable():
            self.skipTest("mount-ns unusable here")
        out = tempfile.TemporaryDirectory(prefix="raptor-uscope-dg-")
        self.addCleanup(out.cleanup)
        prog = textwrap.dedent("""
            import socket
            try:
                socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                print("CREATED")
            except OSError as e:
                print("DENIED", e.errno)
        """)
        from core.sandbox._spawn import run_sandboxed
        with patch("core.sandbox._unix_scope.probe_unix_scope",
                   return_value=False):
            r = run_sandboxed(
                ["/usr/bin/python3", "-c", prog],
                target=out.name, output=out.name,
                block_network=True,
                writable_paths=[out.name, "/tmp"],
                **_SPAWN_DEFAULTS,
            )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DENIED", r.stdout,
                      "with the supervisor unavailable, AF_UNIX must "
                      "stay blocked (fail-closed)")


if __name__ == "__main__":
    unittest.main()
