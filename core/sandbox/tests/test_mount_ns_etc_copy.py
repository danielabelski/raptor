"""_copy_etc_tree: the etc_overlay tmpfs+copy helper.

Regression targets: the helper (formerly ``_copy_dir_shallow`` — a
misnomer, it was always recursive) flattened permissions to 0644/0755,
turning group/other-restricted host /etc files into world-readable
copies inside the sandbox. Mode bits are now preserved on both the
byte-copy and mkdir paths (the hard-link fast path shares the source
inode and preserves them inherently)."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from core.sandbox.mount_ns import _copy_etc_tree


@pytest.fixture(autouse=True)
def hostile_umask():
    """Force a restrictive umask for every test in this file.

    Mode preservation must hold under ANY runner umask: mkfifo(2)'s
    and mkdir(2)'s mode arguments are umask-masked, so a permissive
    local umask (e.g. 0o002) hides a missing chmod that a CI umask
    of 0o022 — or a paranoid 0o077 — exposes. Pinning the harshest
    common value makes the assertions deterministic everywhere.
    """
    old = os.umask(0o077)
    try:
        yield
    finally:
        os.umask(old)


@pytest.fixture
def src_tree(tmp_path):
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    f = src / "restricted.conf"
    f.write_text("secret=1\n")
    os.chmod(f, 0o640)
    g = src / "sub" / "open.conf"
    g.write_text("x=1\n")
    os.chmod(g, 0o644)
    os.chmod(src / "sub", 0o750)
    (src / "link.conf").symlink_to("restricted.conf")
    return src


def _copy(monkeypatch, src, dst, *, force_byte_copy):
    if force_byte_copy:
        def _no_link(*a, **k):
            raise OSError("cross-device")
        monkeypatch.setattr(os, "link", _no_link)
    dst.mkdir()
    _copy_etc_tree(str(src), str(dst))


@pytest.mark.parametrize("force_byte_copy", [True, False])
def test_mode_bits_preserved(tmp_path, monkeypatch, src_tree,
                             force_byte_copy):
    dst = tmp_path / f"dst-{force_byte_copy}"
    _copy(monkeypatch, src_tree, dst, force_byte_copy=force_byte_copy)

    assert (dst / "restricted.conf").read_text() == "secret=1\n"
    assert stat.S_IMODE(
        os.lstat(dst / "restricted.conf").st_mode) == 0o640
    assert stat.S_IMODE(
        os.lstat(dst / "sub" / "open.conf").st_mode) == 0o644
    assert stat.S_IMODE(os.lstat(dst / "sub").st_mode) == 0o750


def test_symlinks_recreated_as_symlinks(tmp_path, monkeypatch, src_tree):
    dst = tmp_path / "dst"
    _copy(monkeypatch, src_tree, dst, force_byte_copy=True)
    link = dst / "link.conf"
    assert link.is_symlink()
    assert os.readlink(link) == "restricted.conf"


def test_fifo_never_wedges_the_copy(tmp_path, monkeypatch, src_tree):
    """A FIFO in /etc must not block the copy: the destination is a
    fresh tmpfs, so the hard-link fast path always fails EXDEV and the
    byte-copy fallback used to open(2) the FIFO — blocking forever
    when it has no writer, wedging sandbox setup until the caller's
    timeout. FIFOs are recreated with mkfifo instead."""
    import threading

    fifo_src = src_tree / "wedge.fifo"
    os.mkfifo(fifo_src)
    os.chmod(fifo_src, 0o620)  # exact source mode, umask-independent
    dst = tmp_path / "dst"

    done = threading.Event()

    def _run():
        _copy(monkeypatch, src_tree, dst, force_byte_copy=True)
        done.set()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    assert done.wait(10), "_copy_etc_tree blocked on the FIFO"

    fifo = dst / "wedge.fifo"
    assert stat.S_ISFIFO(os.lstat(fifo).st_mode)
    assert stat.S_IMODE(os.lstat(fifo).st_mode) == 0o620
    # The rest of the tree still copied.
    assert (dst / "restricted.conf").read_text() == "secret=1\n"


def test_socket_entries_skipped_silently(tmp_path, monkeypatch):
    """Unix sockets in /etc cannot be copied or usefully recreated —
    they must be skipped, never opened.

    The socket is bound in a short mkdtemp under /tmp rather than in
    pytest's tmp_path: struct sockaddr_un's sun_path is 104 bytes on
    macOS/BSD and 108 on Linux (NUL included), and macOS runners'
    per-user tmp trees (/private/var/folders/...) blow that budget —
    bind() fails "AF_UNIX path too long". Same short-base approach as
    core/sandbox/proxy.py make_lane_dir.
    """
    import shutil
    import socket as socket_mod
    import tempfile

    base = tempfile.mkdtemp(prefix=".raptor-etc-", dir="/tmp")
    try:
        src = Path(base) / "src"
        src.mkdir()
        (src / "regular.conf").write_text("x=1\n")
        sock_path = src / "agent.sock"
        # Belt-and-braces: /tmp/.raptor-etc-XXXXXXXX/src/agent.sock is
        # ~40 bytes, comfortably inside both platforms' budgets.
        assert len(str(sock_path).encode()) <= 100, (
            f"socket path {sock_path} exceeds the 100-byte sun_path "
            f"budget; short-base construction is broken"
        )
        s = socket_mod.socket(socket_mod.AF_UNIX, socket_mod.SOCK_STREAM)
        s.bind(str(sock_path))
        try:
            dst = tmp_path / "dst"
            _copy(monkeypatch, src, dst, force_byte_copy=True)
            assert not (dst / "agent.sock").exists()
            assert (dst / "regular.conf").exists()
        finally:
            s.close()
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_unreadable_entries_skipped_silently(tmp_path, monkeypatch,
                                             src_tree):
    if os.geteuid() == 0:
        pytest.skip("root reads anything; unreadable fixture is moot")
    shadow = src_tree / "shadow"
    shadow.write_text("root:!:19000\n")
    os.chmod(shadow, 0o000)
    dst = tmp_path / "dst"
    _copy(monkeypatch, src_tree, dst, force_byte_copy=True)
    assert not (dst / "shadow").exists()
    # The rest of the tree still copied.
    assert (dst / "restricted.conf").exists()
