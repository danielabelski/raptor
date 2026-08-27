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

import pytest

from core.sandbox.mount_ns import _copy_etc_tree


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

    os.mkfifo(src_tree / "wedge.fifo", 0o620)
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


def test_socket_entries_skipped_silently(tmp_path, monkeypatch,
                                         src_tree):
    """Unix sockets in /etc cannot be copied or usefully recreated —
    they must be skipped, never opened."""
    import socket as socket_mod

    s = socket_mod.socket(socket_mod.AF_UNIX, socket_mod.SOCK_STREAM)
    s.bind(str(src_tree / "agent.sock"))
    try:
        dst = tmp_path / "dst"
        _copy(monkeypatch, src_tree, dst, force_byte_copy=True)
        assert not (dst / "agent.sock").exists()
        assert (dst / "restricted.conf").exists()
    finally:
        s.close()


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
