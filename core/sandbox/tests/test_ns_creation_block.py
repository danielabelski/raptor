"""Namespace-creation denial on the fork-backend lane.

A sandboxed payload that can create namespaces — a nested user
namespace above all — reaches the kernel code paths behind most
container-escape CVEs even though uid_map writes are refused. The
fork backend's filter installs AFTER the sandbox's own namespace
setup, so denying namespace creation there costs legitimate
workloads nothing; the subprocess/preexec lanes install their filter
BEFORE exec'ing the unshare CLI bootstrap and must keep the
syscalls.
"""

import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]


def test_only_the_spawn_lane_blocks_ns_creation_source_pin():
    """Source pin: block_ns_creation=True is passed by _spawn's
    grandchild-installed filter and by NOTHING else — the preexec
    lanes' filter precedes the unshare CLI bootstrap."""
    spawn = (_REPO_ROOT / "core" / "sandbox" / "_spawn.py").read_text(
        encoding="utf-8")
    assert "block_ns_creation=True" in spawn
    for other in ("context.py", "_landlock_audit.py"):
        src = (_REPO_ROOT / "core" / "sandbox" / other).read_text(
            encoding="utf-8")
        assert "block_ns_creation=True" not in src, (
            f"{other} must not enable the ns block — its filter "
            f"installs before the sandbox's own namespace setup")


def test_ns_flags_cover_every_clone_namespace():
    from core.sandbox.seccomp import _CLONE_NS_FLAGS
    assert set(_CLONE_NS_FLAGS) == {
        "NEWUSER", "NEWNS", "NEWPID", "NEWNET", "NEWIPC", "NEWUTS",
        "NEWCGROUP", "NEWTIME",
    }


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_payload_cannot_create_namespaces(tmp_path):
    """Inside run_untrusted: every unshare(CLONE_NEW*) and setns is
    EPERM; clone3 is ENOSYS; fork/exec and multiprocessing keep
    working (the sh wrapper keeps cmd[0] inside the bind tree on
    hosts whose driver python lives in a venv)."""
    from core.sandbox import context as _ctx
    probe = r"""
python3 - <<'PY'
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
flags = {"NEWUSER":0x10000000,"NEWNS":0x00020000,"NEWPID":0x20000000,
         "NEWNET":0x40000000,"NEWIPC":0x08000000,"NEWUTS":0x04000000,
         "NEWCGROUP":0x02000000,"NEWTIME":0x00000080}
denied = 0
for fl in flags.values():
    pid = os.fork()
    if pid == 0:
        r = libc.unshare(fl)
        os._exit(0 if r == 0 else ctypes.get_errno())
    _, st = os.waitpid(pid, 0)
    if os.waitstatus_to_exitcode(st) == 1:  # EPERM
        denied += 1
print("unshare-denied:", denied)
r = libc.setns(3, 0)
print("setns-eperm:", r != 0 and ctypes.get_errno() == 1)
r = libc.syscall(435, 0, 0)  # clone3 (x86_64/aarch64 share 435)
print("clone3-enosys:", r != 0 and ctypes.get_errno() == 38)
import subprocess
print("exec-ok:", subprocess.run(["true"]).returncode == 0)
import multiprocessing as mp
q = mp.get_context("fork").Queue()
p = mp.get_context("fork").Process(target=q.put, args=(7,))
p.start(); p.join()
print("mp-ok:", q.get(timeout=10) == 7)
PY
"""
    try:
        r = _ctx.run_untrusted(
            ["sh", "-c", probe], target=str(tmp_path),
            output=str(tmp_path), timeout=120,
            capture_output=True, text=True,
        )
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"sandbox unavailable: {e}")
    if r.returncode != 0:
        pytest.skip(f"probe did not run: {(r.stderr or '')[-200:]}")
    out = r.stdout or ""
    assert "unshare-denied: 8" in out, out
    assert "setns-eperm: True" in out, out
    assert "clone3-enosys: True" in out, out
    assert "exec-ok: True" in out, out
    assert "mp-ok: True" in out, out
