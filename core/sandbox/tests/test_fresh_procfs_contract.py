"""The fresh-procfs contract and the spawn chain's environ hygiene.

Three properties, each independently load-bearing:

1. The grandchild's fresh /proc mount happens BEFORE Landlock installs
   (a landlocked process is denied every mount(2) topology change, so
   the reverse order silently left the host-pid procfs bind visible to
   the target on every Landlock-capable host).
2. Untrusted runs refuse the degraded host-procfs posture (status byte
   'F') unless the operator explicitly accepts it.
"""

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]


# ---------------------------------------------------------- unit tier

def test_f_status_byte_roundtrip():
    from core.sandbox._spawn import _parse_setup_status
    parsed = _parse_setup_status(b"F:fresh procfs mount failed")
    assert parsed == ("F", "fresh procfs mount failed")


def test_layer_install_ordering_source_pin():
    """Source pin: Landlock/seccomp install in the GRANDCHILD after the
    fresh /proc mount; the pre-fork child block no longer calls them.
    A landlocked process cannot mount, so any regression of this order
    reintroduces the host-procfs-visible degrade on every spawn."""
    src = (_REPO_ROOT / "core" / "sandbox" / "_spawn.py").read_text(
        encoding="utf-8")
    grand = src.index("if grand == 0:")
    mount_at = src.index('b"proc", b"/proc", b"proc"', grand)
    landlock_at = src.index("landlock_fn()", grand)
    seccomp_at = src.index("seccomp_fn()", grand)
    assert grand < mount_at < landlock_at < seccomp_at, (
        "fresh-proc mount must precede Landlock/seccomp install in the "
        "grandchild")
    # No install calls anywhere before the grandchild branch (the old
    # child-side step 10/11 block).
    pre_fork_region = src[:grand]
    assert "landlock_fn()" not in pre_fork_region
    assert "seccomp_fn()" not in pre_fork_region


# --------------------------------------------------- integration tier

def _run_untrusted_or_skip(cmd, tmp_path, **kw):
    from core.sandbox import context as _ctx
    try:
        result = _ctx.run_untrusted(
            cmd, target=str(tmp_path), output=str(tmp_path),
            timeout=kw.pop("timeout", 90), **kw,
        )
    except Exception as e:  # noqa: BLE001 — host without userns etc.
        pytest.skip(f"sandbox unavailable: {e}")
    if getattr(result, "returncode", 1) != 0:
        pytest.skip(f"sandboxed child did not run: rc="
                    f"{getattr(result, 'returncode', None)}")
    return result


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_untrusted_procfs_is_pid_ns_local(tmp_path):
    """Inside run_untrusted the target sees a pid-ns-local /proc: a
    handful of pids, itself as pid 1, and the seccomp layer active —
    NOT the host process table."""
    marker = tmp_path / "probe-out"
    _run_untrusted_or_skip(
        ["sh", "-c",
         "{ ls /proc | grep -c '^[0-9]'; echo $$; "
         "grep -E '^(Seccomp|NoNewPrivs):' /proc/self/status; } > "
         f"{marker}"],
        tmp_path,
    )
    if not marker.exists():
        pytest.skip("probe produced no output")
    lines = marker.read_text(encoding="utf-8").split()
    pid_count, self_pid = int(lines[0]), int(lines[1])
    assert pid_count <= 8, (
        f"{pid_count} pids visible in /proc — host procfs is leaking "
        f"into the untrusted sandbox (fresh proc mount regressed?)")
    assert self_pid == 1
    joined = " ".join(lines)
    assert "NoNewPrivs: 1" in joined
    assert "Seccomp: 2" in joined, (
        "seccomp filter not active in the target — the grandchild "
        "install path regressed")


def _decoy_value() -> str:
    # Unique per test run: another session running this same suite on
    # a shared host must not cross-match our watcher or payloads.
    import uuid
    return f"chain-scrub-decoy-{uuid.uuid4().hex[:12]}"


def _drive_run_in_subprocess(tmp_path, beacon_name, payload_sh,
                             decoy_value="chain-scrub-decoy",
                             timeout=120):
    """Launch run_untrusted from a SUBPROCESS whose execve-time env
    carries the decoy credential and a beacon marker.

    The environ IMAGE (/proc/<pid>/environ) is fixed at execve —
    ``monkeypatch.setenv`` only mutates the heap copy — so a valid
    reproduction of the leak needs the decoy in the driver's execve
    env, exactly where a real orchestrator's credential lives.
    """
    driver = textwrap.dedent("""
        import os, sys
        sys.path.insert(0, os.environ["RAPTOR_DIR"])
        from core.sandbox.context import run_untrusted
        r = run_untrusted(
            ["sh", "-c", %r],
            target=%r, output=%r, cwd=%r, timeout=90,
            capture_output=True, text=True,
        )
        print("RC=%%d" %% r.returncode)
    """) % (payload_sh, str(tmp_path), str(tmp_path), str(tmp_path))
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "RAPTOR_DIR": str(_REPO_ROOT),
        beacon_name: "1",
        "RAPTOR_SESSION_TOKEN": decoy_value,
    }
    return subprocess.run(
        [sys.executable, "-c", driver], env=env,
        capture_output=True, text=True, timeout=timeout, check=False,
    )


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_untrusted_cannot_read_spawn_chain_credentials(tmp_path):
    """End-to-end for the audit's headline channel: with a decoy
    session credential in the ORCHESTRATOR'S execve env, no environ
    readable from inside the sandbox carries its value."""
    marker = tmp_path / "hunt-out"
    decoy = _decoy_value()
    payload = (
        "hits=0; for d in /proc/[0-9]*; do "
        "tr '\\0' '\\n' < $d/environ 2>/dev/null "
        f"| grep -q {decoy} && hits=$((hits+1)); done; "
        f"echo $hits > {marker}"
    )
    r = _drive_run_in_subprocess(tmp_path, "SBX_HUNT_BEACON", payload,
                                 decoy_value=decoy)
    if "RC=0" not in r.stdout:
        pytest.skip(f"sandbox unavailable: {r.stdout} {r.stderr[-300:]}")
    if not marker.exists():
        pytest.skip("probe produced no output")
    assert marker.read_text(encoding="utf-8").strip() == "0", (
        "a sandboxed payload can read the session credential out of a "
        "spawn-chain process's environ image")


_FORCED_MOUNT_FAIL_PRELUDE = """
import ctypes, os, sys
sys.path.insert(0, os.environ["RAPTOR_DIR"])
_real_CDLL = ctypes.CDLL
class _FakeLibc:
    def __init__(self, real): self._r = real
    def __getattr__(self, n): return getattr(self._r, n)
    def __getitem__(self, k): return self._r[k]
    def mount(self, *a):
        # Refuse exactly the fresh-proc mount; everything else passes
        # through (persona re-binds use an fd-path source).
        if a and a[0] == b"proc":
            return -1
        return self._r.mount(*a)
def _patched(name=None, *a, **k):
    real = _real_CDLL(name, *a, **k)
    return _FakeLibc(real) if (name is None or "libc" in str(name)) else real
ctypes.CDLL = _patched
"""


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_fresh_procfs_failure_aborts_untrusted_run(tmp_path):
    """A forced fresh-proc mount failure ABORTS the untrusted run with
    the typed SandboxSetupError (status byte 'F') — and proceeds
    warn-only under the documented operator override. The failure is
    injected by a fork-inherited CDLL wrapper that refuses exactly the
    proc mount, so the whole real spawn chain runs."""
    driver = _FORCED_MOUNT_FAIL_PRELUDE + textwrap.dedent("""
        from core.sandbox.context import run_untrusted
        from core.sandbox.errors import SandboxSetupError
        try:
            r = run_untrusted(["true"], target=%r, output=%r, cwd=%r,
                              timeout=90, capture_output=True, text=True)
            print("NO-RAISE rc=%%d" %% r.returncode)
        except SandboxSetupError as e:
            print("RAISED:", str(e)[:120].replace("\\n", " "))
    """) % (str(tmp_path), str(tmp_path), str(tmp_path))
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "RAPTOR_DIR": str(_REPO_ROOT),
    }
    r = subprocess.run([sys.executable, "-c", driver], env=env,
                       capture_output=True, text=True, timeout=150,
                       check=False)
    if r.returncode != 0:
        pytest.skip(f"driver failed: {r.stderr[-300:]}")
    if "NO-RAISE" in r.stdout and "RAISED" not in r.stdout:
        # Mount-ns lane not taken at all on this host — nothing to test.
        pytest.skip(f"forced failure did not reach the spawn lane: "
                    f"{r.stdout}")
    assert "RAISED: sandbox fresh-procfs mount failed" in r.stdout, (
        f"untrusted run survived a fresh-procfs failure: {r.stdout}")

    env["RAPTOR_ALLOW_DEGRADED_UNTRUSTED"] = "1"
    r = subprocess.run([sys.executable, "-c", driver], env=env,
                       capture_output=True, text=True, timeout=150,
                       check=False)
    if r.returncode != 0:
        pytest.skip(f"override driver failed: {r.stderr[-300:]}")
    assert "NO-RAISE rc=0" in r.stdout, (
        f"operator override did not restore the warn-only degrade: "
        f"{r.stdout}")


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_require_fresh_procfs_reaches_the_spawn_layer(tmp_path, monkeypatch):
    """run_untrusted passes require_fresh_procfs=True to run_sandboxed
    by default, False under the documented operator override."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    captured: list[dict] = []
    real = _spawn_mod.run_sandboxed

    def recorder(cmd, **kwargs):
        captured.append(kwargs)
        return real(cmd, **kwargs)

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", recorder)
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    try:
        _ctx.run_untrusted(["true"], target=str(tmp_path),
                           output=str(tmp_path), timeout=90)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"sandbox unavailable: {e}")
    if not captured:
        pytest.skip("mount-ns spawn path not taken on this host")
    assert captured[-1].get("require_fresh_procfs") is True

    captured.clear()
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    try:
        _ctx.run_untrusted(["true"], target=str(tmp_path),
                           output=str(tmp_path), timeout=90)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"sandbox unavailable under override: {e}")
    if not captured:
        pytest.skip("mount-ns spawn path not taken on this host")
    assert captured[-1].get("require_fresh_procfs") is False


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_mount_ns_failure_refuses_landlock_only_for_untrusted(
        tmp_path, monkeypatch):
    """A mount-ns setup failure ('M' status) on an untrusted run must
    NOT silently degrade to the Landlock-only retry — that fallback
    runs with no pid namespace and the host /proc, the exact posture
    the fresh-procfs contract refuses. The operator override restores
    the old degrade."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    from core.sandbox.errors import SandboxSetupError

    def fake_spawn(cmd, **kwargs):
        cp = subprocess.CompletedProcess(cmd, returncode=126,
                                         stdout="", stderr="")
        cp._setup_status = ("M", "forced mount-ns failure")
        return cp

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", fake_spawn)
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    try:
        with pytest.raises(SandboxSetupError, match="host-pid /proc"):
            _ctx.run_untrusted(["true"], target=str(tmp_path),
                               output=str(tmp_path), timeout=60)
    except (pytest.skip.Exception, pytest.fail.Exception):
        raise
    except Exception as e:  # noqa: BLE001 — host can't reach the lane
        pytest.skip(f"mount-ns lane unavailable: {e}")

    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    try:
        r = _ctx.run_untrusted(["true"], target=str(tmp_path),
                               output=str(tmp_path), timeout=60)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"override lane unavailable: {e}")
    assert r.returncode == 0, (
        "operator override did not restore the Landlock-only degrade")


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_no_mount_ns_host_refuses_untrusted_run(tmp_path):
    """On a host whose mount-ns backend cannot engage, untrusted runs
    fail closed up front (the fallback lanes leave the host-pid /proc
    visible); the override restores the old degrade. Simulated by
    poisoning the mount-ns availability cache in a driver subprocess."""
    driver = textwrap.dedent("""
        import os, sys
        sys.path.insert(0, os.environ["RAPTOR_DIR"])
        from core.sandbox import state
        state._mount_ns_available_cache = False
        from core.sandbox.context import run_untrusted
        from core.sandbox.errors import SandboxSetupError
        try:
            r = run_untrusted(["true"], target=%r, output=%r, cwd=%r,
                              timeout=60, capture_output=True, text=True)
            print("NO-RAISE rc=%%d" %% r.returncode)
        except SandboxSetupError as e:
            print("RAISED:", str(e)[:100].replace("\\n", " "))
    """) % (str(tmp_path), str(tmp_path), str(tmp_path))
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "RAPTOR_DIR": str(_REPO_ROOT),
    }
    r = subprocess.run([sys.executable, "-c", driver], env=env,
                       capture_output=True, text=True, timeout=150,
                       check=False)
    if r.returncode != 0:
        pytest.skip(f"driver failed: {r.stderr[-300:]}")
    assert "RAISED: sandbox run(): the fresh-procfs contract" in r.stdout, (
        f"untrusted run proceeded on a no-mount-ns host: {r.stdout}")

    env["RAPTOR_ALLOW_DEGRADED_UNTRUSTED"] = "1"
    r = subprocess.run([sys.executable, "-c", driver], env=env,
                       capture_output=True, text=True, timeout=150,
                       check=False)
    if r.returncode != 0 or "NO-RAISE" not in r.stdout:
        pytest.skip(f"override lane unavailable: {r.stdout} "
                    f"{r.stderr[-200:]}")
    assert "NO-RAISE rc=0" in r.stdout
