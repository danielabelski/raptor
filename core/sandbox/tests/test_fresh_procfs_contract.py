"""The fresh-procfs contract and the spawn chain's environ hygiene.

Three properties, each independently load-bearing:

1. The grandchild's fresh /proc mount happens BEFORE Landlock installs
   (a landlocked process is denied every mount(2) topology change, so
   the reverse order silently left the host-pid procfs bind visible to
   the target on every Landlock-capable host).
2. Untrusted runs refuse the degraded host-procfs posture (status byte
   'F') unless the operator explicitly accepts it.
3. The spawn chain's un-exec'd forks scrub the sensitive values from
   their inherited environ image — the image is the orchestrator's
   full pre-strip environment, and same-userns readers pass the
   kernel's ptrace gate on any lane where host procfs stays visible.
"""

import os
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]


# ---------------------------------------------------------- unit tier

def test_f_status_byte_roundtrip():
    from core.sandbox._spawn import _parse_setup_status
    parsed = _parse_setup_status(b"F:fresh procfs mount failed")
    assert parsed == ("F", "fresh procfs mount failed")


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="scrubs the /proc/self/environ image — Linux procfs only",
)
def test_scrub_env_image_values_zeroes_only_named_values():
    """The helper zeroes the named variables' VALUES in the execve-time
    environ image (what /proc/<pid>/environ serves) and touches nothing
    else. Runs in a subprocess so the image is fully controlled."""
    code = textwrap.dedent("""
        import os, sys
        sys.path.insert(0, %r)
        from core.sandbox._spawn import _scrub_env_image_values
        _scrub_env_image_values((b"SCRUB_ME", b"SCRUB_ME_TOO"))
        img = open("/proc/self/environ", "rb").read()
        entries = [e for e in img.split(b"\\0") if e]
        by_name = dict(e.split(b"=", 1) for e in entries if b"=" in e)
        assert by_name[b"SCRUB_ME"].strip(b"\\0") == b"", by_name[b"SCRUB_ME"]
        assert by_name[b"SCRUB_ME_TOO"].strip(b"\\0") == b""
        assert by_name[b"KEEP_ME"] == b"keep-value"
        # PATH must survive untouched — libc consumers keep working.
        assert by_name.get(b"PATH"), "PATH was damaged by the scrub"
        print("scrub-ok")
    """) % str(_REPO_ROOT)
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "SCRUB_ME": "secret-one",
        "SCRUB_ME_TOO": "secret-two",
        "KEEP_ME": "keep-value",
        "RAPTOR_DIR": str(_REPO_ROOT),
    }
    r = subprocess.run(
        [sys.executable, "-c", code], env=env,
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert r.returncode == 0, r.stderr
    assert "scrub-ok" in r.stdout


def test_scrub_names_cover_credentials_and_provider_keys():
    """Source pin: the pre-fork scrub-name computation covers the
    target strip set, the LLM provider credentials, and RAPTOR_DIR."""
    src = (_REPO_ROOT / "core" / "sandbox" / "_spawn.py").read_text(
        encoding="utf-8")
    block = src[src.index("_env_image_scrub_names = tuple"):][:400]
    assert "TARGET_ENV_STRIP_SET" in block
    assert "LLM_API_KEY_VARS" in block
    assert '"RAPTOR_DIR"' in block


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


def test_branded_tmp_regex_copies_in_sync():
    """The branded-temp matcher exists in context.py AND mount_ns.py
    (the mount-ns child cannot import context) — a drift between them
    re-opens either the env value or the replanted directory name."""
    ctx = (_REPO_ROOT / "core" / "sandbox" / "context.py").read_text(
        encoding="utf-8")
    mns = (_REPO_ROOT / "core" / "sandbox" / "mount_ns.py").read_text(
        encoding="utf-8")
    import re as _re
    pat = _re.compile(r"_BRANDED_TMP_RE = re\.compile\((.+)\)")
    m_ctx = pat.search(ctx)
    m_mns = pat.search(mns)
    assert m_ctx and m_mns, "matcher missing from one of the copies"
    assert m_ctx.group(1) == m_mns.group(1), (
        "context.py and mount_ns.py branded-temp matchers drifted")


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


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_spawn_chain_environ_image_is_scrubbed(tmp_path):
    """Mid-run, every beacon-carrying process inside a FOREIGN user
    namespace (= the class a sandboxed same-userns reader could reach)
    must show a ZEROED session-token value in its /proc/<pid>/environ.

    Carriers still in OUR user namespace are excluded: the driver
    itself, pre-unshare setup-child snapshots, and transient
    capability-probe forks are only readable here because this test
    runs unsandboxed — a sandboxed payload is denied their environ by
    the kernel's cross-userns ptrace gate, so they are out of scope
    for the scrub (which runs immediately AFTER unshare, before the
    process becomes same-userns-readable to any target)."""
    import uuid
    beacon = f"SBX_CHAIN_SCRUB_BEACON_{uuid.uuid4().hex[:8].upper()}"
    decoy = _decoy_value()
    my_userns = os.readlink("/proc/self/ns/user")
    seen: dict[str, tuple[str, bytes]] = {}
    stop = threading.Event()

    def watcher() -> None:
        me = str(os.getpid())
        while not stop.is_set():
            for pid in os.listdir("/proc"):
                if not pid.isdigit() or pid == me:
                    continue
                try:
                    with open(f"/proc/{pid}/environ", "rb") as f:
                        img = f.read()
                    userns = os.readlink(f"/proc/{pid}/ns/user")
                except OSError:
                    continue
                if beacon.encode() + b"=1" in img:
                    # Keep the LAST snapshot per pid — the scrub runs
                    # moments after fork+unshare.
                    seen[pid] = (userns, img)
            time.sleep(0.005)

    t = threading.Thread(target=watcher)
    t.start()
    try:
        r = _drive_run_in_subprocess(
            tmp_path, beacon, "sleep 1.5", decoy_value=decoy,
            timeout=150)
    finally:
        stop.set()
        t.join()
    if "RC=0" not in r.stdout:
        pytest.skip(f"sandbox unavailable: {r.stdout} {r.stderr[-300:]}")
    foreign = {pid: img for pid, (ns, img) in seen.items()
               if ns != my_userns}
    if not foreign:
        pytest.skip("no foreign-userns chain process observed")
    leaky = sorted(pid for pid, img in foreign.items()
                   if b"RAPTOR_SESSION_TOKEN=" + decoy.encode() in img)
    assert not leaky, (
        f"spawn-chain forks readable from inside the sandbox still "
        f"publish the session credential: {leaky}")
    for img in foreign.values():
        assert b"RAPTOR_SESSION_TOKEN=" in img, (
            "scrub should empty the value, not remove the name")


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


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_no_branded_names_in_target_view(tmp_path):
    """The target's mount view and env must not name the framework:
    no launcher session-scratch dir replanted in the private /tmp, no
    RAPTOR checkout path bound in (the pid1-shim grant is an
    unshare-lane Landlock rule, not a mount-ns bind), and no
    framework-identity env values."""
    import re as _re
    marker = tmp_path / "brand-probe"
    _run_untrusted_or_skip(
        ["sh", "-c",
         f"{{ ls -a /tmp; echo ---MI---; "
         f"grep -io 'raptor[^ ]*' /proc/self/mountinfo; "
         f"echo ---ENV---; env; }} > {marker}"],
        tmp_path,
    )
    if not marker.exists():
        pytest.skip("probe produced no output")
    text = marker.read_text(encoding="utf-8")
    listing, _, rest = text.partition("---MI---")
    mi_block, _, envblock = rest.partition("---ENV---")
    # The caller-chosen target/output ancestry is target-visible by
    # definition (here: pytest's own basetemp components) — only
    # entries OUTSIDE that ancestry count as leaks.
    own_components = set(tmp_path.parts) | set(Path(__file__).parts)
    hits = [ln for ln in listing.split()
            if _re.search(r"raptor", ln, _re.IGNORECASE)
            and ln not in own_components]
    assert not hits, (
        f"framework-named entries visible in the sandbox /tmp: {hits}")
    mi_hits = [ln for ln in mi_block.split()
               if ln and ln not in own_components
               and not any(c in ln for c in own_components
                           if "raptor" in c.lower())]
    assert not mi_hits, (
        f"framework-named mount sources visible in mountinfo: "
        f"{mi_hits[:6]}")
    for name in ("RAPTOR_DIR=", "RAPTOR_OUT_DIR=", "RAPTOR_TARGET_KIND=",
                 "_RAPTOR_", "CLAUDECODE="):
        assert name not in envblock, (
            f"framework-identity env reached the target: {name}")


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_run_marker_content_masked_in_target_view(tmp_path):
    """.raptor-run.json (RAPTOR git sha, finder identity, target
    provenance, command line) sits inside the rw output bind — the
    child view must serve an empty mask, writes must land on the mask,
    and the real file must stay intact for the parent-side machinery."""
    marker = tmp_path / ".raptor-run.json"
    marker.write_text('{"manifest":{"base_sha":"mask-me-sha"}}',
                      encoding="utf-8")
    probe_out = tmp_path / "probe-out"
    _run_untrusted_or_skip(
        ["sh", "-c",
         f"cat {marker} > {probe_out} 2>&1; "
         f"echo tamper >> {marker} 2>/dev/null || true"],
        tmp_path,
    )
    if not probe_out.exists():
        pytest.skip("probe produced no output")
    assert "mask-me-sha" not in probe_out.read_text(encoding="utf-8"), (
        "run-marker content readable through the output bind")
    real = marker.read_text(encoding="utf-8")
    assert "mask-me-sha" in real and "tamper" not in real, (
        "the real run marker was altered through the child view")
