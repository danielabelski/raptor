"""Loader-variable quarantine for launcher-carrying sandbox paths.

The unshare/pid1-shim chain and the seatbelt shim must never exec
with live loader variables (``LD_*`` / ``DYLD_*`` / ``GCONV_PATH`` /
``GLIBC_TUNABLES``) from a caller-supplied env dict — those are
quarantined into ``_RAPTOR_ENV_RESTORE`` and re-applied by the shim
at target exec, so the TARGET's effective env is unchanged while the
trusted bootstrap runs clean.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from core.sandbox import context as _ctx
from core.sandbox._env_quarantine import (
    ENV_RESTORE_KEY,
    quarantine_loader_env,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
SHIM_PATH = _REPO_ROOT / "libexec" / "raptor-pid1-shim"


def _require_sandbox():
    if sys.platform != "linux":
        pytest.skip("Linux-only sandbox internals")
    from core.sandbox import check_net_available
    if not check_net_available():
        pytest.skip("User namespaces not available")


def _require_shim():
    if sys.platform != "linux":
        pytest.skip("Linux-only pid1 shim")
    if not SHIM_PATH.is_file() or not os.access(SHIM_PATH, os.X_OK):
        pytest.skip(f"shim missing/not executable: {SHIM_PATH}")


# ─── quarantine helper (pure unit) ──────────────────────────────────


class TestQuarantineLoaderEnv:
    def test_loader_vars_moved_to_payload(self):
        env = {
            "PATH": "/usr/bin",
            "LD_PRELOAD": "/x/evil.so",
            "LD_LIBRARY_PATH": "/x/lib",
            "DYLD_INSERT_LIBRARIES": "/x/evil.dylib",
            "GCONV_PATH": "/x/gconv",
            "GLIBC_TUNABLES": "glibc.malloc.check=1",
        }
        out = quarantine_loader_env(env)
        assert out["PATH"] == "/usr/bin"
        for k in ("LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
                  "GCONV_PATH", "GLIBC_TUNABLES"):
            assert k not in out, f"{k} still live in launcher env"
        restored = json.loads(out[ENV_RESTORE_KEY])
        assert restored["LD_PRELOAD"] == "/x/evil.so"
        assert restored["GLIBC_TUNABLES"] == "glibc.malloc.check=1"
        assert len(restored) == 5

    def test_no_loader_vars_no_payload_key(self):
        out = quarantine_loader_env({"PATH": "/usr/bin", "HOME": "/h"})
        assert ENV_RESTORE_KEY not in out
        assert out == {"PATH": "/usr/bin", "HOME": "/h"}

    def test_caller_supplied_restore_key_dropped_never_merged(self):
        env = {
            ENV_RESTORE_KEY: json.dumps({"LD_PRELOAD": "/attacker.so"}),
            "PATH": "/usr/bin",
        }
        out = quarantine_loader_env(env)
        assert ENV_RESTORE_KEY not in out

    def test_caller_restore_key_dropped_even_with_loader_vars(self):
        env = {
            ENV_RESTORE_KEY: json.dumps({"LD_PRELOAD": "/attacker.so"}),
            "LD_LIBRARY_PATH": "/legit",
        }
        out = quarantine_loader_env(env)
        restored = json.loads(out[ENV_RESTORE_KEY])
        assert restored == {"LD_LIBRARY_PATH": "/legit"}

    def test_input_dict_not_mutated(self):
        env = {"LD_PRELOAD": "/x.so", "PATH": "/usr/bin"}
        snapshot = dict(env)
        quarantine_loader_env(env)
        assert env == snapshot


# ─── pid1 shim restore semantics (direct, no namespaces needed) ─────


class TestShimEnvRestore:
    def _probe(self, *names: str) -> str:
        prints = ";".join(
            f"print({n!r} + '=' + os.environ.get({n!r}, '<unset>'))"
            for n in names
        )
        return f"import os;{prints}"

    def _run_shim(self, probe: str, env: dict, *flags: str):
        return subprocess.run(
            [str(SHIM_PATH), *flags, sys.executable, "-c", probe],
            capture_output=True, text=True, timeout=10,
            env=env,
        )

    def test_restore_reapplies_loader_vars_at_target_exec(self):
        _require_shim()
        payload = json.dumps({"LD_LIBRARY_PATH": "/quarantine-marker"})
        r = self._run_shim(
            self._probe("LD_LIBRARY_PATH", ENV_RESTORE_KEY),
            dict(os.environ, _RAPTOR_TRUSTED="1",
                 **{ENV_RESTORE_KEY: payload}),
        )
        assert r.returncode == 0, r.stderr
        assert "LD_LIBRARY_PATH=/quarantine-marker" in r.stdout
        assert f"{ENV_RESTORE_KEY}=<unset>" in r.stdout, (
            "the restore payload key itself leaked into the target env"
        )

    def test_restore_rejects_non_loader_keys(self):
        _require_shim()
        payload = json.dumps({"PATH": "/evil", "LD_AUDIT": "/ok.so"})
        r = self._run_shim(
            self._probe("PATH", "LD_AUDIT"),
            dict(os.environ, _RAPTOR_TRUSTED="1",
                 **{ENV_RESTORE_KEY: payload}),
        )
        assert r.returncode == 0, r.stderr
        assert "PATH=/evil" not in r.stdout, (
            "restore payload must not overwrite non-loader variables"
        )
        assert "LD_AUDIT=/ok.so" in r.stdout

    def test_malformed_restore_payload_tolerated(self):
        _require_shim()
        r = self._run_shim(
            self._probe(ENV_RESTORE_KEY),
            dict(os.environ, _RAPTOR_TRUSTED="1",
                 **{ENV_RESTORE_KEY: "not-json{"}),
        )
        assert r.returncode == 0, r.stderr
        assert f"{ENV_RESTORE_KEY}=<unset>" in r.stdout




@pytest.mark.integration
def test_caller_loader_var_reaches_target_not_lost(tmp_path):
    """Quarantine must be transparent to the TARGET: a caller-supplied
    loader variable survives the round trip on every backend (on the
    shim path via _RAPTOR_ENV_RESTORE, on direct paths verbatim).

    Uses plain run() — run_untrusted's strict_env contract strips
    loader vars outright (by design, covered elsewhere); intentional
    loader vars are a plain-run capability."""
    _require_sandbox()
    from core.config import RaptorConfig
    env_bin = shutil.which("env") or "/usr/bin/env"
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    caller_env = dict(RaptorConfig.get_safe_env())
    caller_env["LD_LIBRARY_PATH"] = "/quarantine-marker"
    result = _ctx.run(
        [env_bin],
        block_network=True,
        output=str(out_dir),
        env=caller_env, env_caller_filtered=True,
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, (
        f"env exited {result.returncode}: {result.stderr!r}"
    )
    assert "LD_LIBRARY_PATH=/quarantine-marker" in result.stdout, (
        "caller loader var lost in the quarantine round trip"
    )
    assert f"{ENV_RESTORE_KEY}=" not in result.stdout, (
        "restore payload key leaked into the target env"
    )

# ─── wiring: the launcher must actually receive the quarantined view ─


@pytest.mark.integration
def test_launcher_env_has_no_live_loader_vars(monkeypatch, tmp_path):
    """The core wiring property behind this module: on the shim-bearing
    subprocess path, the env handed to the launcher chain (captured at
    the run_landlock_audit / subprocess.run boundary) carries NO live
    loader variables — they travel only inside the restore payload.
    Without this pin, dropping either _quarantine_loader_env call site
    in context.run() would reopen loader injection into the bootstrap
    with a green suite."""
    _require_sandbox()
    from core.config import RaptorConfig
    from core.sandbox import _landlock_audit as _la_mod
    from core.sandbox import _spawn as _spawn_mod

    captured: dict[str, dict] = {}

    def no_spawn(*a, **k):
        raise FileNotFoundError("forced: subprocess path only in this test")

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", no_spawn)

    real_lla = _la_mod.run_landlock_audit

    def lla_spy(cmd, **kw):
        if isinstance(cmd, list) and any(
            "raptor-pid1-shim" in str(c) for c in cmd
        ):
            captured.setdefault("launcher_env", kw.get("env"))
        return real_lla(cmd, **kw)

    monkeypatch.setattr(_la_mod, "run_landlock_audit", lla_spy)

    real_run = subprocess.run

    def run_spy(cmd, **kw):
        if isinstance(cmd, list) and any(
            "raptor-pid1-shim" in str(c) for c in cmd
        ):
            captured.setdefault("launcher_env", kw.get("env"))
        return real_run(cmd, **kw)

    monkeypatch.setattr(_ctx.subprocess, "run", run_spy)

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    caller_env = dict(RaptorConfig.get_safe_env())
    caller_env["LD_LIBRARY_PATH"] = "/quarantine-marker"
    caller_env["GLIBC_TUNABLES"] = "glibc.malloc.check=0"
    result = _ctx.run(
        ["/usr/bin/env"],
        block_network=True,
        output=str(out_dir),
        env=caller_env, env_caller_filtered=True,
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    launcher_env = captured.get("launcher_env")
    assert launcher_env is not None, (
        "no shim-bearing launcher exec observed — path forcing failed"
    )
    assert "LD_LIBRARY_PATH" not in launcher_env, (
        "live loader var reached the launcher chain"
    )
    assert "GLIBC_TUNABLES" not in launcher_env, (
        "live GLIBC_TUNABLES reached the launcher chain"
    )
    payload = json.loads(launcher_env[ENV_RESTORE_KEY])
    assert payload["LD_LIBRARY_PATH"] == "/quarantine-marker"
    assert payload["GLIBC_TUNABLES"] == "glibc.malloc.check=0"


# ─── allowlist parity: quarantined names must all be restorable ──────


class TestQuarantineRestoreParity:
    """The loader-name allowlist exists in three copies (module + two
    -I shims that cannot import it). A name that quarantines but does
    not restore silently deletes the variable from the target env —
    this drives the pid1 shim with every module-truth name and one
    representative per prefix."""

    def test_pid1_shim_restores_every_quarantined_name(self):
        _require_shim()
        from core.sandbox._env_quarantine import _LOADER_EXACT
        names = sorted(_LOADER_EXACT) + ["LD_PRELOAD_X", "DYLD_X"]
        payload = json.dumps({n: f"/pv/{n}" for n in names})
        prints = ";".join(
            f"print({n!r} + '=' + os.environ.get({n!r}, '<unset>'))"
            for n in names
        )
        r = subprocess.run(
            [str(SHIM_PATH), sys.executable, "-c", f"import os;{prints}"],
            capture_output=True, text=True, timeout=10,
            env=dict(os.environ, _RAPTOR_TRUSTED="1",
                     **{ENV_RESTORE_KEY: payload}),
        )
        assert r.returncode == 0, r.stderr
        for n in names:
            assert f"{n}=/pv/{n}" in r.stdout, (
                f"{n} quarantined but not restored by the pid1 shim"
            )
