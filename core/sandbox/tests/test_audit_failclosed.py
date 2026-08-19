"""Fail-closed behaviour of the audit evidence channel.

Pre-fix, ``run(..., audit=True, audit_run_dir=<nonexistent dir>)`` did
not fail: the tracer's ENOENT on ``<dir>/.audit`` was swallowed by the
environmental-degradation excepts, the call cascaded mount-ns →
Landlock-only → bare ``subprocess.run``, and the command executed with
reduced containment and NO audit evidence while the API call looked
successful.

These tests cover the fix layers:

  1. Entry validation — a caller-supplied audit target directory that
     is missing / not a directory / not writable raises ``ValueError``
     before any spawn tier runs (caller-input error, distinct from
     environmental degradation).
  2. Vanished-mid-run — an audit target dir that disappears between
     entry validation and spawn setup raises ``SandboxSetupError``
     instead of riding the degradation ladder.
  3. Evidence bottleneck — legitimate environmental degradation still
     runs the command but always leaves the machine-readable trail
     (``sandbox-audit-degraded.json`` +
     ``sandbox_info["audit_engaged"] is False``), including on the
     runtime-failure paths that previously recorded nothing.

All tests are hermetic: environmental degradation is forced by
monkeypatching the seccomp/ptrace probes and by ``input=`` (which
routes the call off the spawn path), never by relying on host
capabilities.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

from core.sandbox.context import sandbox
from core.sandbox.errors import SandboxSetupError

linux_only = pytest.mark.skipif(
    sys.platform != "linux",
    reason="degradation-ladder paths are Linux-backend specific",
)

MARKER = "sandbox-audit-degraded.json"


@pytest.fixture
def no_audit_tiers(monkeypatch):
    """Force every audit tier off, hermetically.

    The Landlock-only tracer probes are patched at their defining
    modules (context.py imports them inside the function bodies, so
    patching the source modules reaches every call site). The spawn
    tier is avoided per-test by passing ``input=`` — the kwarg-compat
    gate routes such calls off the spawn path on Linux.
    """
    import core.sandbox.ptrace_probe as pp
    import core.sandbox.seccomp as sc
    monkeypatch.setattr(sc, "check_seccomp_available", lambda: False)
    monkeypatch.setattr(pp, "check_ptrace_available", lambda: False)


def _audit_sandbox(audit_dir, **extra):
    return sandbox(
        audit=True, audit_run_dir=str(audit_dir),
        block_network=False, target="/tmp",
        profile="target_run", **extra,
    )


class TestEntryValidation:
    """Layer 1: caller-input errors raise at run() entry."""

    def test_missing_audit_run_dir_raises_and_does_not_execute(
            self, tmp_path):
        proof = tmp_path / "ran"
        with _audit_sandbox(tmp_path / "no-such-dir") as r:
            with pytest.raises(ValueError, match="audit target directory"):
                r(["touch", str(proof)], capture_output=True, timeout=30)
        assert not proof.exists(), (
            "command executed despite the invalid audit target dir — "
            "the fail-open this test exists to prevent"
        )

    def test_audit_run_dir_pointing_at_file_raises(self, tmp_path):
        f = tmp_path / "a-file"
        f.write_text("not a dir")
        with _audit_sandbox(f) as r:
            with pytest.raises(ValueError,
                               match="not an existing directory"):
                r(["true"], capture_output=True, timeout=30)

    @pytest.mark.skipif(os.geteuid() == 0,
                        reason="root bypasses mode-bit write denial")
    def test_unwritable_audit_run_dir_raises(self, tmp_path):
        d = tmp_path / "ro"
        d.mkdir(mode=0o500)
        try:
            with _audit_sandbox(d) as r:
                with pytest.raises(ValueError, match="not writable"):
                    r(["true"], capture_output=True, timeout=30)
        finally:
            d.chmod(0o700)

    def test_output_fallback_audit_target_also_validated(self, tmp_path):
        """audit without audit_run_dir= uses output= as the audit
        target — the same validation must apply to it."""
        with sandbox(audit=True, output=str(tmp_path / "gone"),
                     block_network=False, target="/tmp",
                     profile="target_run") as r:
            with pytest.raises(ValueError,
                               match=r"output \(audit target fallback\)"):
                r(["true"], capture_output=True, timeout=30)

    def test_valid_audit_dir_runs_and_stamps_sandbox_info(self, tmp_path):
        """The legitimate contract (existing writable run dir) is
        unchanged, and the machine-readable per-call record exists."""
        d = tmp_path / "audit"
        d.mkdir()
        with _audit_sandbox(d) as r:
            res = r(["true"], capture_output=True, timeout=60)
        assert res.returncode == 0
        assert isinstance(res.sandbox_info.get("audit_engaged"), bool)

    def test_no_audit_means_no_validation(self, tmp_path):
        """audit_run_dir= without audit engaged is inert (sca passes
        ``audit_run_dir=None if not audit`` but other callers may pass
        the path unconditionally) — must not raise."""
        with sandbox(audit_run_dir=str(tmp_path / "missing"),
                     block_network=False, target="/tmp",
                     profile="target_run") as r:
            res = r(["true"], capture_output=True, timeout=60)
        assert res.returncode == 0


@linux_only
class TestVanishedMidRun:
    """Layer 2: audit dir vanishing after entry validation fails loud."""

    def test_spawn_enoent_with_vanished_dir_raises(
            self, tmp_path, monkeypatch):
        """A FileNotFoundError out of the spawn tier while the audit
        dir is gone must raise SandboxSetupError, not degrade."""
        import shutil

        from core.sandbox import _spawn as spawn_mod
        d = tmp_path / "audit"
        d.mkdir()
        proof = tmp_path / "ran"

        def _vanish_and_raise(*a, **k):
            shutil.rmtree(d)
            raise FileNotFoundError(2, "No such file or directory",
                                    str(d / ".audit"))

        monkeypatch.setattr(spawn_mod, "mount_ns_available", lambda: True)
        monkeypatch.setattr(spawn_mod, "run_sandboxed", _vanish_and_raise)
        # Force the spawn tier eligible regardless of host capabilities.
        from core.sandbox import context as ctx
        monkeypatch.setattr(ctx, "check_net_available", lambda: True)
        monkeypatch.setattr(ctx, "check_mount_available", lambda: True)

        with _audit_sandbox(d) as r:
            with pytest.raises(SandboxSetupError,
                               match="audit target directory"):
                r(["touch", str(proof)], capture_output=True, timeout=30)
        assert not proof.exists()

    def test_spawn_failure_with_intact_dir_still_degrades(
            self, tmp_path, monkeypatch, no_audit_tiers):
        """Environmental spawn failures (audit dir intact) keep the
        legitimate degradation ladder — the command still runs, and
        the degradation leaves the machine-readable trail."""
        from core.sandbox import _spawn as spawn_mod
        from core.sandbox import context as ctx
        d = tmp_path / "audit"
        d.mkdir()

        def _env_failure(*a, **k):
            raise RuntimeError("kernel quirk: uidmap handshake failed")

        monkeypatch.setattr(spawn_mod, "mount_ns_available", lambda: True)
        monkeypatch.setattr(spawn_mod, "run_sandboxed", _env_failure)
        monkeypatch.setattr(ctx, "check_net_available", lambda: True)
        monkeypatch.setattr(ctx, "check_mount_available", lambda: True)

        with _audit_sandbox(d) as r:
            res = r(["true"], capture_output=True, timeout=60)
        assert res.returncode == 0
        assert res.sandbox_info.get("audit_engaged") is False
        payload = json.loads((d / MARKER).read_text())
        assert payload["degraded"] is True
        assert "spawn path failed" in payload["reason"]


@linux_only
class TestEvidenceBottleneck:
    """Layer 3: audit requested but no tier engaged is always
    machine-readable."""

    def test_default_degrade_writes_marker_and_sandbox_info(
            self, tmp_path, no_audit_tiers):
        d = tmp_path / "audit"
        d.mkdir()
        with _audit_sandbox(d) as r:
            # input= routes off the spawn tier; probes kill the
            # Landlock-only tracer tier.
            res = r(["cat"], input=b"", capture_output=True, timeout=60)
        assert res.returncode == 0
        assert res.sandbox_info.get("audit_engaged") is False
        payload = json.loads((d / MARKER).read_text())
        assert payload["audit_requested"] is True
        assert payload["audit_engaged"] is False
        assert payload["reason"]
