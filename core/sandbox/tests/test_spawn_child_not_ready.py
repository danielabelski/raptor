"""Typed engagement error when the spawn child dies before "R".

The spawn child's first act is unshare(USER|NS|IPC|[NET]). On hosts
where the kernel refuses it (userns sysctl, outer seccomp filter, LSM
policy) the child dies before signalling ready and the parent used to
raise a bare ``RuntimeError("sandbox child did not signal ready")`` —
no diagnostic, no remediation, and (through the context ladder's
environmental RuntimeError catch) a silent demotion to the
Landlock-only path. The child in fact reports WHY it died: it writes
its setup category ('U') plus the failing exception to the exec-status
pipe before exiting. The parent must surface that as the same typed
SandboxSetupError every other engagement-failure path uses.
"""

import sys
from unittest import mock

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="mount-ns backend is Linux-only",
)


def _run_with_unshare_refused():
    from core.sandbox import _spawn
    if not _spawn.mount_ns_available():
        pytest.skip("mount-ns not available on this host")
    # The forked child inherits the patched os.unshare and dies exactly
    # the way a userns-restricted kernel kills it: PermissionError at
    # the unshare stage, before "R".
    with mock.patch("os.unshare",
                    side_effect=PermissionError(
                        1, "Operation not permitted")):
        _spawn.run_sandboxed(
            ["/usr/bin/true"],
            target=None, output=None,
            writable_paths=[], readable_paths=None,
            allowed_tcp_ports=None,
            block_network=True, nproc_limit=1024,
            limits={"memory_mb": 0, "max_file_mb": 10240,
                    "cpu_seconds": 300},
            seccomp_profile="full", seccomp_block_udp=False,
            env=None, cwd=None, timeout=30,
            capture_output=True, text=True,
        )


def test_unshare_refusal_raises_typed_engage_error():
    from core.sandbox.errors import SandboxSetupError
    with pytest.raises(SandboxSetupError) as ei:
        _run_with_unshare_refused()
    exc = ei.value
    # Category 'U' — the unshare stage, drained from the exec-status
    # pipe (_write_setup_status).
    assert exc.setup_category == "U"
    # The kernel's actual refusal.
    assert "Operation not permitted" in str(exc)
    # Actionable remediation, same text the context-level engagement
    # gate surfaces.
    assert "namespace layer cannot engage" in str(exc)


def test_context_ladder_still_degrades_loudly_on_category_u(tmp_path):
    # The context ladder's documented environmental degrade must keep
    # working for the unshare-stage death: the run completes on the
    # Landlock-confined retry path, with the loud stamp — the typed
    # error must not turn a one-call environmental flap into a whole-
    # run abort when Landlock can still enforce the policy. (On a
    # Landlock-less kernel the demotion recheck refuses instead —
    # covered in test_backend_demotion.)
    from unittest import mock

    from core.sandbox import _spawn
    from core.sandbox import context as ctx
    from core.sandbox.landlock import check_landlock_available
    if not _spawn.mount_ns_available():
        pytest.skip("mount-ns not available on this host")
    if not check_landlock_available():
        pytest.skip("Landlock unavailable")
    tgt = tmp_path / "t"
    out = tmp_path / "o"
    tgt.mkdir()
    out.mkdir()
    # Warm every availability/engagement cache on the REAL mount path
    # first. The ladder under test is the runtime failure of a chosen
    # backend; in a cold process the construction-time probes would
    # otherwise run UNDER the patch, observe the refusal themselves,
    # and route around the spawn path entirely (Landlock-only from the
    # start — a different, separately-tested lane with no demotion
    # stamp). Cache state must not depend on which tests ran earlier
    # in the process.
    probe = ctx.run(["true"], target=str(tgt), output=str(out),
                    capture_output=True, text=True, timeout=30)
    if not (probe.returncode == 0
            and (getattr(probe, "sandbox_info", None) or {})
            .get("mount_ns_active")):
        pytest.skip("mount backend not engaging on this host")
    with mock.patch("os.unshare",
                    side_effect=PermissionError(
                        1, "Operation not permitted")):
        r = ctx.run(["true"], target=str(tgt), output=str(out),
                    capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr[-300:]
    assert "spawn setup failed" in (
        (getattr(r, "sandbox_info", None) or {})
        .get("mount_ns_degraded") or "")
