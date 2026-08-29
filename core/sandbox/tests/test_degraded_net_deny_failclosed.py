"""block_network=True must never yield silently-open egress.

The interface-level network block rides the namespace backend. On hosts
without one, the designed consolation is Landlock's TCP-connect deny
(ABI v4+, `degraded_net_deny=True`). Pre-fix, when THAT lane was also
unavailable (no Landlock ABI v4+), the context logged a one-shot
warning and ran with unrestricted network — the demanded block
evaporated exactly on the most-degraded hosts, and every call after
the first did so without even the warning. Now the context refuses
(SandboxSetupError); `degraded_net_deny=False` stays the documented
per-run escape hatch that explicitly accepts open egress on a degraded
host, and `strict` keeps deferring to its own all-requirements gate.
"""

import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="namespace backend is Linux-only",
)


def _force_no_namespace_backend(monkeypatch):
    from core.sandbox import state
    monkeypatch.setattr(state, "_net_available_cache", False)


def _force_landlock_abi(monkeypatch, abi: int):
    import core.sandbox.landlock as ll
    monkeypatch.setattr(ll, "_get_landlock_abi", lambda: abi)


def test_no_namespaces_and_no_landlock_v4_refuses(monkeypatch):
    from core.sandbox import sandbox
    from core.sandbox.errors import SandboxSetupError
    _force_no_namespace_backend(monkeypatch)
    _force_landlock_abi(monkeypatch, 3)  # pre-v4: no TCP deny rules
    with pytest.raises(SandboxSetupError) as ei:
        with sandbox(block_network=True):
            pass
    msg = str(ei.value)
    assert "no layer can enforce" in msg
    assert "degraded_net_deny=False" in msg  # names the escape hatch


def test_no_namespaces_and_no_landlock_at_all_refuses(monkeypatch):
    import core.sandbox.landlock as ll
    from core.sandbox import sandbox
    from core.sandbox.errors import SandboxSetupError
    _force_no_namespace_backend(monkeypatch)
    monkeypatch.setattr(ll, "check_landlock_available", lambda: False)
    with pytest.raises(SandboxSetupError):
        with sandbox(block_network=True):
            pass


def test_landlock_v4_still_degrades_to_tcp_deny(monkeypatch):
    # The designed consolation lane is untouched: with Landlock v4+
    # the run proceeds under the degraded TCP-connect deny and says so
    # in sandbox_info.
    from core.sandbox import sandbox
    from core.sandbox.landlock import _get_landlock_abi, check_landlock_available
    if not (check_landlock_available() and _get_landlock_abi() >= 4):
        pytest.skip("host lacks Landlock ABI v4+")
    _force_no_namespace_backend(monkeypatch)
    with sandbox(block_network=True) as run:
        r = run(["true"], capture_output=True, timeout=30)
    assert r.returncode == 0, r.stderr[-300:]
    assert r.sandbox_info.get("degraded_net_deny") is True


def test_opt_out_explicitly_accepts_open_network(monkeypatch):
    # degraded_net_deny=False is the operator's conscious acceptance of
    # unrestricted network on a degraded host — it must keep running,
    # not raise.
    from core.sandbox import sandbox
    _force_no_namespace_backend(monkeypatch)
    _force_landlock_abi(monkeypatch, 3)
    with sandbox(block_network=True, degraded_net_deny=False) as run:
        r = run(["true"], capture_output=True, timeout=30)
    assert r.returncode == 0, r.stderr[-300:]


def test_allowed_tcp_ports_with_landlock_v4_engages(monkeypatch):
    # block_network + allowed_tcp_ports is the documented dead combo
    # whose network policy IS the port allowlist; with Landlock v4+ the
    # allowlist is enforceable on the backend-less path, so the context
    # engages (no deny-all — that would break the allowlist).
    from core.sandbox import sandbox
    from core.sandbox.landlock import _get_landlock_abi, check_landlock_available
    if not (check_landlock_available() and _get_landlock_abi() >= 4):
        pytest.skip("host lacks Landlock ABI v4+")
    _force_no_namespace_backend(monkeypatch)
    with sandbox(block_network=True, allowed_tcp_ports=[443]) as run:
        assert callable(run)  # context engaged — no refusal


def test_allowed_tcp_ports_without_landlock_v4_refuses(monkeypatch):
    # Below ABI v4 the port allowlist is unenforceable too — the same
    # host shape previously ran with FULLY OPEN egress (any port, any
    # host) behind two misleading warnings. Must refuse, and the
    # refusal must say the allowlist is part of what cannot engage.
    from core.sandbox import sandbox
    from core.sandbox.errors import SandboxSetupError
    from core.sandbox.landlock import check_landlock_available
    if not check_landlock_available():
        pytest.skip("Landlock unavailable")
    _force_no_namespace_backend(monkeypatch)
    _force_landlock_abi(monkeypatch, 3)
    with pytest.raises(SandboxSetupError) as ei:
        with sandbox(block_network=True, allowed_tcp_ports=[443]):
            pass
    assert "allowed_tcp_ports" in str(ei.value)


def test_operator_override_env_downgrades_refusal_to_warning(monkeypatch):
    # RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1 is the documented host-wide
    # acceptance of the degraded tier: the refusal becomes a loud
    # warning and the run proceeds.
    from core.sandbox import sandbox
    _force_no_namespace_backend(monkeypatch)
    _force_landlock_abi(monkeypatch, 3)
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    with sandbox(block_network=True) as run:
        r = run(["true"], capture_output=True, timeout=30)
    assert r.returncode == 0, r.stderr[-300:]
