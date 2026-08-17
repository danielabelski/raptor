"""RPC-boundary validation tests for netns_coordinator._run_child.

These run WITHOUT a working coordinator substrate (no namespaces
needed) — they exercise the spec-shape validation only, so they are
deliberately not in test_coordinator_isolation.py, which skips the
whole module when the coordinator can't launch on the host.

Pins the fix for spec-shape TypeErrors escaping the try that
populates ``result.error``: a malformed exploit spec crashed the
coordinator with a raw traceback (breaking the JSON-on-stdout
protocol), and a malformed target spec silently killed the target
thread, leaving ``returncode=None`` with no error string.
"""

import json

from core.sandbox import netns_coordinator as _nc


def test_run_child_malformed_spec_sets_structured_error_not_raise():
    for field, bad in (
        ("writable_paths", "/tmp/not-a-list"),
        ("readable_paths", "/tmp/not-a-list"),
        ("etc_overlay", [["/etc/hosts", "/tmp/hosts"]]),
    ):
        spec = {"cmd": ["/bin/true"], field: bad}
        result = _nc._ChildResult()
        _nc._run_child("exploit", spec, result)  # must not raise
        assert result.error is not None, field
        assert "TypeError" in result.error
        assert field in result.error
        # The fail-loud message must still reach the caller through
        # the structured response _emit_response serialises.
        json.dumps(result.to_dict())
        assert result.wallclock_s >= 0.0


def test_run_child_missing_cmd_sets_structured_error():
    result = _nc._ChildResult()
    _nc._run_child("exploit", {"env": {}}, result)  # must not raise
    assert result.error is not None
    assert "KeyError" in result.error
    json.dumps(result.to_dict())
