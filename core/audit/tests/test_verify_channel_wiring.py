"""Wiring tests: verification channels inside the orchestrator chain.

Covers _cwe_fallback_chain / _hypothesis_to_tool_chain entry emission
and _run_tool_chain dispatch for the joern_guard / joern_flow /
coccinelle_flow tool types, with the channel entry points monkeypatched
so nothing external runs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import core.audit.orchestrator as orch
from core.audit.orchestrator import (
    TierCounters,
    _cwe_fallback_chain,
    _hypothesis_to_tool_chain,
    _run_tool_chain,
)
from core.audit.sweep import SweepResult


def _types(chain):
    return [e["type"] for e in chain]


class TestChainEmission:
    def test_guard_cwe_gets_joern_guard(self):
        for cwe in ("CWE-120", "CWE-122", "CWE-125", "CWE-787", "CWE-476"):
            assert "joern_guard" in _types(_cwe_fallback_chain(cwe)), cwe

    def test_flow_cwes_get_joern_flow(self):
        for cwe in ("CWE-20", "CWE-74", "CWE-78", "CWE-89", "CWE-79"):
            assert "joern_flow" in _types(_cwe_fallback_chain(cwe)), cwe

    def test_flow_cocci_cwes(self):
        for cwe in ("CWE-416", "CWE-415", "CWE-252", "CWE-367"):
            assert "coccinelle_flow" in _types(_cwe_fallback_chain(cwe)), cwe

    def test_unrelated_cwe_unchanged(self):
        types = _types(_cwe_fallback_chain("CWE-190"))
        assert "joern_guard" not in types
        assert "joern_flow" not in types
        assert "coccinelle_flow" not in types

    def test_hypothesis_chain_adds_coccinelle_flow(self):
        chain = _hypothesis_to_tool_chain(
            "use-after-free of `conn` in handler", "src/a.c",
        )
        entry = next(
            e for e in chain if e["type"] == "coccinelle_flow"
        )
        assert entry["config"]["template"] == "use_after_free"

    def test_hypothesis_chain_no_duplicate_with_cwe(self):
        chain = _hypothesis_to_tool_chain(
            "use-after-free of `conn` in handler", "src/a.c",
            cwe="CWE-416",
        )
        assert _types(chain).count("coccinelle_flow") == 1

    def test_new_tier_counters_exist(self):
        counters = orch._make_tier_counters()
        for key in ("joern_guard", "joern_flow", "coccinelle_flow",
                    "fail_open"):
            assert key in counters


class _Cfg:
    """Minimal OrchestratorConfig stand-in for _run_tool_chain."""

    def __init__(self, target: Path):
        self.target_path = target
        self.out_dir = None
        self.codeql_db_path = None
        self.project_sinks = None


def _mk_result(outcome, rule_id, **kw):
    return SweepResult(
        tool="joern", file_path="src/a.c", function_name="f",
        outcome=outcome, rule_id=rule_id, **kw,
    )


@pytest.fixture
def counters():
    return {
        "joern_guard": TierCounters(),
        "joern_flow": TierCounters(),
        "coccinelle_flow": TierCounters(),
    }


class TestRunToolChainDispatch:
    HYP_GUARD = "missing bounds check on `len` before memcpy"
    HYP_FLOW = "attacker data from `argv` reaches system()"
    HYP_UAF = "use-after-free of `conn` after free"

    _SERVER_SENTINEL = object()

    def _run(self, tmp_path, chain, hypothesis, counters,
             server=_SERVER_SENTINEL):
        return _run_tool_chain(
            chain,
            config=_Cfg(tmp_path),
            file_path="src/a.c",
            function_name="f",
            source="",
            hypothesis=hypothesis,
            tier_counters=counters,
            joern_server=server,
        )

    def test_guard_confirm_stamps(self, tmp_path, counters, monkeypatch):
        import core.audit.joern_verify as jv
        monkeypatch.setattr(
            jv, "run_guard_dominance_check",
            lambda **kw: _mk_result(
                "confirmed", "joern:guard-dominance",
                matches=[{"line": 4}],
            ),
        )
        confirmed = self._run(
            tmp_path,
            [{"type": "joern_guard", "config": {"sinks": ["memcpy"]}}],
            self.HYP_GUARD, counters,
        )
        assert confirmed == ["joern:guard-dominance"]
        assert counters["joern_guard"].confirmed == 1

    def test_guard_refuted_returns_no_confirmation(
        self, tmp_path, counters, monkeypatch,
    ):
        import core.audit.joern_verify as jv
        monkeypatch.setattr(
            jv, "run_guard_dominance_check",
            lambda **kw: _mk_result("refuted", "joern:guard-dominance"),
        )
        confirmed = self._run(
            tmp_path,
            [{"type": "joern_guard", "config": {"sinks": ["memcpy"]}}],
            self.HYP_GUARD, counters,
        )
        assert confirmed == []
        assert counters["joern_guard"].refuted == 1

    def test_guard_error_counts_error(
        self, tmp_path, counters, monkeypatch,
    ):
        import core.audit.joern_verify as jv
        monkeypatch.setattr(
            jv, "run_guard_dominance_check",
            lambda **kw: _mk_result(
                "error", "joern:guard-dominance", errors=["boom"],
            ),
        )
        confirmed = self._run(
            tmp_path,
            [{"type": "joern_guard", "config": {"sinks": ["memcpy"]}}],
            self.HYP_GUARD, counters,
        )
        assert confirmed == []
        assert counters["joern_guard"].errors == 1

    def test_guard_no_binding_skips_without_running(
        self, tmp_path, counters, monkeypatch,
    ):
        import core.audit.joern_verify as jv

        def _explode(**kw):
            raise AssertionError("must not run without binding")

        monkeypatch.setattr(jv, "run_guard_dominance_check", _explode)
        confirmed = self._run(
            tmp_path,
            [{"type": "joern_guard", "config": {"sinks": ["memcpy"]}}],
            "something vague about safety", counters,
        )
        assert confirmed == []
        assert counters["joern_guard"].skipped == 1

    def test_guard_no_server_skips(self, tmp_path, counters, monkeypatch):
        import core.audit.joern_verify as jv

        def _explode(**kw):
            raise AssertionError("must not run without a server")

        monkeypatch.setattr(jv, "run_guard_dominance_check", _explode)
        confirmed = self._run(
            tmp_path,
            [{"type": "joern_guard", "config": {"sinks": ["memcpy"]}}],
            self.HYP_GUARD, counters, server=None,
        )
        assert confirmed == []
        assert counters["joern_guard"].skipped == 1

    def test_flow_confirm_stamps(self, tmp_path, counters, monkeypatch):
        import core.audit.joern_verify as jv
        seen = {}

        def fake_flow(**kw):
            seen.update(kw)
            return _mk_result(
                "confirmed", "joern:flow", matches=[{"steps": []}],
            )

        monkeypatch.setattr(jv, "run_flow_reachability_check", fake_flow)
        confirmed = self._run(
            tmp_path,
            [{"type": "joern_flow", "config": {"sinks": ["system"]}}],
            self.HYP_FLOW, counters,
        )
        assert confirmed == ["joern:flow"]
        assert seen["source_id"] == "argv"
        assert seen["sink_call"] == "system"
        assert counters["joern_flow"].confirmed == 1

    def test_flow_inconclusive_counts(self, tmp_path, counters, monkeypatch):
        import core.audit.joern_verify as jv
        monkeypatch.setattr(
            jv, "run_flow_reachability_check",
            lambda **kw: _mk_result("inconclusive", "joern:flow"),
        )
        confirmed = self._run(
            tmp_path,
            [{"type": "joern_flow", "config": {"sinks": ["system"]}}],
            self.HYP_FLOW, counters,
        )
        assert confirmed == []
        assert counters["joern_flow"].inconclusive == 1

    def test_cocci_flow_confirm_stamps_coccinelle_namespace(
        self, tmp_path, counters, monkeypatch,
    ):
        import core.audit.cocci_flow as cf
        monkeypatch.setattr(
            cf, "run_flow_cocci_sweep",
            lambda **kw: SweepResult(
                tool="coccinelle_flow", file_path="src/a.c",
                function_name="f", outcome="confirmed",
                matches=[{"line": 9}],
                rule_id="cocci-flow:use_after_free",
            ),
        )
        confirmed = self._run(
            tmp_path,
            [{"type": "coccinelle_flow",
              "config": {"template": "use_after_free"}}],
            self.HYP_UAF, counters,
        )
        assert confirmed == ["coccinelle:flow-use_after_free"]
        assert counters["coccinelle_flow"].confirmed == 1
        # The stamp must count as tool evidence and must be allowed to
        # promote (dynamic rules are not detection-only).
        from core.audit.evidence_grade import is_tool_evidence
        from core.audit.orchestrator import _is_detection_only
        assert is_tool_evidence(confirmed[0])
        assert not _is_detection_only(confirmed[0])

    def test_cocci_flow_error_never_confirms(
        self, tmp_path, counters, monkeypatch,
    ):
        import core.audit.cocci_flow as cf
        monkeypatch.setattr(
            cf, "run_flow_cocci_sweep",
            lambda **kw: SweepResult(
                tool="coccinelle_flow", file_path="src/a.c",
                function_name="f", outcome="error",
                errors=["parse error"],
                rule_id="cocci-flow:use_after_free",
            ),
        )
        confirmed = self._run(
            tmp_path,
            [{"type": "coccinelle_flow",
              "config": {"template": "use_after_free"}}],
            self.HYP_UAF, counters,
        )
        assert confirmed == []
        assert counters["coccinelle_flow"].errors == 1

    def test_channel_exception_does_not_break_chain(
        self, tmp_path, counters, monkeypatch,
    ):
        import core.audit.joern_verify as jv

        def _boom(**kw):
            raise RuntimeError("channel exploded")

        monkeypatch.setattr(jv, "run_guard_dominance_check", _boom)
        # A later entry must still run.
        import core.audit.cocci_flow as cf
        monkeypatch.setattr(
            cf, "run_flow_cocci_sweep",
            lambda **kw: SweepResult(
                tool="coccinelle_flow", file_path="src/a.c",
                function_name="f", outcome="confirmed",
                matches=[{"line": 9}],
                rule_id="cocci-flow:use_after_free",
            ),
        )
        confirmed = self._run(
            tmp_path,
            [
                {"type": "joern_guard", "config": {"sinks": ["memcpy"]}},
                {"type": "coccinelle_flow",
                 "config": {"template": "use_after_free"}},
            ],
            self.HYP_GUARD + " and use-after-free of `conn`",
            counters,
        )
        assert confirmed == ["coccinelle:flow-use_after_free"]


class TestReceiptEntries:
    def test_guard_receipt_description(self):
        from core.audit.evidence_grade import grade_review_result

        items = grade_review_result(
            {"hypothesis": "h"}, evidence_tool="joern:guard-dominance",
        )
        tool_items = [i for i in items if i.source.value == "mechanical:joern"]
        assert tool_items
        assert "dominat" in tool_items[0].description

    def test_flow_receipt_description(self):
        from core.audit.evidence_grade import grade_review_result

        items = grade_review_result(
            {"hypothesis": "h"}, evidence_tool="joern:flow",
        )
        tool_items = [i for i in items if i.source.value == "mechanical:joern"]
        assert tool_items
        assert "reachableByFlows" in tool_items[0].description
