"""Tests for the P7 precision feedback on graduated-rule findings.

``_record_graduated_rule_feedback`` keys off the
``synthesized:<library_rule_id>`` ruleId the scanner's graduated stage
stamps, and feeds the analysis verdict into RuleLibrary.record_match.
The library is stubbed — no filesystem manifest involved.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from typing import ClassVar

from packages.llm_analysis.agent import AutonomousSecurityAgentV2


class _FakeLibrary:
    calls: ClassVar[list] = []

    def __init__(self, *a, **kw):
        pass

    def record_match(self, rule_id, is_tp):
        _FakeLibrary.calls.append((rule_id, is_tp))


def _agent_stub():
    agent = SimpleNamespace(
        _SYNTHESIZED_RULE_PREFIX=(
            AutonomousSecurityAgentV2._SYNTHESIZED_RULE_PREFIX
        ),
    )
    agent._record_graduated_rule_feedback = (
        AutonomousSecurityAgentV2._record_graduated_rule_feedback.__get__(
            agent, type(agent)
        )
    )
    return agent


def _vuln(rule_id, analysis):
    return SimpleNamespace(rule_id=rule_id, analysis=analysis)


def _patch_library(monkeypatch):
    _FakeLibrary.calls = []
    import packages.checker_synthesis.library as lib_mod
    monkeypatch.setattr(lib_mod, "RuleLibrary", _FakeLibrary)
    return _FakeLibrary.calls


class TestGraduatedRuleFeedback:
    def test_fp_verdict_records_is_tp_false(self, monkeypatch):
        calls = _patch_library(monkeypatch)
        agent = _agent_stub()
        agent._record_graduated_rule_feedback(
            _vuln("synthesized:uaf-variant-3", {"is_true_positive": False}),
        )
        assert calls == [("uaf-variant-3", False)]

    def test_tp_verdict_records_is_tp_true(self, monkeypatch):
        calls = _patch_library(monkeypatch)
        agent = _agent_stub()
        agent._record_graduated_rule_feedback(
            _vuln("synthesized:uaf-variant-3", {"is_true_positive": True}),
        )
        assert calls == [("uaf-variant-3", True)]

    def test_non_synthesized_rule_ignored(self, monkeypatch):
        calls = _patch_library(monkeypatch)
        agent = _agent_stub()
        agent._record_graduated_rule_feedback(
            _vuln("cpp/overflow-buffer", {"is_true_positive": False}),
        )
        assert calls == []

    def test_no_verdict_records_nothing(self, monkeypatch):
        calls = _patch_library(monkeypatch)
        agent = _agent_stub()
        agent._record_graduated_rule_feedback(
            _vuln("synthesized:uaf-variant-3", {}),
        )
        agent._record_graduated_rule_feedback(
            _vuln("synthesized:uaf-variant-3", None),
        )
        assert calls == []
