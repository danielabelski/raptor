"""Premise binding for refuted/countered-hypothesis re-verification.

A function-local SAT/pattern confirm may not override an LLM
refutation that rests on a cross-function premise ("the caller
validates the level", "that helper caps the length") — the engine
never encoded the premise, so the confirm re-proves the lexical shape
the reviewer already saw and refuted.
"""

import json
from pathlib import Path

import core.audit.orchestrator as orch
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _premise_blocks_confirm,
    _promote_clean_refuted,
    _refutation_scope_cross_function,
    _tool_sees_cross_function,
)

_CROSS_COUNTER = (
    "access_remote_vm caps the returned length at PAGE_SIZE and the "
    "name is written under mmap_write_lock, so the read cannot "
    "overrun the buffer."
)
_LOCAL_COUNTER = (
    "the loop condition i < n prevents the index from ever reaching "
    "the sentinel slot, so the write stays in bounds."
)


class TestToolScope:
    def test_function_local_families(self):
        for t in ("smt:check-overflow", "coccinelle:missing_bounds_check",
                  "semgrep:rule-1", "ptr_lifecycle:stale-alias",
                  "prefilter:sink"):
            assert not _tool_sees_cross_function(t)

    def test_cross_function_families(self):
        for t in ("joern:flow-42", "codeql:cpp/overflow",
                  "consistency:contract-witness",
                  "callsite_deviation:width"):
            assert _tool_sees_cross_function(t)


class TestRefutationScope:
    def test_structured_field_wins(self):
        assert _refutation_scope_cross_function(
            {"counter": _LOCAL_COUNTER, "counter_scope": "cross_function"},
        )
        assert not _refutation_scope_cross_function(
            {"counter": _CROSS_COUNTER, "counter_scope": "local"},
        )

    def test_fallback_symbol_plus_guarantee(self):
        assert _refutation_scope_cross_function({"counter": _CROSS_COUNTER})

    def test_fallback_caller_language(self):
        assert _refutation_scope_cross_function({
            "counter": "callers only invoke grow when the array is "
                       "already full, so the reallocation is safe",
        })

    def test_fallback_local_fact_stays_local(self):
        assert not _refutation_scope_cross_function(
            {"counter": _LOCAL_COUNTER},
        )

    def test_short_counter_ignored(self):
        assert not _refutation_scope_cross_function({"counter": "callers"})


class TestPremiseBlocksConfirm:
    def test_blocks_function_local_confirm(self):
        h = {"counter": _CROSS_COUNTER, "counter_scope": "cross_function"}
        assert _premise_blocks_confirm(h, ["smt:check-overflow"])

    def test_cross_function_channel_allows(self):
        h = {"counter": _CROSS_COUNTER, "counter_scope": "cross_function"}
        assert not _premise_blocks_confirm(
            h, ["smt:check-overflow", "joern:flow"],
        )

    def test_local_refutation_allows(self):
        h = {"counter": _LOCAL_COUNTER, "counter_scope": "local"}
        assert not _premise_blocks_confirm(h, ["smt:check-overflow"])

    def test_no_confirm_no_block(self):
        h = {"counter": _CROSS_COUNTER, "counter_scope": "cross_function"}
        assert not _premise_blocks_confirm(h, [])


class TestCleanRefutedLaneIntegration:
    def _run(self, tmp_path: Path, counter_scope: str):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.c").write_text("int f(int n) { return n * 4; }\n")
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)
        outcome = ReviewOutcome(
            file="a.c", function="f", status="clean",
            body="clean after refutation",
            hypothesis="",
            hypotheses=[{
                "mechanism": "integer overflow in size multiplication "
                             "reaches the allocation",
                "confidence": "refuted",
                "counter": _CROSS_COUNTER,
                "counter_scope": counter_scope,
            }],
            line=1,
        )
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.clean = 1
        checklist = {
            "files": [{
                "path": "a.c",
                "items": [{"name": "f", "line_start": 1, "line_end": 1}],
            }],
        }
        return config, result, checklist

    def test_cross_function_premise_blocks_promotion(
        self, tmp_path, monkeypatch,
    ):
        config, result, checklist = self._run(tmp_path, "cross_function")
        monkeypatch.setattr(
            orch, "_hypothesis_to_smt_verb", lambda m: "check-overflow",
        )
        monkeypatch.setattr(
            orch, "_run_tool_chain",
            lambda *a, **k: ["smt:check-overflow"],
        )
        monkeypatch.setattr(
            orch, "_check_sink_guarded_cached", lambda *a, **k: "unguarded",
        )
        _promote_clean_refuted(result, config, checklist=checklist)
        assert result.outcomes[0].status == "clean"
        assert getattr(
            result.tier_counters["refuted_sweep"], "premise_blocked", 0,
        ) >= 1
        # The premise was parked on the reading list for the study loop.
        rl = json.loads((config.out_dir / "reading-list.json").read_text())
        questions = [it["question"] for it in rl["items"]]
        assert any("access_remote_vm" in q for q in questions)

    def test_local_premise_still_promotes(self, tmp_path, monkeypatch):
        config, result, checklist = self._run(tmp_path, "local")
        monkeypatch.setattr(
            orch, "_hypothesis_to_smt_verb", lambda m: "check-overflow",
        )
        monkeypatch.setattr(
            orch, "_run_tool_chain",
            lambda *a, **k: ["smt:check-overflow"],
        )
        monkeypatch.setattr(
            orch, "_check_sink_guarded_cached", lambda *a, **k: "unguarded",
        )
        _promote_clean_refuted(result, config, checklist=checklist)
        assert result.outcomes[0].status == "finding"
