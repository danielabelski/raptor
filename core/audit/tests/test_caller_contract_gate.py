"""Post-review caller-contract confidence demotion gate.

The caller-proof FP family: "dangerous-if-misused" hypotheses
("double free if a caller invokes it twice") formed against a
function reviewed in isolation, where every actual call site upholds
the assumed contract.  The gate consumes the api_boundary channel's
``refuted`` verdict — previously telemetry-only — into a receipted
confidence demotion: ``caller_evidence`` record, ``[caller-contract:
...]`` body prefix, suppressions.jsonl ``dropped: false`` row, and a
confidence clamp enforced at export.  Never a suppression: status is
untouched and the finding still ships.

Demotion declines on ANY enumeration incompleteness (address-taken
escape, capped scan) and on any non-structural per-site receipt —
the recall-loss lane is policed by construction.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.orchestrator import (
    OrchestratorConfig,
    ReviewOutcome,
    _apply_caller_contract_gate,
    _caller_contract_demotion_pass,
)

HYP = (
    "Double free of b if a caller invokes bitmap_free twice on the "
    "same pointer (free(b) has no idempotence guard)"
)

BITMAP_DEF = """\
void bitmap_free(struct bitmap *b)
{
    if (b == NULL)
        return;
    free(b->d);
    free(b);
}
"""

GUARDED_CALLERS = """\
void session_close(struct bitmap *m) {
    bitmap_free(m);
    m = NULL;
}
void ctx_free(struct ctx *c) {
    bitmap_free(c->map);
}
"""

UNGUARDED_CALLERS = """\
void broken(struct bitmap *m) {
    bitmap_free(m);
    bitmap_free(m);
}
"""

FNPTR_CALLERS = """\
struct ops { void (*fr)(struct bitmap *); };
struct ops O = { .fr = bitmap_free };
void a(struct bitmap *m) {
    bitmap_free(m);
}
"""


def _target(tmp_path: Path, callers: str) -> Path:
    tgt = tmp_path / "src"
    tgt.mkdir(exist_ok=True)
    (tgt / "bitmap.c").write_text(BITMAP_DEF)
    (tgt / "callers.c").write_text(callers)
    return tgt


def _config(tmp_path: Path, callers: str) -> OrchestratorConfig:
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return OrchestratorConfig(
        target_path=_target(tmp_path, callers),
        out_dir=out,
    )


def _outcome(status: str = "suspicious", **kw) -> ReviewOutcome:
    defaults = dict(
        file="bitmap.c",
        function="bitmap_free",
        status=status,
        body="free(b) at line 6 has no idempotence guard",
        hypothesis=HYP,
        review_result={"hypothesis": HYP, "vuln_type": "double_free"},
        line=1,
    )
    defaults.update(kw)
    return ReviewOutcome(**defaults)


class TestGateDemotes:
    def test_refuted_contract_demotes_with_receipts(self, tmp_path):
        config = _config(tmp_path, GUARDED_CALLERS)
        outcome = _outcome()
        assert _apply_caller_contract_gate(outcome, config) is True
        # Status untouched — demotion, never suppression.
        assert outcome.status == "suspicious"
        assert outcome.body.startswith(
            "[caller-contract: all 2 call site(s) uphold the "
            "precondition]",
        )
        record = outcome.review_result["caller_evidence"]
        assert record["outcome"] == "refuted"
        assert record["demotion"]["confidence_clamp"] == "low"
        assert record["enumeration"]["complete"] is True
        assert len(record["sites"]) == 2
        assert all(
            s["verdict"] == "guarded" and s["grade"] == "structural"
            for s in record["sites"]
        )

    def test_suppressions_row_dropped_false(self, tmp_path):
        config = _config(tmp_path, GUARDED_CALLERS)
        outcome = _outcome(status="finding")
        assert _apply_caller_contract_gate(outcome, config) is True
        rows = [
            json.loads(line)
            for line in (config.out_dir / "suppressions.jsonl")
            .read_text().splitlines() if line.strip()
        ]
        assert len(rows) == 1
        row = rows[0]
        assert row["dropped"] is False
        assert row["verdict"] == "caller_contract_refuted"
        assert row["function"] == "bitmap_free"
        assert row["confidence_clamp"] == "low"
        assert row["sites"] == 2

    def test_gate_is_idempotent(self, tmp_path):
        config = _config(tmp_path, GUARDED_CALLERS)
        outcome = _outcome()
        assert _apply_caller_contract_gate(outcome, config) is True
        assert _apply_caller_contract_gate(outcome, config) is False
        assert outcome.body.count("[caller-contract:") == 1


class TestGateDeclines:
    def test_unguarded_caller_blocks_demotion(self, tmp_path):
        config = _config(tmp_path, UNGUARDED_CALLERS)
        outcome = _outcome()
        assert _apply_caller_contract_gate(outcome, config) is False
        assert "[caller-contract:" not in outcome.body
        assert "caller_evidence" not in (outcome.review_result or {})

    def test_function_pointer_escape_blocks_demotion(self, tmp_path):
        # Enumeration-incompleteness trap: the callee is reachable via
        # a dispatch table — the evidence declines, verdict unchanged.
        config = _config(tmp_path, FNPTR_CALLERS)
        outcome = _outcome()
        assert _apply_caller_contract_gate(outcome, config) is False
        assert "caller_evidence" not in (outcome.review_result or {})

    def test_tool_confirmed_outcomes_never_demoted(self, tmp_path):
        config = _config(tmp_path, GUARDED_CALLERS)
        outcome = _outcome(evidence_tool="semgrep")
        assert _apply_caller_contract_gate(outcome, config) is False

    def test_non_caller_conditional_hypothesis_skipped(self, tmp_path):
        config = _config(tmp_path, GUARDED_CALLERS)
        hyp = "unchecked memcpy overflows the destination buffer"
        outcome = _outcome(
            hypothesis=hyp, review_result={"hypothesis": hyp},
        )
        assert _apply_caller_contract_gate(outcome, config) is False

    def test_live_non_contract_sibling_hypothesis_blocks_demotion(
        self, tmp_path,
    ):
        # The exported confidence covers the WHOLE finding: refuting
        # the caller-contract claim must not demote an outcome that
        # also carries a live in-body mechanism.
        config = _config(tmp_path, GUARDED_CALLERS)
        outcome = _outcome(hypotheses=[
            {"mechanism": HYP, "confidence": "high"},
            {"mechanism": "off-by-one in the length computation "
                          "overflows the copy", "confidence": "medium"},
        ])
        assert _apply_caller_contract_gate(outcome, config) is False

    def test_refuted_sibling_does_not_block_demotion(self, tmp_path):
        config = _config(tmp_path, GUARDED_CALLERS)
        outcome = _outcome(hypotheses=[
            {"mechanism": HYP, "confidence": "high"},
            {"mechanism": "unchecked memcpy overflow",
             "confidence": "refuted"},
        ])
        assert _apply_caller_contract_gate(outcome, config) is True

    def test_clean_and_dark_statuses_skipped(self, tmp_path):
        config = _config(tmp_path, GUARDED_CALLERS)
        for status in ("clean", "dark", "error"):
            assert _apply_caller_contract_gate(
                _outcome(status=status), config,
            ) is False


class _FakeResult:
    def __init__(self, outcomes):
        self.outcomes = outcomes


class TestDemotionPass:
    def test_pass_demotes_eligible_outcomes(self, tmp_path):
        config = _config(tmp_path, GUARDED_CALLERS)
        eligible = _outcome()
        clean = _outcome(status="clean")
        _caller_contract_demotion_pass(
            _FakeResult([eligible, clean]), config,
        )
        assert "caller_evidence" in eligible.review_result
        assert "[caller-contract:" in eligible.body
        assert "[caller-contract:" not in clean.body

    def test_flag_off_leaves_outcomes_untouched(self, tmp_path):
        config = _config(tmp_path, GUARDED_CALLERS)
        config.caller_contract_demotion = False
        outcome = _outcome()
        _caller_contract_demotion_pass(_FakeResult([outcome]), config)
        assert "caller_evidence" not in (outcome.review_result or {})
        assert "[caller-contract:" not in outcome.body
