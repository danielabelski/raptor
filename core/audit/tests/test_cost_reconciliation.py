"""Run-cost ledgers must reconcile or explain themselves.

Observed field failure: one run showed $8.08 (LLM client ledger),
$4.52 (cost-breakdown review phase) and $2.82 (final summary) with no
way to relate them. The fix defines the semantics (see
core/audit/cost_tracker.py module docstring) and these tests pin them.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from core.audit.cost_tracker import CostTracker, format_cost_summary
from core.audit.orchestrator import (
    OrchestratorResult,
    ReviewOutcome,
    _tally_outcome,
    _untally_outcome,
)


class TestFailedAttemptLedger:
    def test_failed_attempts_tracked_per_phase(self):
        ct = CostTracker()
        ct.record_call("review", cost_usd=2.82)
        ct.record_failed_attempt("review", cost_usd=5.26)

        pc = ct.phases["review"]
        assert pc.calls == 1
        assert pc.failed_calls == 1
        assert abs(pc.cost_usd - 2.82) < 1e-9
        assert abs(pc.failed_attempts_cost_usd - 5.26) < 1e-9

        d = ct.to_dict()
        assert d["phases"]["review"]["failed_calls"] == 1
        assert d["phases"]["review"]["failed_attempts_cost_usd"] == 5.26

    def test_reconciliation_arithmetic_closes(self):
        ct = CostTracker()
        ct.record_call("review", cost_usd=2.82)
        ct.record_failed_attempt("review", cost_usd=4.0)
        ct.set_total_spend(8.08)  # the client ledger

        assert abs(ct.total_cost_usd - 2.82) < 1e-9
        assert abs(ct.total_failed_attempts_cost_usd - 4.0) < 1e-9
        assert abs(ct.total_spend_usd - 8.08) < 1e-9
        # total_spend = completed + failed + unattributed, always.
        assert abs(
            ct.unattributed_cost_usd - (8.08 - 2.82 - 4.0)
        ) < 1e-9

        totals = ct.to_dict()["totals"]
        assert totals["total_spend_usd"] == 8.08
        assert totals["failed_attempts_cost_usd"] == 4.0
        assert abs(
            totals["cost_usd"]
            + totals["failed_attempts_cost_usd"]
            + totals["unattributed_cost_usd"]
            - totals["total_spend_usd"]
        ) < 1e-3

    def test_client_ledger_cannot_hide_tracked_spend(self):
        ct = CostTracker()
        ct.record_call("review", cost_usd=3.0)
        ct.set_total_spend(1.0)  # stale / partial snapshot
        assert ct.total_spend_usd == 3.0
        assert ct.unattributed_cost_usd == 0.0

    def test_clean_run_keeps_legacy_shape(self):
        """No failed attempts + no client ledger → no new totals keys
        (consumers of the old cost-breakdown.json shape unaffected)."""
        ct = CostTracker()
        ct.record_call("review", cost_usd=0.5)
        totals = ct.to_dict()["totals"]
        assert "failed_attempts_cost_usd" not in totals
        assert "total_spend_usd" not in totals
        assert "failed_calls" not in ct.to_dict()["phases"]["review"]

    def test_summary_line_shows_failed_spend(self):
        ct = CostTracker()
        ct.record_call("review", cost_usd=2.82)
        ct.set_total_spend(8.08)
        s = ct.summary()
        assert "$8.08" in s
        assert "failed/timed-out" in s


class TestFormatCostSummary:
    def _result(self, **kw) -> SimpleNamespace:
        base = {
            "total_cost_usd": 0.0,
            "failed_attempts_cost_usd": 0.0,
            "llm_spend_usd": 0.0,
            "reviewed": 0,
            "errors": 0,
        }
        base.update(kw)
        return SimpleNamespace(**base)

    def test_observed_scenario(self):
        """The real run: $8.08 spent, $2.82 across 3 completed
        reviews (15 reviewed, 12 errors), rest on failed attempts."""
        line = format_cost_summary(self._result(
            total_cost_usd=2.82, llm_spend_usd=8.08,
            failed_attempts_cost_usd=5.26, reviewed=15, errors=12,
        ))
        assert line == (
            "Cost: $8.08 ($2.82 across 3 completed reviews; "
            "$5.26 on failed/timed-out attempts)"
        )

    def test_no_failed_spend_stays_simple(self):
        line = format_cost_summary(self._result(
            total_cost_usd=2.82, llm_spend_usd=2.82, reviewed=3,
        ))
        assert line == "Cost: $2.82"

    def test_no_client_ledger_uses_tracked_split(self):
        line = format_cost_summary(self._result(
            total_cost_usd=1.0, failed_attempts_cost_usd=0.5,
            reviewed=2, errors=0,
        ))
        assert line == (
            "Cost: $1.50 ($1.00 across 2 completed reviews; "
            "$0.50 on failed/timed-out attempts)"
        )

    def test_singular_review(self):
        line = format_cost_summary(self._result(
            total_cost_usd=1.0, llm_spend_usd=2.0, reviewed=1,
        ))
        assert "1 completed review;" in line

    def test_zero_spend_prints_nothing(self):
        assert format_cost_summary(self._result()) is None

    def test_legacy_result_without_new_fields(self):
        line = format_cost_summary(
            SimpleNamespace(total_cost_usd=0.75, reviewed=2, errors=0),
        )
        assert line == "Cost: $0.75"


class TestUntallyKeepsSpend:
    def test_untally_reverses_verdict_not_cost(self):
        """Deepen/re-review replace outcomes, but the replaced call's
        money was still spent — reversing it made the summary drift
        below every other ledger and under-enforced --max-cost."""
        result = OrchestratorResult()
        outcome = ReviewOutcome(
            file="a.c", function="f", status="suspicious",
            body="hmm", cost_usd=1.7,
        )
        _tally_outcome(result, outcome)
        assert result.suspicious == 1
        assert abs(result.total_cost_usd - 1.7) < 1e-9

        _untally_outcome(result, outcome)
        assert result.suspicious == 0
        assert result.reviewed == 0
        assert abs(result.total_cost_usd - 1.7) < 1e-9  # spend survives

        replacement = ReviewOutcome(
            file="a.c", function="f", status="clean",
            body="ok", cost_usd=0.3,
        )
        _tally_outcome(result, replacement)
        assert abs(result.total_cost_usd - 2.0) < 1e-9


@pytest.mark.slow
class TestEndToEndReconciliation:
    def test_failed_attempt_spend_reaches_breakdown_and_summary(
        self, tmp_path,
    ):
        """A review call that raises after the client billed the
        attempt: the delta lands in failed_attempts_cost_usd, the
        client ledger in totals.total_spend_usd, and the summary line
        reports the split."""
        from core.audit.orchestrator import run_orchestrator
        from core.audit.tests.test_budget_terminal import (
            _config,
            _setup_target,
        )

        target, out, names = _setup_target(tmp_path, n_functions=2)

        client = SimpleNamespace(total_cost=0.0)
        client.is_budget_exhausted = lambda estimated_cost=0.1: False

        def review_fn(ctx, config):
            if ctx["function"] == names[0]:
                client.total_cost += 1.7   # billed attempt...
                raise RuntimeError("timeout after 600s")  # ...that died
            client.total_cost += 0.5
            return ReviewOutcome(
                file=ctx["file"], function=ctx["function"],
                status="clean", body="ok", cost_usd=0.5,
            )

        cfg = _config(target, out, llm_budget_client=client)
        result = run_orchestrator(cfg, review_fn)

        # The main-pass attempt billed 1.7 and was booked as a failed
        # attempt on the review phase; the error-retry pass's second
        # 1.7 attempt has no phase attribution and must surface as
        # unattributed rather than vanish.
        assert result.errors == 1
        assert abs(result.failed_attempts_cost_usd - 1.7) < 1e-6
        assert abs(result.llm_spend_usd - client.total_cost) < 1e-6

        breakdown = json.loads((out / "cost-breakdown.json").read_text())
        review_phase = breakdown["phases"]["review"]
        assert review_phase["failed_calls"] == 1
        assert abs(review_phase["failed_attempts_cost_usd"] - 1.7) < 1e-6
        totals = breakdown["totals"]
        assert abs(totals["total_spend_usd"] - client.total_cost) < 1e-3
        assert abs(
            totals["cost_usd"]
            + totals["failed_attempts_cost_usd"]
            + totals["unattributed_cost_usd"]
            - totals["total_spend_usd"]
        ) < 1e-3

        line = format_cost_summary(result)
        assert line is not None
        total_s = f"${client.total_cost:.2f}"
        failed_s = f"${client.total_cost - 0.5:.2f}"
        assert line.startswith(
            f"Cost: {total_s} ($0.50 across 1 completed review;",
        )
        assert f"{failed_s} on failed/timed-out attempts" in line
