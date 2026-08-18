"""Tests for the audit corpus metrics module."""

from __future__ import annotations

import json

import pytest

from core.audit.corpus.corpus_metrics import (
    ClassMetrics,
    _read_results,
    check_gate,
    compute_attribution,
    compute_metrics,
    compute_mode_mismatches,
    diff_runs,
    error_rows,
    format_attribution_report,
    format_mode_report,
    format_report,
    main,
    status_matches,
)


def _row(fid, bug_class, expected, actual, model="test", **extra):
    row = {
        "function_id": fid,
        "bug_class": bug_class,
        "expected": expected,
        "actual": actual,
        "model": model,
    }
    row.update(extra)
    return row


class TestClassMetrics:
    def test_precision(self):
        cm = ClassMetrics(tp=3, fp=1, tn=5, fn=1)
        assert cm.precision == 0.75

    def test_recall(self):
        cm = ClassMetrics(tp=3, fp=1, tn=5, fn=1)
        assert cm.recall == 0.75

    def test_f1(self):
        cm = ClassMetrics(tp=3, fp=1, tn=5, fn=1)
        assert cm.f1 == 0.75

    def test_no_positives(self):
        cm = ClassMetrics(tp=0, fp=0, tn=5, fn=0)
        assert cm.precision is None
        assert cm.recall is None

    def test_total_includes_error(self):
        cm = ClassMetrics(tp=1, fp=2, tn=3, fn=4, error=2)
        assert cm.total == 12
        assert cm.adjudicated == 10

    def test_error_excluded_from_precision_recall(self):
        # 3 errors must not shift P/R at all
        with_err = ClassMetrics(tp=3, fp=1, tn=5, fn=1, error=3)
        without = ClassMetrics(tp=3, fp=1, tn=5, fn=1)
        assert with_err.precision == without.precision
        assert with_err.recall == without.recall
        assert with_err.f1 == without.f1


class TestComputeMetrics:
    def test_basic(self):
        rows = [
            _row("a:f1", "aliasing", "finding", "finding"),
            _row("a:f2", "aliasing", "clean", "clean"),
            _row("a:f3", "aliasing", "finding", "clean"),
            _row("b:f1", "auth", "clean", "finding"),
        ]
        agg, per_class, skipped = compute_metrics(rows)
        assert agg.tp == 1
        assert agg.fn == 1
        assert agg.fp == 1
        assert agg.tn == 1
        assert agg.error == 0
        assert skipped == 0

        assert per_class["aliasing"].tp == 1
        assert per_class["aliasing"].fn == 1
        assert per_class["auth"].fp == 1

    def test_dormant_as_clean(self):
        rows = [
            _row("h:f1", "trap", "dormant", "dormant"),
            _row("h:f2", "trap", "dormant", "clean"),
        ]
        agg, per_class, _ = compute_metrics(rows)
        assert agg.tn == 2
        assert agg.fp == 0

    def test_error_gets_own_cell_not_tn_or_fn(self):
        rows = [
            # expected=clean, actual=error: must NOT count as TN
            _row("a:f1", "aliasing", "clean", "error"),
            # expected=finding, actual=error: must NOT count as FN
            _row("a:f2", "aliasing", "finding", "error"),
            _row("a:f3", "aliasing", "finding", "finding"),
        ]
        agg, per_class, _ = compute_metrics(rows)
        assert agg.error == 2
        assert agg.tn == 0
        assert agg.fn == 0
        assert agg.tp == 1
        # recall denominator excludes the errored finding label
        assert agg.recall == 1.0
        assert per_class["aliasing"].error == 2

    def test_suspicious_counts_as_claim(self):
        rows = [
            # suspicious hit on a finding label: TP, consistent with
            # the lenient verdict match the runner reports
            _row("a:f1", "aliasing", "finding", "suspicious"),
            # suspicious alarm on a clean label: FP, not TN
            _row("a:f2", "aliasing", "clean", "suspicious"),
        ]
        agg, _, _ = compute_metrics(rows)
        assert agg.tp == 1
        assert agg.fp == 1
        assert agg.tn == 0
        assert agg.fn == 0

    def test_skipped_counted_and_still_classified(self):
        rows = [
            _row("a:f1", "aliasing", "finding", "clean", skipped=True),
            _row("a:f2", "aliasing", "clean", "clean", skipped=False),
        ]
        agg, _, skipped = compute_metrics(rows)
        assert skipped == 1
        # the mechanically-skipped miss still counts as FN — the
        # end-to-end verdict is what the corpus measures
        assert agg.fn == 1
        assert agg.tn == 1


class TestErrorRows:
    def test_selects_only_errors(self):
        rows = [
            _row("a:f1", "aliasing", "clean", "error", error="boom"),
            _row("a:f2", "aliasing", "clean", "clean"),
        ]
        errs = error_rows(rows)
        assert [r["function_id"] for r in errs] == ["a:f1"]


class TestCheckGate:
    def test_trap_finding_fails(self):
        rows = [
            _row("h:f1", "trap", "dormant", "finding"),
            _row("a:f1", "aliasing", "finding", "finding"),
        ]
        agg, per_class, _ = compute_metrics(rows)
        failures = check_gate(agg, per_class, rows)
        assert any("Trap" in f for f in failures)

    def test_trap_suspicious_also_fails(self):
        rows = [
            _row("h:f1", "trap", "dormant", "suspicious"),
        ]
        agg, per_class, _ = compute_metrics(rows)
        failures = check_gate(agg, per_class, rows)
        msgs = [f for f in failures if "Trap" in f]
        assert len(msgs) == 1
        assert "h:f1" in msgs[0]

    def test_trap_dormant_passes(self):
        rows = [
            _row("h:f1", "trap", "dormant", "dormant"),
            _row("h:f2", "trap", "dormant", "clean"),
        ]
        agg, per_class, _ = compute_metrics(rows)
        failures = check_gate(agg, per_class, rows)
        assert not failures

    def test_precision_floor(self):
        rows = [
            _row("a:f1", "aliasing", "finding", "finding"),
            _row("a:f2", "aliasing", "clean", "finding"),
            _row("a:f3", "aliasing", "clean", "finding"),
            _row("a:f4", "aliasing", "clean", "finding"),
        ]
        agg, per_class, _ = compute_metrics(rows)
        failures = check_gate(agg, per_class, rows, precision_floor=0.5)
        assert any("Precision floor" in f for f in failures)

    def test_zero_recall_fails(self):
        rows = [
            _row("a:f1", "aliasing", "finding", "clean"),
            _row("a:f2", "aliasing", "finding", "clean"),
            _row("a:f3", "aliasing", "clean", "clean"),
        ]
        agg, per_class, _ = compute_metrics(rows)
        failures = check_gate(agg, per_class, rows)
        assert any("aliasing has 0% recall" in f for f in failures)

    def test_all_clean_no_false_alarm(self):
        rows = [
            _row("a:f1", "aliasing", "clean", "clean"),
            _row("b:f1", "auth", "clean", "clean"),
        ]
        agg, per_class, _ = compute_metrics(rows)
        failures = check_gate(agg, per_class, rows)
        assert not failures

    def test_error_fraction_gate_fails_and_lists_labels(self):
        rows = [
            _row("a:f1", "aliasing", "clean", "error"),
            _row("a:f2", "aliasing", "finding", "error"),
            _row("a:f3", "aliasing", "finding", "finding"),
            _row("a:f4", "aliasing", "clean", "clean"),
        ]
        agg, per_class, _ = compute_metrics(rows)
        failures = check_gate(agg, per_class, rows, max_error_fraction=0.1)
        msgs = [f for f in failures if "Error fraction" in f]
        assert len(msgs) == 1
        assert "a:f1" in msgs[0]
        assert "a:f2" in msgs[0]
        assert "a:f3" not in msgs[0]

    def test_error_fraction_gate_respects_threshold(self):
        rows = [
            _row("a:f1", "aliasing", "clean", "error"),
            _row("a:f2", "aliasing", "finding", "finding"),
            _row("a:f3", "aliasing", "clean", "clean"),
            _row("a:f4", "aliasing", "clean", "clean"),
        ]
        agg, per_class, _ = compute_metrics(rows)
        # 25% errored, threshold 50% — passes
        failures = check_gate(agg, per_class, rows, max_error_fraction=0.5)
        assert not any("Error fraction" in f for f in failures)

    def test_no_errors_no_error_gate(self):
        rows = [_row("a:f1", "aliasing", "clean", "clean")]
        agg, per_class, _ = compute_metrics(rows)
        failures = check_gate(agg, per_class, rows, max_error_fraction=0.0)
        assert not any("Error fraction" in f for f in failures)


class TestDiffRuns:
    def test_shows_flips(self):
        before = [
            _row("a:f1", "aliasing", "finding", "clean"),
            _row("a:f2", "aliasing", "clean", "clean"),
        ]
        after = [
            _row("a:f1", "aliasing", "finding", "finding"),
            _row("a:f2", "aliasing", "clean", "clean"),
        ]
        result = diff_runs(before, after)
        assert "a:f1" in result
        assert "improved" in result

    def test_no_changes(self):
        rows = [_row("a:f1", "aliasing", "finding", "finding")]
        result = diff_runs(rows, rows)
        assert "No classification changes" in result

    def test_regression_detected(self):
        before = [_row("a:f1", "aliasing", "finding", "finding")]
        after = [_row("a:f1", "aliasing", "finding", "clean")]
        result = diff_runs(before, after)
        assert "regressed" in result

    def test_flip_to_error_reported_as_errored(self):
        before = [_row("a:f1", "aliasing", "finding", "finding")]
        after = [_row("a:f1", "aliasing", "finding", "error")]
        result = diff_runs(before, after)
        assert "errored" in result
        assert "improved" not in result


class TestFormatReport:
    def test_includes_model(self):
        agg = ClassMetrics(tp=1, fp=0, tn=2, fn=0)
        per = {"aliasing": ClassMetrics(tp=1, fp=0, tn=2, fn=0)}
        report = format_report(agg, per, model="haiku")
        assert "haiku" in report
        assert "aliasing" in report

    def test_error_column_and_note(self):
        agg = ClassMetrics(tp=1, fp=0, tn=2, fn=0, error=2)
        per = {"aliasing": ClassMetrics(tp=1, fp=0, tn=2, fn=0, error=2)}
        report = format_report(agg, per)
        assert "Err" in report
        assert "2 error(s) excluded from P/R" in report

    def test_skipped_note(self):
        agg = ClassMetrics(tn=3)
        per = {"clean": ClassMetrics(tn=3)}
        report = format_report(agg, per, skipped=3)
        assert "3 mechanically skipped" in report


class TestStatusMatches:
    def test_finding_accepts_suspicious(self):
        assert status_matches("finding", "suspicious")
        assert status_matches("finding", "finding")
        assert not status_matches("finding", "clean")

    def test_clean_dormant_interchangeable(self):
        assert status_matches("clean", "dormant")
        assert status_matches("dormant", "clean")
        assert not status_matches("dormant", "finding")

    def test_error_never_matches(self):
        assert not status_matches("clean", "error")
        assert not status_matches("finding", "error")


class TestComputeAttribution:
    def test_respects_runner_annotation(self):
        rows = [
            _row("a:f1", "clean", "clean", "clean",
                 expected_mechanism="refutation:contract",
                 attribution="attributed",
                 observed_mechanisms=["refutation:contract"],
                 match=True),
        ]
        summary = compute_attribution(rows)
        assert summary.cells["attributed"] == 1
        assert summary.checked == 1

    def test_falls_back_to_row_level(self):
        # No stored attribution: derive from evidence_tool
        rows = [
            _row("a:f1", "clean", "clean", "clean",
                 expected_mechanism="refutation:contract",
                 evidence_tool="triage:classifier", match=True),
        ]
        summary = compute_attribution(rows)
        assert summary.cells["misattributed"] == 1
        assert summary.misattributed[0]["function_id"] == "a:f1"
        assert "triage:classifier" in (
            summary.misattributed[0]["observed_mechanisms"]
        )

    def test_unattributed_reported_not_failed(self):
        rows = [
            _row("a:f1", "clean", "clean", "clean",
                 expected_mechanism="refutation:contract", match=True),
        ]
        summary = compute_attribution(rows)
        assert summary.cells["unattributed"] == 1
        assert summary.unattributed[0]["expected_mechanism"] == (
            "refutation:contract"
        )

    def test_report_flags_misattributed_loudly(self):
        rows = [
            _row("a:f1", "clean", "clean", "clean",
                 expected_mechanism="concept_compiler",
                 evidence_tool="triage:classifier", match=True),
        ]
        report = format_attribution_report(compute_attribution(rows))
        assert "MISATTRIBUTED a:f1" in report
        assert "concept_compiler" in report


class TestModeMismatches:
    def test_single_mode_row(self):
        rows = [
            _row("a:f1", "finding", "clean", "clean",
                 mode="security",
                 expected_mode_results={"security": "finding"}),
        ]
        checked, mismatches = compute_mode_mismatches(rows)
        assert checked == 1
        assert mismatches == [{
            "function_id": "a:f1", "mode": "security",
            "expected": "finding", "actual": "clean",
        }]

    def test_ensemble_per_mode_actuals(self):
        rows = [
            _row("a:f1", "finding", "finding", "finding",
                 mode="ensemble",
                 security_actual="clean",
                 bug_first_actual="finding",
                 expected_mode_results={
                     "security": "finding", "bug_first": "finding",
                 }),
        ]
        checked, mismatches = compute_mode_mismatches(rows)
        assert checked == 2
        assert len(mismatches) == 1
        assert mismatches[0]["mode"] == "security"

    def test_unexercised_mode_not_counted(self):
        rows = [
            _row("a:f1", "clean", "clean", "clean",
                 mode="security",
                 expected_mode_results={
                     "security": "clean", "quality": "clean",
                 }),
        ]
        checked, mismatches = compute_mode_mismatches(rows)
        assert checked == 1  # quality never ran — not guessed
        assert not mismatches

    def test_errored_rows_excluded(self):
        rows = [
            _row("a:f1", "clean", "error", "error",
                 mode="security",
                 expected_mode_results={"security": "clean"}),
        ]
        checked, mismatches = compute_mode_mismatches(rows)
        assert checked == 0
        assert not mismatches

    def test_lenient_status_matching(self):
        rows = [
            _row("a:f1", "finding", "suspicious", "suspicious",
                 mode="security", match=True,
                 expected_mode_results={"security": "finding"}),
        ]
        checked, mismatches = compute_mode_mismatches(rows)
        assert checked == 1
        assert not mismatches

    def test_format_mode_report(self):
        report = format_mode_report(3, [{
            "function_id": "a:f1", "mode": "security",
            "expected": "finding", "actual": "clean",
        }])
        assert "3 checked, 1 mismatch(es)" in report
        assert "a:f1 [security]" in report


class TestMisattributionGate:
    def test_misattributed_fails_gate(self):
        rows = [
            _row("a:f1", "clean", "clean", "clean",
                 expected_mechanism="refutation:known_return_type",
                 evidence_tool="triage:classifier", match=True),
        ]
        agg, per_class, _ = compute_metrics(rows)
        failures = check_gate(agg, per_class, rows)
        msgs = [f for f in failures if "Misattribution" in f]
        assert len(msgs) == 1
        assert "a:f1" in msgs[0]
        assert "refutation:known_return_type" in msgs[0]

    def test_attributed_passes_gate(self):
        rows = [
            _row("a:f1", "clean", "clean", "clean",
                 expected_mechanism="refutation:contract",
                 hypothesis="[contract: callers checksum first]",
                 match=True),
        ]
        agg, per_class, _ = compute_metrics(rows)
        failures = check_gate(agg, per_class, rows)
        assert not any("Misattribution" in f for f in failures)

    def test_unattributed_does_not_fail_gate(self):
        # No receipt at all is reported, not gated — old results and
        # receipt-less mechanisms must not hard-fail.
        rows = [
            _row("a:f1", "clean", "clean", "clean",
                 expected_mechanism="concept_compiler", match=True),
        ]
        agg, per_class, _ = compute_metrics(rows)
        failures = check_gate(agg, per_class, rows)
        assert not any("Misattribution" in f for f in failures)


class TestReadResults:
    def test_reads_wrapped_json(self, tmp_path):
        p = tmp_path / "results.json"
        p.write_text(json.dumps({
            "meta": {"count": 1},
            "results": [_row("a:f1", "aliasing", "clean", "clean")],
        }))
        rows = _read_results(p)
        assert len(rows) == 1
        assert rows[0]["function_id"] == "a:f1"

    def test_reads_bare_list_json(self, tmp_path):
        p = tmp_path / "results.json"
        p.write_text(json.dumps([_row("a:f1", "aliasing", "clean", "clean")]))
        rows = _read_results(p)
        assert len(rows) == 1

    def test_reads_legacy_csv(self, tmp_path):
        p = tmp_path / "results.csv"
        p.write_text(
            "function_id,bug_class,expected,actual,model\n"
            "a:f1,aliasing,clean,clean,test\n"
        )
        rows = _read_results(p)
        assert rows[0]["actual"] == "clean"

    def test_rejects_unknown_shape(self, tmp_path):
        p = tmp_path / "results.json"
        p.write_text('{"nope": 1}')
        with pytest.raises(ValueError, match="expected a result list"):
            _read_results(p)


class TestMainCLI:
    def test_gate_failure_exits_nonzero(self, tmp_path, capsys):
        p = tmp_path / "results.json"
        rows = [
            _row("a:f1", "aliasing", "clean", "error", error="crashed"),
            _row("a:f2", "aliasing", "finding", "finding"),
        ]
        p.write_text(json.dumps({"meta": {}, "results": rows}))
        rc = main([str(p), "--check-gate", "--max-error-fraction", "0.1"])
        out = capsys.readouterr().out
        assert rc == 1
        assert "GATE FAIL" in out
        assert "Error fraction" in out
        assert "crashed" in out  # error reason surfaced

    def test_clean_run_exits_zero(self, tmp_path, capsys):
        p = tmp_path / "results.json"
        rows = [_row("a:f1", "aliasing", "finding", "finding")]
        p.write_text(json.dumps(rows))
        rc = main([str(p), "--check-gate"])
        assert rc == 0

    def test_old_rows_enriched_from_committed_labels(
        self, tmp_path, capsys, monkeypatch,
    ):
        # A row for a committed label, written before attribution
        # fields existed: recompute joins expected_mechanism from the
        # label and attributes from row-level signals.
        import core.audit.corpus.label as label_mod

        label_file = tmp_path / "l.label.json"
        label_file.write_text(json.dumps({
            "function_id": "lex/lexer.go:readNumber",
            "bug_class": "integer",
            "expected_status": "clean",
            "rationale": "bounded readNumber loop",
            "expected_mechanism": "refutation:bounds",
            "source": {
                "repo": "demo-repo", "sha": "abc123",
                "file": "lex/lexer.go",
                "line_start": 1, "line_end": 10,
            },
            "labeler": "t", "labeled_at": "2026-01-01",
        }))
        label = label_mod.load_label(label_file)
        monkeypatch.setattr(
            label_mod, "load_all_labels", lambda **kw: [label],
        )
        p = tmp_path / "results.json"
        rows = [{
            "function_id": "lex/lexer.go:readNumber",
            "bug_class": "integer",
            "expected": "clean",
            "actual": "clean",
            "match": True,
            "evidence_tool": "triage:classifier",
            "model": "test",
        }]
        p.write_text(json.dumps(rows))
        rc = main([str(p)])
        out = capsys.readouterr().out
        assert rc == 0
        assert "Enriched 1 row(s)" in out
        assert "Mechanism attribution" in out
        assert "MISATTRIBUTED lex/lexer.go:readNumber" in out

    def test_run_dir_joins_receipts(self, tmp_path, capsys):
        run = tmp_path / "run" / "repo"
        run.mkdir(parents=True)
        (run / ".audit-log.jsonl").write_text(json.dumps({
            "action": "refutation_gate", "gate": "contract",
            "key": "a.c:f:10", "applied": True,
        }) + "\n")
        p = tmp_path / "results.json"
        rows = [_row("a:f1", "aliasing", "clean", "clean",
                     match=True, function_id="a.c:f",
                     expected_mechanism="refutation:contract",
                     expected_mode_results={})]
        rows[0]["function_id"] = "a.c:f"
        p.write_text(json.dumps(rows))
        rc = main([str(p), "--run-dir", str(tmp_path / "run"),
                   "--check-gate"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "recomputed from 1 run dir(s)" in out.lower()
        assert "attributed (right verdict, right mechanism):     1" in out
