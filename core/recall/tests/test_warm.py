"""Tests for mechanical-warm (would-suppress) scoring."""

from __future__ import annotations

import json

from core.recall.warm import (
    apply_would_suppress,
    load_suppression_records,
    matched_expected_entries,
    render_warm_markdown,
)


def _record(**kw):
    base = {
        "finding_id": "f1",
        "rule_id": "r.xss",
        "file_path": "/work/repo/src/A.java",
        "line": 42,
        "function": "doPost",
        "verdict": "sanitizer_dominated",
        "reason": "value-bound cut",
        "dropped": False,
    }
    base.update(kw)
    return base


def _report(clean_fps, missed=None):
    return {
        "clean_region_fps": clean_fps,
        "missed": missed or [],
    }


class TestLoadRecords:
    def test_parses_and_counts_malformed(self, tmp_path):
        p = tmp_path / "suppressions.jsonl"
        p.write_text(json.dumps(_record()) + "\nnot-json\n\n",
                     encoding="utf-8")
        records = load_suppression_records(p)
        assert len(records) == 2
        assert sum(1 for r in records if r.get("_malformed")) == 1

    def test_missing_file_is_empty(self, tmp_path):
        assert load_suppression_records(tmp_path / "nope.jsonl") == []


class TestApplyWouldSuppress:
    def test_file_level_fp_suppressed_by_path_and_rule(self):
        fp = {"id": "A", "cwe": "CWE-79", "file": "src/A.java",
              "line_start": None, "rules": ["r.xss"]}
        warm = apply_would_suppress(_report([fp]), [_record()])
        assert warm["would_suppress_fps"] == 1
        assert warm["warm_clean_region_fps"] == 0
        assert warm["per_cwe"][0]["warm_fps"] == 0
        assert warm["fp_suppressions"][0]["verdict"] == "sanitizer_dominated"

    def test_rule_mismatch_does_not_suppress(self):
        fp = {"id": "A", "cwe": "CWE-79", "file": "src/A.java",
              "line_start": None, "rules": ["r.other"]}
        warm = apply_would_suppress(_report([fp]), [_record()])
        assert warm["would_suppress_fps"] == 0
        assert warm["warm_clean_region_fps"] == 1

    def test_line_scoped_entry_respects_drift(self):
        fp = {"id": "A", "cwe": "CWE-79", "file": "src/A.java",
              "line_start": 40, "line_end": 41, "rules": ["r.xss"]}
        assert apply_would_suppress(
            _report([fp]), [_record(line=42)],
        )["would_suppress_fps"] == 1  # within drift 2
        assert apply_would_suppress(
            _report([fp]), [_record(line=99)],
        )["would_suppress_fps"] == 0

    def test_true_finding_damage_counted(self):
        matched = [{"id": "T", "cwe": "CWE-79", "file": "src/A.java",
                    "line_start": None}]
        warm = apply_would_suppress(
            _report([]), [_record()], matched_expected=matched)
        assert warm["true_finding_damage_count"] == 1
        assert warm["true_finding_would_suppress"][0]["id"] == "T"

    def test_raw_numbers_never_change(self):
        fp = {"id": "A", "cwe": "CWE-79", "file": "src/A.java",
              "line_start": None, "rules": ["r.xss"]}
        report = _report([fp])
        apply_would_suppress(report, [_record()])
        assert len(report["clean_region_fps"]) == 1  # untouched

    def test_markdown_renders(self):
        fp = {"id": "A", "cwe": "CWE-79", "file": "src/A.java",
              "line_start": None, "rules": ["r.xss"]}
        warm = apply_would_suppress(_report([fp]), [_record()])
        md = render_warm_markdown(warm)
        assert "would-suppress" in md and "CWE-79" in md


class TestMatchedExpected:
    def test_complement_of_missed(self):
        expected = [{"id": "A"}, {"id": "B"}]
        report = {"missed": [{"id": "B"}]}
        got = matched_expected_entries(report, expected)
        assert [e["id"] for e in got] == ["A"]
