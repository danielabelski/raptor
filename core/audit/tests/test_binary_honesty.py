"""Gate-engagement honesty on binary items.

Four of the five refutation gates need inputs a binary checklist
cannot provide (domain model, main-rooted call graph, function
source). These tests pin that a gate which could NOT run leaves a
journal record naming the missing prerequisite — distinct from a
gate that ran and passed — that the run-level channel skips are
declared, and that the run summary aggregates the records. Records
only: none of this touches verdicts.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from core.audit.binary_honesty import (
    BINARY_DISABLED_CHANNELS,
    REFUTATION_GATES,
    declare_binary_channel_skips,
    diagnose_gate_engagement,
    journal_binary_provenance,
    record_gate_engagement,
    summarize_gate_engagement,
)


def _outcome(file="binary:demo", function="fcn_handler",
             hypothesis="integer overflow via ntohs in fcn_handler",
             evidence_tool="", status="suspicious"):
    return SimpleNamespace(
        file=file, function=function, hypothesis=hypothesis,
        evidence_tool=evidence_tool, status=status,
    )


def _binary_checklist(with_calls=False, with_source=False):
    item = {
        "name": "fcn_handler", "kind": "function",
        "address": 0x401000, "size": 128,
        "metadata": {"address": 0x401000, "size": 128},
    }
    if with_source:
        item["source"] = "int fcn_handler(void) { return helper(); }"
    fentry = {
        "path": "binary:demo",
        "language": "binary",
        "sha256": "ab" * 32,
        "items": [item],
    }
    if with_calls:
        fentry["call_graph"] = {"calls": [
            {"caller": "main", "chain": ["fcn_handler"], "line": 10},
            {"caller": "fcn_handler", "chain": ["helper"], "line": 20},
        ]}
    return {
        "target_path": "/x/demo",
        "target_kind": "binary",
        "files": [fentry],
        "binary_stats": {
            "total_functions": 1,
            "named_functions": 0,
            "auto_named": 1,
            "auto_named_ratio": 1.0,
            "name_provenance_counts": {"tool_synthetic": 1},
            "source_tool": "r2",
            "provenance": {
                "probe": "readelf",
                "build_id": "aabbccdd",
                "has_dwarf": False,
                "has_symtab": False,
                "has_dynsym": True,
                "stripped": True,
                "fortified": False,
                "fortified_imports": [],
            },
        },
    }


def _read_log(out_dir):
    log = Path(out_dir) / ".audit-log.jsonl"
    if not log.is_file():
        return []
    return [json.loads(line) for line in log.read_text().splitlines()]


class TestDiagnoseGateEngagement:
    def test_bare_binary_item_reports_gates_1_2_3_6_could_not_run(self):
        """On a binary checklist with no domain model, no calls, and
        no source, the architecture / lifecycle / contract / callee
        gates must say could-not-run with the missing prerequisite
        named — never silently pass."""
        records = diagnose_gate_engagement(
            _outcome(),
            domain_model=None,
            checklist=_binary_checklist(),
        )
        by_gate = {r["gate"]: r for r in records}
        assert set(by_gate) == set(REFUTATION_GATES)

        assert by_gate["architecture"]["engaged"] is False
        assert by_gate["architecture"]["blocked_on"] == "domain_model"
        assert by_gate["lifecycle"]["engaged"] is False
        assert (
            by_gate["lifecycle"]["blocked_on"]
            == "checklist.call_graph.calls"
        )
        assert by_gate["contract"]["engaged"] is False
        assert by_gate["contract"]["blocked_on"] == "domain_model"
        assert by_gate["callee_inheritance"]["engaged"] is False
        assert by_gate["callee_inheritance"]["blocked_on"] == "item.source"

        # The text-only gate needs no checklist inputs — live.
        assert by_gate["input_bound_t0"]["engaged"] is True
        assert by_gate["input_bound_t0"]["blocked_on"] is None

    def test_satisfied_inputs_report_all_gates_live(self):
        records = diagnose_gate_engagement(
            _outcome(),
            domain_model={
                "architecture": {"threading_model": "single_threaded"},
                "contracts": [{"function": "fcn_handler"}],
            },
            checklist=_binary_checklist(with_calls=True,
                                        with_source=True),
        )
        assert all(r["engaged"] for r in records)
        assert all(r["blocked_on"] is None for r in records)

    def test_call_graph_without_main_root_named_specifically(self):
        checklist = _binary_checklist(with_calls=True)
        checklist["files"][0]["call_graph"]["calls"] = [
            {"caller": "fcn_handler", "chain": ["helper"], "line": 20},
        ]
        records = diagnose_gate_engagement(
            _outcome(), domain_model=None, checklist=checklist,
        )
        by_gate = {r["gate"]: r for r in records}
        assert (
            by_gate["lifecycle"]["blocked_on"]
            == "checklist.call_graph.calls[main]"
        )

    def test_tool_evidence_outcomes_are_design_passes_not_records(self):
        records = diagnose_gate_engagement(
            _outcome(evidence_tool="semgrep"),
            domain_model=None,
            checklist=_binary_checklist(),
        )
        assert records == []

    def test_no_hypothesis_no_records(self):
        records = diagnose_gate_engagement(
            _outcome(hypothesis=""),
            domain_model=None,
            checklist=_binary_checklist(),
        )
        assert records == []


class TestRecordGateEngagement:
    def test_binary_outcome_journals_engagement(self, tmp_path):
        records = record_gate_engagement(
            tmp_path, _outcome(),
            domain_model=None, checklist=_binary_checklist(),
        )
        assert records
        entries = [
            e for e in _read_log(tmp_path)
            if e.get("action") == "refutation_gate_engagement"
        ]
        assert len(entries) == 1
        entry = entries[0]
        assert entry["file"] == "binary:demo"
        assert entry["function"] == "fcn_handler"
        gates = {g["gate"]: g for g in entry["gates"]}
        assert gates["architecture"]["engaged"] is False
        assert gates["input_bound_t0"]["engaged"] is True

    def test_source_outcomes_are_not_recorded(self, tmp_path):
        records = record_gate_engagement(
            tmp_path, _outcome(file="src/parser.c"),
            domain_model=None, checklist=None,
        )
        assert records == []
        assert _read_log(tmp_path) == []

    def test_never_raises_on_bad_inputs(self, tmp_path):
        assert record_gate_engagement(
            tmp_path, SimpleNamespace(file="binary:x"),
            domain_model=None, checklist=None,
        ) == []


class TestChannelSkipDeclaration:
    def test_declares_structurally_disabled_channels(self, tmp_path):
        declare_binary_channel_skips(tmp_path, _binary_checklist())
        entries = [
            e for e in _read_log(tmp_path)
            if e.get("action") == "tool_coverage_declaration"
        ]
        assert len(entries) == 1
        skipped = entries[0]["skipped_channels"]
        # The two channels that today no-op silently instead of
        # skipping loudly must be declared, with reasons.
        assert "checker_synthesis" in skipped
        assert "consistency" in skipped
        assert all(isinstance(v, str) and v for v in skipped.values())
        assert skipped == BINARY_DISABLED_CHANNELS
        assert entries[0]["target_kind"] == "binary"


class TestBinaryProvenanceJournal:
    def test_journals_block_and_persists_in_build_id_cache(
            self, tmp_path, monkeypatch):
        cache_dir = tmp_path / "cache"
        monkeypatch.setenv("RAPTOR_BINARY_CACHE_DIR", str(cache_dir))
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        journal_binary_provenance(out_dir, _binary_checklist())

        entries = [
            e for e in _read_log(out_dir)
            if e.get("action") == "binary_target_provenance"
        ]
        assert len(entries) == 1
        stats = entries[0]["binary_stats"]
        assert stats["auto_named_ratio"] == 1.0
        assert stats["provenance"]["stripped"] is True

        artifact = cache_dir / "aabbccdd" / "binary-provenance.json"
        assert artifact.is_file()
        envelope = json.loads(artifact.read_text())
        assert envelope["artifact"] == "binary-provenance"
        assert envelope["data"]["provenance"]["stripped"] is True
        assert envelope["data"]["name_provenance_counts"] == {
            "tool_synthetic": 1,
        }
        # Content binding: the checklist's binary hash rides along.
        assert envelope["binary_sha256"] == "ab" * 32

    def test_no_build_id_no_cache_entry(self, tmp_path, monkeypatch):
        cache_dir = tmp_path / "cache"
        monkeypatch.setenv("RAPTOR_BINARY_CACHE_DIR", str(cache_dir))
        checklist = _binary_checklist()
        checklist["binary_stats"]["provenance"]["build_id"] = None

        journal_binary_provenance(tmp_path, checklist)

        assert [
            e for e in _read_log(tmp_path)
            if e.get("action") == "binary_target_provenance"
        ]
        assert not (cache_dir / "aabbccdd").exists()

    def test_source_checklist_is_untouched(self, tmp_path):
        journal_binary_provenance(
            tmp_path, {"target_kind": "source", "files": []},
        )
        assert _read_log(tmp_path) == []


class TestRunSummary:
    def test_aggregates_live_and_blocked_counts(self, tmp_path):
        for i in range(3):
            record_gate_engagement(
                tmp_path, _outcome(function=f"fcn_{i}"),
                domain_model=None, checklist=_binary_checklist(),
            )
        line = summarize_gate_engagement(tmp_path)
        assert line is not None
        assert line.startswith("Refutation gate engagement")
        assert "architecture 0/3 live" in line
        assert "domain_model x3" in line
        assert "input_bound_t0 3/3 live" in line

    def test_silent_when_no_records(self, tmp_path):
        assert summarize_gate_engagement(tmp_path) is None
