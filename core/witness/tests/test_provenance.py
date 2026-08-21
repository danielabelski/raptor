"""Tests for core/witness/provenance.py — unforgeable markers on
witness/feasibility evidence records (W1 witness/verdict provenance).
"""

from __future__ import annotations

import os

import pytest

from core.witness import provenance as prov


@pytest.fixture(autouse=True)
def _isolated_key(tmp_path, monkeypatch):
    """Every test gets its own key under a private XDG_DATA_HOME."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    yield


def _finding(**kw):
    base = {"id": "F-001", "file": "src/a.c", "function": "parse"}
    base.update(kw)
    return base


class TestMintVerify:
    def test_round_trip(self, tmp_path):
        fields = {"kind": "witness-execution", "run": "r1", "verdict": "confirmed"}
        token = prov.mint(fields)
        assert token
        assert prov.verify(fields, token)

    def test_field_tamper_fails(self, tmp_path):
        fields = {"kind": "witness-execution", "run": "r1", "verdict": "refuted"}
        token = prov.mint(fields)
        assert not prov.verify({**fields, "verdict": "confirmed"}, token)

    def test_kind_domain_separation(self, tmp_path):
        base = {"run": "r1", "verdict": "confirmed"}
        t1 = prov.mint({**base, "kind": "witness-execution"})
        assert not prov.verify({**base, "kind": "feasibility-analysis"}, t1)

    def test_mint_requires_kind(self):
        with pytest.raises(ValueError):
            prov.mint({"run": "r1"})

    def test_missing_token_fails(self):
        assert not prov.verify({"kind": "x"}, None)
        assert not prov.verify({"kind": "x"}, "")

    def test_key_file_is_private(self, tmp_path):
        prov.mint({"kind": "witness-execution"})
        key = tmp_path / "xdg" / "raptor" / "witness-mac.key"
        assert key.is_file()
        assert (key.stat().st_mode & 0o077) == 0

    def test_group_readable_key_refused(self, tmp_path):
        prov.mint({"kind": "witness-execution"})
        key = tmp_path / "xdg" / "raptor" / "witness-mac.key"
        os.chmod(key, 0o644)
        prov._warned_paths.clear()
        assert prov.mint({"kind": "witness-execution"}) is None
        assert not prov.key_usable()


class TestStampAndVerifyRecords:
    def test_witness_execution_round_trip(self, tmp_path):
        f = _finding()
        record = {"verdict": "confirmed", "match_detail": "ok"}
        f["witness_execution"] = record
        prov.stamp_witness_execution(f, record, tmp_path)
        assert record[prov.PROVENANCE_KEY]
        assert prov.verify_witness_execution(f, tmp_path)

    def test_witness_execution_run_binding(self, tmp_path):
        f = _finding()
        record = {"verdict": "confirmed"}
        f["witness_execution"] = record
        prov.stamp_witness_execution(f, record, tmp_path / "run-a")
        assert prov.verify_witness_execution(f, tmp_path / "run-a")
        # Replay into another run directory fails.
        assert not prov.verify_witness_execution(f, tmp_path / "run-b")

    def test_witness_execution_verdict_flip_fails(self, tmp_path):
        f = _finding()
        record = {"verdict": "refuted"}
        f["witness_execution"] = record
        prov.stamp_witness_execution(f, record, tmp_path)
        record["verdict"] = "confirmed"
        assert not prov.verify_witness_execution(f, tmp_path)

    def test_witness_execution_finding_swap_fails(self, tmp_path):
        f = _finding()
        record = {"verdict": "confirmed"}
        f["witness_execution"] = record
        prov.stamp_witness_execution(f, record, tmp_path)
        # Grafting the stamped record onto a different finding fails.
        other = _finding(function="lookalike")
        other["witness_execution"] = dict(record)
        assert not prov.verify_witness_execution(other, tmp_path)

    def test_feasibility_round_trip(self, tmp_path):
        f = _finding()
        feas = {"status": "analyzed", "verdict": "exploitable",
                "binary_path": "/bin/app"}
        f["feasibility"] = feas
        prov.stamp_feasibility(f, feas, tmp_path)
        assert prov.verify_feasibility(f, tmp_path)
        feas["verdict"] = "likely_exploitable"
        assert not prov.verify_feasibility(f, tmp_path)

    def test_unstamped_records_never_verify(self, tmp_path):
        f = _finding(witness_execution={"verdict": "confirmed"},
                     feasibility={"status": "analyzed", "verdict": "exploitable"})
        assert not prov.verify_witness_execution(f, tmp_path)
        assert not prov.verify_feasibility(f, tmp_path)


class TestSanitiseFindingsEvidence:
    def test_forged_witness_record_stripped_and_ruling_rolled_back(self, tmp_path):
        f = _finding(
            witness_execution={"verdict": "confirmed"},
            ruling={"status": "confirmed", "witness": "dark_verify:confirmed"},
            status="confirmed",
        )
        stats = prov.sanitise_findings_evidence({"findings": [f]}, tmp_path)
        assert stats["witness_stripped"] == 1
        assert "witness_execution" not in f
        assert f["ruling"].get("witness") is None
        assert f["ruling"]["status"] == "confirmed_unverified"
        assert f["status"] == "confirmed_unverified"

    def test_forged_refutation_rolled_back_to_pending(self, tmp_path):
        f = _finding(
            witness_execution={"verdict": "refuted"},
            ruling={"status": "ruled_out", "disqualifier": "witness_refuted",
                    "witness": "dark_verify:refuted"},
            status="ruled_out",
        )
        prov.sanitise_findings_evidence({"findings": [f]}, tmp_path)
        assert "witness_execution" not in f
        assert "ruling" not in f
        assert f["status"] == "pending"

    def test_ruling_marker_without_record_stripped(self, tmp_path):
        f = _finding(
            ruling={"status": "confirmed", "witness": "dark_verify:confirmed"},
        )
        stats = prov.sanitise_findings_evidence({"findings": [f]}, tmp_path)
        assert stats["witness_stripped"] == 1
        assert f["ruling"]["status"] == "confirmed_unverified"

    def test_stamped_record_survives(self, tmp_path):
        f = _finding(status="confirmed")
        record = {"verdict": "confirmed"}
        f["witness_execution"] = record
        f["ruling"] = {"status": "confirmed",
                       "witness": "dark_verify:confirmed"}
        prov.stamp_witness_execution(f, record, tmp_path)
        stats = prov.sanitise_findings_evidence({"findings": [f]}, tmp_path)
        assert stats["witness_stripped"] == 0
        assert f["witness_execution"]["verdict"] == "confirmed"
        assert f["ruling"]["status"] == "confirmed"

    def test_marker_grafted_onto_other_verdict_stripped(self, tmp_path):
        # Verified refuted record + a hand-added confirmed marker.
        f = _finding(status="confirmed")
        record = {"verdict": "refuted"}
        f["witness_execution"] = record
        prov.stamp_witness_execution(f, record, tmp_path)
        f["ruling"] = {"status": "confirmed",
                       "witness": "dark_verify:confirmed"}
        stats = prov.sanitise_findings_evidence({"findings": [f]}, tmp_path)
        assert stats["witness_stripped"] == 1
        assert "witness_execution" not in f

    def test_forged_analyzed_feasibility_demoted(self, tmp_path):
        f = _finding(
            feasibility={"status": "analyzed", "verdict": "exploitable",
                         "chain_breaks": ["waf"]},
            final_status="exploitable",
            is_exploitable=True,
        )
        stats = prov.sanitise_findings_evidence({"findings": [f]}, tmp_path)
        assert stats["feasibility_demoted"] == 1
        assert f["feasibility"]["status"] == "pending"
        assert "verdict" not in f["feasibility"]
        # LLM-tier source content survives for re-derivation.
        assert f["feasibility"]["chain_breaks"] == ["waf"]
        assert f["final_status"] == "confirmed_unverified"
        assert f["is_exploitable"] is False

    def test_stamped_feasibility_survives(self, tmp_path):
        f = _finding(final_status="exploitable")
        feas = {"status": "analyzed", "verdict": "exploitable",
                "binary_path": "/bin/app"}
        f["feasibility"] = feas
        prov.stamp_feasibility(f, feas, tmp_path)
        stats = prov.sanitise_findings_evidence({"findings": [f]}, tmp_path)
        assert stats["feasibility_demoted"] == 0
        assert stats["final_status_demoted"] == 0
        assert f["final_status"] == "exploitable"
        assert f["feasibility"]["verdict"] == "exploitable"

    def test_bare_exploitable_final_status_clamped(self, tmp_path):
        # No feasibility at all — a pre-set verdict-tier final_status
        # is quarantined.
        f = _finding(final_status="likely_exploitable", is_exploitable=True)
        stats = prov.sanitise_findings_evidence({"findings": [f]}, tmp_path)
        assert stats["final_status_demoted"] == 1
        assert f["final_status"] == "confirmed_unverified"
        assert f["is_exploitable"] is False

    def test_non_dict_shapes_tolerated(self, tmp_path):
        assert prov.sanitise_findings_evidence(None, tmp_path) == {
            "witness_stripped": 0, "feasibility_demoted": 0,
            "final_status_demoted": 0,
        }
        prov.sanitise_findings_evidence({"findings": "nope"}, tmp_path)
        prov.sanitise_findings_evidence({"findings": [42, None]}, tmp_path)
