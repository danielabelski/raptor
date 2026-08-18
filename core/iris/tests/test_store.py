"""Tests for core.iris.store — persistent spec storage."""

from core.evidence import EvidenceTier
from core.iris.assumptions import AssumptionCategory, SafetyAssumption
from core.iris.specs import TaintSpec
from core.iris.store import (
    RoundRecord,
    checklist_sha,
    evict_stale,
    load_assumptions,
    load_specs,
    load_store_metadata,
    merge_specs,
    save_specs,
)


def _make_spec(fn="check_input", file="src/auth.py", role="sanitiser", **kw):
    return TaintSpec(function=fn, file=file, role=role, **kw)


class TestChecksumSha:
    def test_deterministic(self):
        cl = {"files": [
            {"path": "a.py", "sha256": "aaa"},
            {"path": "b.py", "sha256": "bbb"},
        ]}
        assert checklist_sha(cl) == checklist_sha(cl)

    def test_order_independent(self):
        cl1 = {"files": [
            {"path": "a.py", "sha256": "aaa"},
            {"path": "b.py", "sha256": "bbb"},
        ]}
        cl2 = {"files": [
            {"path": "b.py", "sha256": "bbb"},
            {"path": "a.py", "sha256": "aaa"},
        ]}
        assert checklist_sha(cl1) == checklist_sha(cl2)

    def test_sha_change_detected(self):
        cl1 = {"files": [{"path": "a.py", "sha256": "aaa"}]}
        cl2 = {"files": [{"path": "a.py", "sha256": "bbb"}]}
        assert checklist_sha(cl1) != checklist_sha(cl2)

    def test_empty_checklist(self):
        assert checklist_sha({}) == checklist_sha({"files": []})


class TestSaveLoad:
    def test_roundtrip(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        specs = [_make_spec(), _make_spec(fn="eval_query", role="sink")]

        save_specs(run_dir, specs, cl_sha="abc123")
        loaded = load_specs(run_dir)

        assert len(loaded) == 2
        funcs = {s.function for s in loaded}
        assert "check_input" in funcs
        assert "eval_query" in funcs

    def test_empty_store(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        assert load_specs(run_dir) == []

    def test_metadata_preserved(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        specs = [_make_spec()]

        save_specs(
            run_dir, specs, cl_sha="xyz", round_num=2,
            history=[{"round": 0, "n_specs": 5, "n_confirmed": 3}],
        )
        meta = load_store_metadata(run_dir)

        assert meta["checklist_sha"] == "xyz"
        assert meta["round"] == 2
        assert len(meta["history"]) == 1

    def test_atomic_overwrite(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)

        save_specs(run_dir, [_make_spec(fn="first")])
        save_specs(run_dir, [_make_spec(fn="second")])

        loaded = load_specs(run_dir)
        assert len(loaded) == 1
        assert loaded[0].function == "second"

    def test_source_field_roundtrip(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        specs = [_make_spec(source="llm")]

        save_specs(run_dir, specs)
        loaded = load_specs(run_dir)

        assert loaded[0].source == "llm"


class TestMergeSpecs:
    def test_no_conflict(self):
        a = [_make_spec(fn="a")]
        b = [_make_spec(fn="b")]
        merged = merge_specs(a, b)
        assert len(merged) == 2

    def test_higher_tier_wins(self):
        old = [_make_spec(evidence_tier=EvidenceTier.HEURISTIC)]
        new = [_make_spec(evidence_tier=EvidenceTier.XREF_BACKED)]
        merged = merge_specs(old, new)
        assert len(merged) == 1
        assert merged[0].evidence_tier == EvidenceTier.XREF_BACKED

    def test_equal_tier_new_wins(self):
        old = [_make_spec(confidence=0.3)]
        new = [_make_spec(confidence=0.9)]
        merged = merge_specs(old, new)
        assert len(merged) == 1
        assert merged[0].confidence == 0.9

    def test_different_roles_kept(self):
        a = [_make_spec(role="sink")]
        b = [_make_spec(role="sanitiser")]
        merged = merge_specs(a, b)
        assert len(merged) == 2

    def test_old_higher_tier_wins(self):
        """Old XREF_BACKED must survive over new HEURISTIC (old-wins)."""
        old = [_make_spec(
            evidence_tier=EvidenceTier.XREF_BACKED, source="operator_confirmed",
        )]
        new = [_make_spec(
            evidence_tier=EvidenceTier.HEURISTIC, source="llm",
        )]
        merged = merge_specs(old, new)
        assert len(merged) == 1
        assert merged[0].evidence_tier == EvidenceTier.XREF_BACKED
        assert merged[0].source == "operator_confirmed"

    def test_empty_inputs(self):
        assert merge_specs([], []) == []
        specs = [_make_spec()]
        assert merge_specs(specs, []) == specs
        assert merge_specs([], specs) == specs


class TestEvictStale:
    def test_keeps_current_files(self):
        specs = [_make_spec(file="a.py"), _make_spec(fn="b", file="b.py")]
        result = evict_stale(specs, {"a.py", "b.py"})
        assert len(result) == 2

    def test_evicts_missing_files(self):
        specs = [_make_spec(file="a.py"), _make_spec(fn="b", file="gone.py")]
        result = evict_stale(specs, {"a.py"})
        assert len(result) == 1
        assert result[0].file == "a.py"

    def test_keeps_confirmed_despite_missing(self):
        specs = [_make_spec(
            file="gone.py", evidence_tier=EvidenceTier.XREF_BACKED,
        )]
        result = evict_stale(specs, {"a.py"})
        assert len(result) == 1

    def test_evicts_heuristic_when_missing(self):
        specs = [_make_spec(
            file="gone.py", evidence_tier=EvidenceTier.HEURISTIC,
        )]
        result = evict_stale(specs, {"a.py"})
        assert len(result) == 0

    def test_empty_specs(self):
        assert evict_stale([], {"a.py"}) == []


class TestAssumptionStorage:
    def _make_assumption(self, **kw):
        return SafetyAssumption(
            target=kw.get("target", "modify_state"),
            file=kw.get("file", "src/state.c"),
            assumption="requires enforcer",
            category=AssumptionCategory.ORDERING,
            enforced_by=kw.get("enforced_by", ["acquire_lock"]),
            evidence_tier=kw.get("evidence_tier", EvidenceTier.HEURISTIC),
        )

    def test_roundtrip(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        specs = [_make_spec()]
        assumptions = [self._make_assumption(), self._make_assumption(target="exec_query")]

        save_specs(run_dir, specs, assumptions=assumptions)
        loaded = load_assumptions(run_dir)

        assert len(loaded) == 2
        targets = {a.target for a in loaded}
        assert targets == {"modify_state", "exec_query"}

    def test_empty_when_no_assumptions(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [_make_spec()])
        loaded = load_assumptions(run_dir)
        assert loaded == []

    def test_empty_when_no_store(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        assert load_assumptions(run_dir) == []

    def test_target_path_filter(self, tmp_path):
        from pathlib import Path
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(
            run_dir, [_make_spec()],
            assumptions=[self._make_assumption()],
            target_path=Path("/repo/a"),
        )
        assert len(load_assumptions(run_dir, target_path=Path("/repo/a"))) == 1
        assert load_assumptions(run_dir, target_path=Path("/repo/b")) == []

    def test_assumptions_in_metadata(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [], assumptions=[self._make_assumption()])
        meta = load_store_metadata(run_dir)
        assert len(meta["assumptions"]) == 1
        assert meta["assumptions"][0]["target"] == "modify_state"


class TestRoundRecord:
    def test_fields(self):
        r = RoundRecord(round=0, n_specs=10, n_confirmed=7, n_refuted=2)
        assert r.round == 0
        assert r.n_specs == 10


class TestLoadRefinedSpecs:
    """Run-local refined-artifact reader (refine-loop continuity)."""

    def _write_artifact(self, run_dir, specs):
        import json

        payload = json.dumps([s.to_dict() for s in specs], indent=2)
        (run_dir / "iris-taint-specs-refined.json").write_text(payload)

    def test_round_trip_preserves_tier_and_source(self, tmp_path):
        from core.iris.store import load_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        self._write_artifact(run_dir, [
            _make_spec(fn="confirmed", role="sanitiser",
                       evidence_tier=EvidenceTier.XREF_BACKED,
                       source="operator_confirmed"),
            _make_spec(fn="guessy", role="sink",
                       evidence_tier=EvidenceTier.HEURISTIC),
        ])
        loaded = load_refined_specs(run_dir)
        by_fn = {s.function: s for s in loaded}
        assert by_fn["confirmed"].evidence_tier == EvidenceTier.XREF_BACKED
        assert by_fn["confirmed"].source == "operator_confirmed"
        assert by_fn["guessy"].evidence_tier == EvidenceTier.HEURISTIC

    def test_missing_artifact_empty(self, tmp_path):
        from core.iris.store import load_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        assert load_refined_specs(run_dir) == []

    def test_malformed_artifact_empty(self, tmp_path):
        from core.iris.store import load_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        (run_dir / "iris-taint-specs-refined.json").write_text("{not json")
        assert load_refined_specs(run_dir) == []
        (run_dir / "iris-taint-specs-refined.json").write_text('{"a": 1}')
        assert load_refined_specs(run_dir) == []

    def test_unknown_tier_degrades_to_heuristic_never_up(self, tmp_path):
        import json

        from core.iris.store import load_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        (run_dir / "iris-taint-specs-refined.json").write_text(json.dumps([
            {"function": "f", "file": "a.py", "role": "sanitiser",
             "evidence_tier": "totally_made_up_tier"},
        ]))
        loaded = load_refined_specs(run_dir)
        assert loaded[0].evidence_tier == EvidenceTier.HEURISTIC


class TestPersistRefinedSpecs:
    """Caller-persist step: store merge + envelope-metadata preservation."""

    def test_merges_into_empty_store(self, tmp_path):
        from core.iris.store import persist_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        dest = persist_refined_specs(run_dir, [
            _make_spec(fn="new_sani", role="sanitiser"),
        ])
        assert dest is not None
        loaded = load_specs(run_dir)
        assert [s.function for s in loaded] == ["new_sani"]

    def test_merge_keeps_higher_tier(self, tmp_path):
        """A tool-confirmed store spec survives a heuristic re-refine."""
        from core.iris.store import persist_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [
            _make_spec(fn="sani", role="sanitiser",
                       evidence_tier=EvidenceTier.XREF_BACKED),
        ])
        persist_refined_specs(run_dir, [
            _make_spec(fn="sani", role="sanitiser",
                       evidence_tier=EvidenceTier.HEURISTIC),
        ])
        loaded = load_specs(run_dir)
        assert loaded[0].evidence_tier == EvidenceTier.XREF_BACKED

    def test_preserves_envelope_metadata(self, tmp_path):
        from pathlib import Path

        from core.iris.store import persist_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(
            run_dir,
            [_make_spec(fn="old_spec", role="sink")],
            cl_sha="abc123",
            round_num=2,
            history=[{"round": 0, "n_specs": 1}, {"round": 1, "n_specs": 1}],
            target_path=Path("/repo/a"),
            assumptions=[SafetyAssumption(
                target="old_spec", file="src/auth.py",
                assumption="requires check",
                category=AssumptionCategory.ORDERING,
                enforced_by=["check"],
            )],
        )
        persist_refined_specs(
            run_dir,
            [_make_spec(fn="refined_spec", role="sanitiser")],
            history=[{"round": 0, "n_specs": 2}],
        )
        meta = load_store_metadata(run_dir)
        # checklist_sha kept when caller passes none
        assert meta["checklist_sha"] == "abc123"
        # prior history preserved, new round appended
        assert len(meta["history"]) == 3
        # target path preserved
        assert meta["target_path"] == str(Path("/repo/a").resolve())
        # stored assumptions preserved
        assert len(meta["assumptions"]) == 1
        # both specs present after merge
        fns = {s.function for s in load_specs(run_dir)}
        assert fns == {"old_spec", "refined_spec"}

    def test_cross_target_guard(self, tmp_path):
        from pathlib import Path

        from core.iris.store import persist_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [_make_spec(fn="theirs")],
                   target_path=Path("/repo/a"))
        dest = persist_refined_specs(
            run_dir, [_make_spec(fn="mine")],
            target_path=Path("/repo/b"),
        )
        assert dest is None
        assert {s.function for s in load_specs(run_dir)} == {"theirs"}

    def test_empty_refined_is_noop(self, tmp_path):
        from core.iris.store import persist_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        assert persist_refined_specs(run_dir, []) is None
        assert load_specs(run_dir) == []
