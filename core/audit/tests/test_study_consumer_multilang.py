"""Study-consumer language dispatch (P37 — study loop beyond C/C++).

Pins: per-batch routing (C corpus / in-process multilang / unsupported),
re-review parity for non-C languages, and the reading-list marking
semantics — resolved requires domain-model evidence, unresolvable
carries a reason and is never resolved-clean, attempted-but-unverified
stays pending.  All hermetic: subprocess and run_study stubbed.
"""

from __future__ import annotations

import json
import time
import types

import pytest

from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    StudyQueue,
    StudyRequest,
    _extract_concept_from_question,
    _LockedOutcomes,
    _mark_batch_reading_list,
    _partition_study_batch,
    _study_consumer_loop,
)

# ------------------------------------------------------------------
# Question concept extraction (dotted / qualified shapes)
# ------------------------------------------------------------------

class TestExtractConceptDotted:
    def test_c_shape_unchanged(self) -> None:
        assert _extract_concept_from_question("what is sk_buff?") == "sk_buff"
        assert (
            _extract_concept_from_question("how does skb_put work?")
            == "skb_put"
        )

    def test_dotted_python(self) -> None:
        assert (
            _extract_concept_from_question("Does json.loads reject NaN?")
            == "json.loads"
        )

    def test_double_colon_rust(self) -> None:
        assert (
            _extract_concept_from_question(
                "Does Vec::with_capacity zero the memory?",
            )
            == "Vec::with_capacity"
        )

    def test_backticked(self) -> None:
        assert (
            _extract_concept_from_question("Does `http.Client.Do` retry?")
            == "http.Client.Do"
        )

    def test_trailing_period_stripped(self) -> None:
        assert (
            _extract_concept_from_question("does parse_config. work")
            == "parse_config"
        )


# ------------------------------------------------------------------
# Batch partitioning
# ------------------------------------------------------------------

def _req(source_file: str, question: str = "does thing work?", **kw):
    return StudyRequest(
        question=question,
        source_file=source_file,
        source_function=kw.pop("source_function", "fn"),
        **kw,
    )


class TestPartitionStudyBatch:
    def test_c_files_route_to_c(self) -> None:
        c, ml, un = _partition_study_batch(
            [_req("a.c"), _req("b.cpp"), _req("h.hpp")],
        )
        assert len(c) == 3 and not ml and not un

    def test_multilang_files_route_in_process(self) -> None:
        c, ml, un = _partition_study_batch([
            _req("a.py"), _req("b.go"), _req("C.java"),
            _req("d.ts"), _req("e.rs"), _req("f.js"),
        ])
        assert not c and len(ml) == 6 and not un

    def test_unsupported_language_partitioned_out(self) -> None:
        c, ml, un = _partition_study_batch([_req("a.rb"), _req("b.lua")])
        assert not c and not ml and len(un) == 2

    def test_missing_source_file_stays_on_c_path(self) -> None:
        c, ml, un = _partition_study_batch([_req("")])
        assert len(c) == 1 and not ml and not un

    def test_mixed_batch(self) -> None:
        c, ml, un = _partition_study_batch(
            [_req("a.c"), _req("b.py"), _req("c.rb")],
        )
        assert len(c) == 1 and len(ml) == 1 and len(un) == 1


# ------------------------------------------------------------------
# Reading-list marking semantics (pinned)
# ------------------------------------------------------------------

def _seed_reading_list(out_dir, entries):
    from core.concepts.audit_bridge import queue_reading_list_item

    for e in entries:
        queue_reading_list_item(out_dir, **e)


def _load_rl(out_dir):
    return json.loads((out_dir / "reading-list.json").read_text())


class TestMarkBatchReadingList:
    def test_resolved_requires_domain_model_evidence(self, tmp_path) -> None:
        q = "Does `parse_config` validate its input?"
        _seed_reading_list(tmp_path, [{
            "question": q, "source_file": "pkg/config.py",
            "source_function": "handler",
        }])
        dm = {"concepts": [{"id": "parse_config_contract"}],
              "invariants": [], "contracts": []}
        _mark_batch_reading_list(
            tmp_path,
            [_req("pkg/config.py", q)],
            dm,
            {},
        )
        item = _load_rl(tmp_path)["items"][0]
        assert item["resolved"]
        assert item["resolved_concept_id"] == "parse_config_contract"

    def test_attempted_but_unverified_stays_pending(self, tmp_path) -> None:
        q = "Does `parse_config` validate its input?"
        _seed_reading_list(tmp_path, [{
            "question": q, "source_file": "pkg/config.py",
        }])
        dm = {"concepts": [{"id": "unrelated_concept"}],
              "invariants": [], "contracts": []}
        _mark_batch_reading_list(
            tmp_path, [_req("pkg/config.py", q)], dm, {},
        )
        item = _load_rl(tmp_path)["items"][0]
        assert not item["resolved"]
        assert not item["unresolvable"]

    def test_failure_marks_unresolvable_never_resolved(self, tmp_path) -> None:
        q = "Does `ghost_fn` retry?"
        _seed_reading_list(tmp_path, [{
            "question": q, "source_file": "pkg/config.py",
        }])
        dm = {"concepts": [{"id": "ghost_fn_contract"}],
              "invariants": [], "contracts": []}
        # Even though a concept would match, the resolver verdict wins:
        # the identifier has no static definition.
        _mark_batch_reading_list(
            tmp_path, [_req("pkg/config.py", q)], dm,
            {q: "not found in the scanned source tree"},
        )
        item = _load_rl(tmp_path)["items"][0]
        assert item["unresolvable"]
        assert "not found" in item["unresolvable_reason"]
        assert not item["resolved"]

    def test_critical_failure_is_loud(self, tmp_path, monkeypatch) -> None:
        import core.audit.orchestrator as _orch

        lines = []
        monkeypatch.setattr(
            _orch.logger, "warning",
            lambda msg, *a, **kw: lines.append(msg % a if a else msg),
        )
        q = "Does `ghost_fn` retry?"
        _seed_reading_list(tmp_path, [{
            "question": q, "source_file": "pkg/config.py",
            "priority": "critical",
        }])
        _mark_batch_reading_list(
            tmp_path,
            [_req("pkg/config.py", q, priority="critical")],
            None,
            {q: "not found"},
        )
        assert any("CRITICAL assumption unresolvable" in ln for ln in lines)

    def test_invariant_subject_counts_as_evidence(self, tmp_path) -> None:
        q = "Does MaxHeaderLen bound the buffer?"
        _seed_reading_list(tmp_path, [{
            "question": q, "source_file": "server/header.go",
        }])
        dm = {"concepts": [],
              "invariants": [{"subject": "maxheaderlen"}],
              "contracts": []}
        _mark_batch_reading_list(
            tmp_path, [_req("server/header.go", q)], dm, {},
        )
        assert _load_rl(tmp_path)["items"][0]["resolved"]


# ------------------------------------------------------------------
# Full consumer loop (hermetic)
# ------------------------------------------------------------------

def _fixture_tree(tmp_path):
    target = tmp_path / "src"
    pkg = target / "pkg"
    pkg.mkdir(parents=True)
    (pkg / "config.py").write_text(
        'def parse_config(path):\n'
        '    """Parse the config file. Raises ValueError on bad input."""\n'
        '    return path\n',
    )
    return target


def _stub_prep(monkeypatch, out_dir, calls=None):
    """Stub the study-prep subprocess: records calls, writes study-list."""
    import core.audit.orchestrator as _orch

    recorded = calls if calls is not None else []

    def fake_run(cmd, **kwargs):
        recorded.append(cmd)
        (out_dir / "study-list.json").write_text(json.dumps({
            "target": str(out_dir), "source_root": str(out_dir),
            "items": [],
        }))
        return types.SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(_orch.subprocess, "run", fake_run)
    return recorded


def _stub_llm(monkeypatch):
    import core.llm.client as _client_mod

    monkeypatch.setattr(
        _client_mod, "LLMClient",
        lambda *a, **kw: types.SimpleNamespace(total_cost=0.0),
    )


def _stub_run_study(monkeypatch, out_dir, concepts):
    import core.concepts.study as _study_mod

    def fake_run_study(study_list_path, output_dir, client, **kw):
        (out_dir / "domain-model.json").write_text(json.dumps({
            "version": "1", "target": "", "source_root": "",
            "concepts": concepts, "invariants": [], "contracts": [],
            "bug_patterns": [],
        }))

    monkeypatch.setattr(_study_mod, "run_study", fake_run_study)


def _run_loop(config, queue, *, reviewed=None):
    shared = types.SimpleNamespace(domain_model=None)
    _study_consumer_loop(
        queue, config, shared, lambda ctx, cfg: None,
        reviewed if reviewed is not None else _LockedOutcomes(),
        OrchestratorResult(),
        checklist={"files": []},
        context_map=None,
        evidence_index={},
        sarif_cache=None,
        entry_points=set(),
        start_time=time.monotonic(),
        on_progress=None,
    )
    return shared


def _queue(*reqs):
    q = StudyQueue()
    for r in reqs:
        q.enqueue(r)
    q.signal_producer_done()
    return q


class TestConsumerMultilangDispatch:
    def test_python_question_resolves_and_merges(
        self, monkeypatch, tmp_path,
    ) -> None:
        target = _fixture_tree(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)
        _stub_prep(monkeypatch, out)
        _stub_llm(monkeypatch)
        _stub_run_study(
            monkeypatch, out, [{"id": "parse_config_contract"}],
        )

        q = "Does `parse_config` validate its input?"
        _run_loop(config, _queue(StudyRequest(
            question=q, source_file="pkg/config.py",
            source_function="handler",
        )))

        # Resolved definition merged into the study corpus
        study_list = json.loads((out / "study-list.json").read_text())
        names = {i["name"] for i in study_list["items"]}
        assert "parse_config" in names
        # Reading-list item resolved against the domain model
        rl = _load_rl(out)
        assert rl["items"][0]["resolved"]

    def test_unresolvable_python_question_marked_with_reason(
        self, monkeypatch, tmp_path,
    ) -> None:
        target = _fixture_tree(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)
        _stub_prep(monkeypatch, out)
        _stub_llm(monkeypatch)
        _stub_run_study(monkeypatch, out, [{"id": "ghost_fn_contract"}])

        q = "Does `ghost_fn` retry on failure?"
        _run_loop(config, _queue(StudyRequest(
            question=q, source_file="pkg/config.py",
            source_function="handler",
        )))

        item = _load_rl(out)["items"][0]
        assert item["unresolvable"]
        assert item["unresolvable_reason"]
        assert not item["resolved"]
        # Honest record also lands in the study corpus
        study_list = json.loads((out / "study-list.json").read_text())
        assert any(
            u["name"] == "ghost_fn"
            for u in study_list.get("unresolved_identifiers", [])
        )

    def test_unsupported_language_skips_study_entirely(
        self, monkeypatch, tmp_path,
    ) -> None:
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=tmp_path, out_dir=out)
        calls = _stub_prep(monkeypatch, out)

        q = "Does `method_missing` proxy to the client?"
        queue = _queue(StudyRequest(
            question=q, source_file="lib/client.rb",
            source_function="call",
        ))
        _run_loop(config, queue)

        assert calls == [], "study-prep must not run for unsupported batch"
        item = _load_rl(out)["items"][0]
        assert item["unresolvable"]
        assert ".rb" in item["unresolvable_reason"]
        assert not item["resolved"]
        # Suppression gate released
        assert queue.pending_concepts() == frozenset()

    def test_re_review_parity_for_python(
        self, monkeypatch, tmp_path,
    ) -> None:
        """A resolved non-C assumption re-enters the review queue for
        its originating function exactly as for C."""
        import core.audit.orchestrator as _orch

        target = _fixture_tree(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)
        _stub_prep(monkeypatch, out)
        _stub_llm(monkeypatch)
        _stub_run_study(
            monkeypatch, out, [{"id": "parse_config_contract"}],
        )

        re_reviewed: list[set] = []

        def fake_re_review(result, *a, **kw):
            # reading_list_functions is positional arg 8 (a[7])
            re_reviewed.append(set(a[7]))
            return result

        monkeypatch.setattr(
            _orch, "_re_review_study_enriched", fake_re_review,
        )

        reviewed = _LockedOutcomes()
        reviewed["pkg/config.py:handler"] = types.SimpleNamespace(
            status="suspicious",
        )

        q = "Does `parse_config` validate its input?"
        _run_loop(config, _queue(StudyRequest(
            question=q, source_file="pkg/config.py",
            source_function="handler",
        )), reviewed=reviewed)

        assert re_reviewed, "re-review must fire for non-C languages"
        assert "pkg/config.py:handler" in re_reviewed[0]

    def test_unresolvable_function_not_re_reviewed(
        self, monkeypatch, tmp_path,
    ) -> None:
        """No knowledge was gained — the originating function must not
        burn a re-review slot."""
        import core.audit.orchestrator as _orch

        target = _fixture_tree(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)
        _stub_prep(monkeypatch, out)
        _stub_llm(monkeypatch)
        _stub_run_study(monkeypatch, out, [{"id": "anything"}])

        re_reviewed: list[set] = []
        monkeypatch.setattr(
            _orch, "_re_review_study_enriched",
            lambda result, *a, **kw: (re_reviewed.append(set(a[7])), result)[1],
        )

        reviewed = _LockedOutcomes()
        reviewed["pkg/config.py:handler"] = types.SimpleNamespace(
            status="suspicious",
        )

        _run_loop(config, _queue(StudyRequest(
            question="Does `ghost_fn` retry?",
            source_file="pkg/config.py", source_function="handler",
        )), reviewed=reviewed)

        for keys in re_reviewed:
            assert "pkg/config.py:handler" not in keys


# ------------------------------------------------------------------
# Gate: non-C workqueues start the consumer
# ------------------------------------------------------------------

class TestStudyGateSuffixes:
    @pytest.mark.parametrize("path,expected", [
        ("a.c", True), ("b.cpp", True),
        ("pkg/app.py", True), ("srv/main.go", True),
        ("App.java", True), ("web/app.ts", True), ("lib.rs", True),
        ("script.rb", False), ("conf.lua", False), ("style.css", False),
    ])
    def test_supported_path(self, path, expected) -> None:
        from core.concepts.lang_resolve import is_study_supported_path
        assert is_study_supported_path(path) is expected
