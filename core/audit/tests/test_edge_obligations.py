"""Edge-obligation scoping pass (core.audit.edge_obligations).

Synthetic fixtures shaped like the validation bar: a boundary-incident
edge (tier 1), an interior on-path edge — the CopyFail shape, where
both endpoints share a trust domain and only the source→sink scope
obligates the edge (tier 2) — plus dispatch/indirection blind spots.
"""

from __future__ import annotations

from core.audit.edge_obligations import (
    EDGE_OBLIGATIONS_FILENAME,
    build_and_write,
    build_edge_obligations,
)

# entry.c: handle_input (entry point + trust-boundary check inside it)
#   calls process() at line 10.
# mid.c: process calls page_op() at line 15 and helper() at line 16.
# sink.c: page_op is the sink. helper.c: helper reaches no sink.
_CHECKLIST = {
    "files": [
        {"path": "entry.c",
         "items": [{"name": "handle_input", "line_start": 1, "line_end": 20}],
         "call_graph": {"calls": [
             {"line": 10, "chain": ["process"], "caller": "handle_input"},
         ], "indirection": [], "getattr_targets": []}},
        {"path": "mid.c",
         "items": [{"name": "process", "line_start": 1, "line_end": 30}],
         "call_graph": {"calls": [
             {"line": 15, "chain": ["page_op"], "caller": "process"},
             {"line": 16, "chain": ["helper"], "caller": "process"},
         ], "indirection": ["fn_ptr_dispatch"], "getattr_targets": []}},
        {"path": "sink.c",
         "items": [{"name": "page_op", "line_start": 1, "line_end": 9}],
         "call_graph": {"calls": [], "indirection": [],
                        "getattr_targets": []}},
        {"path": "helper.c",
         "items": [{"name": "helper", "line_start": 1, "line_end": 9}],
         "call_graph": {"calls": [], "indirection": [],
                        "getattr_targets": []}},
    ],
}

_CONTEXT_MAP = {
    "entry_points": [{"id": "EP-001", "file": "entry.c", "line": 2}],
    "sinks": [{"type": "memory", "location": "sink.c:5"}],
    "trust_boundaries": [
        {"boundary": "input gate", "check": "entry.c:3"},
    ],
}


def _keys(records):
    return {(r["caller"], r["callee"]) for r in records}


def test_boundary_incident_edge_is_tier1():
    payload = build_edge_obligations(_CHECKLIST, _CONTEXT_MAP)
    assert ("handle_input", "process") in _keys(payload["tier1"])
    t1 = next(r for r in payload["tier1"] if r["caller"] == "handle_input")
    assert t1["reason"] == "boundary:input gate"
    assert t1["call_line"] == 10


def test_interior_on_path_edge_is_tier2_copyfail_shape():
    # process→page_op crosses no boundary; only the source→sink scope
    # obligates it. This is the assertion-1 shape from the validation
    # plan: the known-bad interior edge MUST be in the obligation set.
    payload = build_edge_obligations(_CHECKLIST, _CONTEXT_MAP)
    assert ("process", "page_op") in _keys(payload["tier2"])
    assert ("process", "page_op") not in _keys(payload["tier1"])


def test_off_path_edge_not_obligated():
    payload = build_edge_obligations(_CHECKLIST, _CONTEXT_MAP)
    all_obligated = _keys(payload["tier1"]) | _keys(payload["tier2"])
    assert ("process", "helper") not in all_obligated


def test_deterministic_and_touched_never_satisfies():
    # Assertion-2 shape: re-running reproduces the set, and a touched
    # (traced) edge stays an obligation — touched is extent, not review.
    touched = [{"caller_file": "mid.c", "caller": "process",
                "callee_file": "sink.c", "callee": "page_op",
                "call_line": 15, "source": "flow-trace-1.json"}]
    a = build_edge_obligations(_CHECKLIST, _CONTEXT_MAP, touched=touched)
    b = build_edge_obligations(_CHECKLIST, _CONTEXT_MAP, touched=touched)
    assert a == b
    rec = next(r for r in a["tier2"] if r["callee"] == "page_op")
    assert rec["touched"] is True


def test_ambiguous_callee_is_one_blind_spot_not_fanout():
    checklist = {"files": [
        dict(_CHECKLIST["files"][0]),
        dict(_CHECKLIST["files"][1]),
        {"path": "impl_a.c",
         "items": [{"name": "page_op", "line_start": 1, "line_end": 5}],
         "call_graph": {"calls": [], "indirection": [],
                        "getattr_targets": []}},
        {"path": "impl_b.c",
         "items": [{"name": "page_op", "line_start": 1, "line_end": 5}],
         "call_graph": {"calls": [], "indirection": [],
                        "getattr_targets": []}},
    ]}
    cm = {
        "entry_points": [{"id": "EP-001", "file": "entry.c", "line": 2}],
        "sinks": [{"type": "memory", "location": "impl_a.c:2"}],
        "trust_boundaries": [],
    }
    payload = build_edge_obligations(checklist, cm)
    # No phantom obligations for either candidate definition.
    assert not any(r["callee"] == "page_op"
                   for r in payload["tier1"] + payload["tier2"])
    assert payload["stats"]["ambiguous"] >= 1
    # On-path caller → surfaced as a single ambiguous_callee blind spot.
    spots = [b for b in payload["blind_spots"]
             if b["kind"] == "ambiguous_callee" and b["name"] == "page_op"]
    assert len(spots) == 1


def test_indirection_on_attack_path_is_blind_spot():
    payload = build_edge_obligations(_CHECKLIST, _CONTEXT_MAP)
    assert {"file": "mid.c", "caller": None, "kind": "indirection",
            "name": "fn_ptr_dispatch"} in payload["blind_spots"]


def test_caller_falls_back_to_containing_item():
    checklist = {"files": [
        {"path": "entry.c",
         "items": [{"name": "handle_input", "line_start": 1,
                    "line_end": 20}],
         # extractor didn't capture ``caller`` — resolve by line.
         "call_graph": {"calls": [{"line": 10, "chain": ["process"]}],
                        "indirection": [], "getattr_targets": []}},
        {"path": "mid.c",
         "items": [{"name": "process", "line_start": 1, "line_end": 30}],
         "call_graph": {"calls": [], "indirection": [],
                        "getattr_targets": []}},
    ]}
    payload = build_edge_obligations(checklist, _CONTEXT_MAP)
    assert ("handle_input", "process") in _keys(payload["tier1"])


def test_degrades_honestly_without_context_map():
    payload = build_edge_obligations(_CHECKLIST, None)
    assert payload["tier1"] == [] and payload["tier2"] == []
    assert "no-context-map" in payload["stats"]["degraded"]


def test_degrades_honestly_without_anchors():
    payload = build_edge_obligations(_CHECKLIST, {"entry_points": []})
    assert "no-boundary-anchors" in payload["stats"]["degraded"]
    assert "no-path-anchors" in payload["stats"]["degraded"]


def test_build_and_write_persists(tmp_path):
    import json
    payload = build_and_write(tmp_path, _CHECKLIST, _CONTEXT_MAP)
    on_disk = json.loads(
        (tmp_path / EDGE_OBLIGATIONS_FILENAME).read_text(encoding="utf-8"))
    assert on_disk == payload
    assert on_disk["schema_version"] == 1
