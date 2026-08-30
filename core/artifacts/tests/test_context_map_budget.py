"""Tests for the producer-side context-map size budget."""

from __future__ import annotations

import copy
from typing import Any

from core.artifacts import context_map_budget as cmb


def _llm_entry(i: int) -> dict[str, Any]:
    return {
        "id": f"EP-{i:03d}",
        "name": f"handler_{i}",
        "file": "app.py",
        "line": 10 + i,
        "notes": "LLM-authored narrative " + "n" * 200,
        "ast_view": {"signature": f"handler_{i}()", "calls": ["a", "b"]},
        "forward_reachable": {
            "host": f"app.handler_{i}",
            "internal_count": 2,
            "external_count": 1,
            "internal_names": ["app.x", "app.y"],
            "external_names": ["os.read"],
            "truncated": False,
        },
    }


def _synth_entry(i: int) -> dict[str, Any]:
    return {
        "id": f"EP-LIB-{i:03d}",
        "type": "library_api",
        "name": f"export_{i}",
        "file": "lib.c",
        "line": i,
        "origin": "inventory-entry",
        "ast_view": {"signature": f"export_{i}()", "body": "x" * 2000},
        "forward_reachable": {
            "host": f"lib.export_{i}",
            "internal_count": 50,
            "external_count": 50,
            "internal_names": [f"lib.fn_{j}" for j in range(50)],
            "external_names": [f"ext.fn_{j}" for j in range(50)],
            "truncated": False,
        },
    }


def _context_map(n_llm: int = 2, n_synth: int = 6) -> dict[str, Any]:
    return {
        "target_kind": "library",
        "entry_points": (
            [_llm_entry(i) for i in range(n_llm)]
            + [_synth_entry(i) for i in range(n_synth)]
        ),
        "sink_details": [{"id": "SINK-001", "file": "app.py", "line": 5}],
    }


def _synth_eps(m: dict[str, Any]) -> list[dict[str, Any]]:
    return [e for e in m["entry_points"]
            if e.get("origin") == "inventory-entry"]


def _llm_eps(m: dict[str, Any]) -> list[dict[str, Any]]:
    return [e for e in m["entry_points"]
            if e.get("origin") != "inventory-entry"]


def test_within_budget_is_untouched():
    m = _context_map()
    before = copy.deepcopy(m)
    applied = cmb.enforce_context_map_budget(
        m, budget_bytes=cmb._serialized_size(m) + 1)
    assert applied == []
    assert m == before


def test_non_dict_is_noop():
    assert cmb.enforce_context_map_budget([1, 2]) == []  # type: ignore[arg-type]


def test_step1_drops_only_synth_ast_views():
    m = _context_map()
    # Budget = exactly what step 1 alone achieves.
    sim = copy.deepcopy(m)
    cmb._drop_synth_ast_views(sim)
    budget = cmb._serialized_size(sim)

    applied = cmb.enforce_context_map_budget(m, budget_bytes=budget)
    assert len(applied) == 1
    assert applied[0].startswith("dropped ast_view")
    assert all("ast_view" not in e for e in _synth_eps(m))
    # LLM-authored entries keep every payload.
    for e in _llm_eps(m):
        assert "ast_view" in e
        assert e["forward_reachable"]["internal_names"]
    # Step 2 did not run.
    for e in _synth_eps(m):
        assert e["forward_reachable"]["internal_names"]
    assert cmb._serialized_size(m) <= budget


def test_step2_drops_name_lists_keeps_counts():
    m = _context_map()
    sim = copy.deepcopy(m)
    cmb._drop_synth_ast_views(sim)
    cmb._drop_synth_reachable_names(sim)
    budget = cmb._serialized_size(sim)

    applied = cmb.enforce_context_map_budget(m, budget_bytes=budget)
    assert len(applied) == 2
    assert applied[1].startswith("dropped forward_reachable")
    for e in _synth_eps(m):
        fr = e["forward_reachable"]
        assert fr["internal_names"] == []
        assert fr["external_names"] == []
        assert fr["internal_count"] == 50
        assert fr["truncated"] is True
    # LLM-authored closures survive with names.
    for e in _llm_eps(m):
        assert e["forward_reachable"]["internal_names"] == ["app.x", "app.y"]
        assert e["forward_reachable"]["truncated"] is False
    assert len(_synth_eps(m)) == 6  # step 3 did not run


def test_step3_caps_synth_entries_never_llm():
    m = _context_map()
    # Budget = the map with ALL synthesized entries gone: forces the cap.
    sim = copy.deepcopy(m)
    sim["entry_points"] = _llm_eps(sim)
    budget = cmb._serialized_size(sim)

    applied = cmb.enforce_context_map_budget(m, budget_bytes=budget)
    assert len(applied) == 3
    assert applied[2].startswith("capped synthesized entry points")
    assert len(_llm_eps(m)) == 2          # untouched
    assert _synth_eps(m) == []            # all shed
    assert cmb._serialized_size(m) <= budget


def test_step3_partial_cap_keeps_prefix():
    m = _context_map()
    original_synth_ids = [e["id"] for e in _synth_eps(m)]
    # Budget between "steps 1+2" and "everything gone": some synthesized
    # entries must survive, shed from the tail.
    sim = copy.deepcopy(m)
    cmb._drop_synth_ast_views(sim)
    cmb._drop_synth_reachable_names(sim)
    sim_eps = sim["entry_points"]
    del sim_eps[-2:]                      # drop last two synthesized
    budget = cmb._serialized_size(sim)

    cmb.enforce_context_map_budget(m, budget_bytes=budget)
    kept_ids = [e["id"] for e in _synth_eps(m)]
    assert kept_ids                       # not everything shed
    assert kept_ids == original_synth_ids[: len(kept_ids)]  # prefix, tail-first
    assert len(_llm_eps(m)) == 2
    assert cmb._serialized_size(m) <= budget


def test_llm_only_overage_is_never_degraded():
    m = {"entry_points": [_llm_entry(i) for i in range(4)]}
    before = copy.deepcopy(m)
    applied = cmb.enforce_context_map_budget(m, budget_bytes=64)
    assert applied == []
    assert m == before


def test_producer_budget_below_consumer_cap():
    assert (cmb.CONTEXT_MAP_PRODUCER_BUDGET_BYTES
            < cmb.CONTEXT_MAP_CONSUMER_MAX_BYTES)
