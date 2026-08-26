"""Tests for the heap-trace template shape (pure JS; no slot rendering)."""

from __future__ import annotations

from pathlib import Path

from packages.frida.runner import list_templates, load_script_source

_TEMPLATE = (Path(__file__).resolve().parents[1]
             / "templates" / "heap-trace.js")


def test_template_is_listed() -> None:
    assert "heap-trace" in list_templates()


def test_template_loads_verbatim() -> None:
    source, origin = load_script_source("heap-trace", None)
    assert origin == "template:heap-trace"
    assert source == _TEMPLATE.read_text(encoding="utf-8")


def test_template_shape() -> None:
    text = _TEMPLATE.read_text(encoding="utf-8")
    # The three anomaly kinds plus the aggregate summary.
    assert "'double_free'" in text
    assert "'invalid_free'" in text
    assert "'uaf_candidate'" in text
    assert "kind: 'summary'" in text
    # Allocator coverage.
    for fn in ("'malloc'", "'calloc'", "'realloc'", "'free'"):
        assert fn in text


def test_no_per_allocation_events() -> None:
    """Allocator storms must aggregate in-agent; only anomalies and
    flush summaries leave the process."""
    text = _TEMPLATE.read_text(encoding="utf-8")
    # recordAlloc must not send at all.
    body = text.split("function recordAlloc")[1].split("\nfunction ")[0]
    assert "send" not in body


def test_bounded_state_and_budget() -> None:
    text = _TEMPLATE.read_text(encoding="utf-8")
    assert "MAX_EVENTS" in text
    assert "cap reached" in text
    assert "MAX_LIVE" in text
    assert "live_overflow" in text          # gaps counted, never silent
    assert "QUARANTINE" in text
    assert "MAX_PENDING_INVALID" in text
    assert "MAX_SEEN_ANOMALIES" in text


def test_flush_transport() -> None:
    """Controller flush clock: posted message preferred, rpc kept for
    manual drivers — same contract as bb-coverage / call-edges."""
    text = _TEMPLATE.read_text(encoding="utf-8")
    assert "recv('raptor:flush'" in text
    assert "rpc.exports" in text


def test_mode_gated_invalid_free() -> None:
    """invalid_free is meaningless in attach mode; candidates are
    buffered until the controller says spawned=true."""
    text = _TEMPLATE.read_text(encoding="utf-8")
    assert "spawnedKnown" in text
    assert "msg.spawned === true" in text
    assert "pendingInvalidFrees" in text


def test_memalign_family_are_alloc_sources() -> None:
    """aligned_alloc/posix_memalign pointers freed later must not
    read as invalid frees (C++17 aligned new, SIMD libraries)."""
    text = _TEMPLATE.read_text(encoding="utf-8")
    for fn in ("'aligned_alloc'", "'posix_memalign'", "'memalign'",
               "'valloc'"):
        assert fn in text
    # And a hook failure suppresses the verdict instead of minting
    # phantoms from legitimate frees.
    assert "allocSourceGaps === 0" in text


def test_quarantine_drop_is_overlap_aware() -> None:
    """Consolidated chunks: one malloc can span several stale freed
    ranges; keeping them would flag live-memory writes as UAF."""
    text = _TEMPLATE.read_text(encoding="utf-8")
    assert "quarantineDropRange" in text
    assert "quarantineDrop(" not in text.replace("quarantineDropRange(", "")


def test_anomalies_carry_sibling_payload_parity() -> None:
    """caller_module_base/path enable the bridge's PIE dual-candidate
    callsite resolution and project-library attribution."""
    text = _TEMPLATE.read_text(encoding="utf-8")
    assert text.count("caller_module_base") >= 3
    assert text.count("caller_module_path") >= 3


def test_agent_churn_is_counted_not_reported() -> None:
    """frida's own injected code (unresolvable caller) recycles target
    chunks; that traffic must never surface as anomalies."""
    text = _TEMPLATE.read_text(encoding="utf-8")
    assert "agentChurn" in text
    assert "agent_churn" in text
    assert "site.module === null" in text


def test_summary_is_meta_marked() -> None:
    """The aggregate summary must not enter the validation bridge's
    call-evidence path (only anomaly events are call observations)."""
    text = _TEMPLATE.read_text(encoding="utf-8")
    assert "_meta: 'heap summary'" in text


def test_alias_dedup() -> None:
    """memcpy/memmove can share an implementation or tail-call each
    other; one call must not be reported twice."""
    text = _TEMPLATE.read_text(encoding="utf-8")
    assert "attachOnce" in text
    assert "seenAnomalies" in text


def test_abort_drain_hook() -> None:
    """A double free aborts the target moments after the event is
    recorded; the abort path must drain in-flight sends."""
    text = _TEMPLATE.read_text(encoding="utf-8")
    assert "'abort'" in text
    assert "Thread.sleep" in text
