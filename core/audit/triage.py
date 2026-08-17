"""Triage classifier — assigns every function to a depth bucket before review.

The mechanical triage pass sorts functions into 4 buckets with a 100x budget
range so LLM tokens are concentrated on functions most likely to contain bugs.
All classification is deterministic — no LLM calls.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from ._util import safe_join
from .prefilter import PrefilterResult


class TriageBucket(str, Enum):
    SKIP = "skip"
    GLANCE = "glance"
    INVESTIGATE = "investigate"
    DEEP_DIVE = "deep_dive"


TOKEN_BUDGETS: dict[TriageBucket, int] = {
    TriageBucket.SKIP: 0,
    TriageBucket.GLANCE: 500,
    TriageBucket.INVESTIGATE: 6000,
    TriageBucket.DEEP_DIVE: 50000,
}


@dataclass(frozen=True)
class TriageResult:
    bucket: TriageBucket
    reasons: tuple
    token_budget: int
    priority_score: float = 0.0


_DEEP_DIVE_SLOC = 200
_INVESTIGATE_SLOC = 20
_GLANCE_MAX_SLOC = 20
_HIGH_COMPLEXITY_BRANCHES = 15


def classify_function(
    *,
    file: str,
    function: str,
    sloc: int = 0,
    source: str = "",
    priority_score: float = 0.0,
    is_entry_point: bool = False,
    is_sink: bool = False,
    is_trust_boundary: bool = False,
    on_taint_path: bool = False,
    has_joern_flows: bool = False,
    has_dangerous_callees: bool = False,
    binary_absent: bool = False,
    sink_unreachable: bool = False,
    prefilter: PrefilterResult | None = None,
    branch_count: int = 0,
    caller_count: int = 0,
) -> TriageResult:
    """Classify a single function into a triage bucket.

    All inputs are mechanical signals already available from the pre-sweep
    (Joern CPG, binary oracle, prefilter, priority scoring, context map).
    """
    reasons: list[str] = []

    if prefilter and prefilter.skip_llm:
        reasons.append(f"prefilter skip: {prefilter.skip_reason}")
        return TriageResult(
            bucket=TriageBucket.SKIP,
            reasons=tuple(reasons),
            token_budget=TOKEN_BUDGETS[TriageBucket.SKIP],
            priority_score=priority_score,
        )

    if (
        sink_unreachable
        and not is_entry_point
        and not is_sink
        and not is_trust_boundary
        and not has_dangerous_callees
        and sloc <= 30
    ):
        reasons.append("no sink path, no dangerous callees, small")
        return TriageResult(
            bucket=TriageBucket.SKIP,
            reasons=tuple(reasons),
            token_budget=TOKEN_BUDGETS[TriageBucket.SKIP],
            priority_score=priority_score,
        )

    # Binary-oracle absent (suppression-earning: callers pass keys only
    # for full-DWARF-tier verdicts on trusted binaries — see the
    # chokepoint rules in core.analysis.reachability). The compiler
    # removed the function from every analysed binary: spending
    # hypothesis budget on it wastes review slots. Entry points, sinks
    # and trust boundaries stay exempt.
    if (
        binary_absent
        and not is_entry_point
        and not is_sink
        and not is_trust_boundary
    ):
        reasons.append(
            "binary_oracle_absent (not present in any analysed binary)"
        )
        return TriageResult(
            bucket=TriageBucket.SKIP,
            reasons=tuple(reasons),
            token_budget=TOKEN_BUDGETS[TriageBucket.SKIP],
            priority_score=priority_score,
        )

    if binary_absent and sink_unreachable and not is_entry_point:
        reasons.append("binary absent + no sink path")
        return TriageResult(
            bucket=TriageBucket.SKIP,
            reasons=tuple(reasons),
            token_budget=TOKEN_BUDGETS[TriageBucket.SKIP],
            priority_score=priority_score,
        )

    if is_entry_point:
        reasons.append("entry point")
    if is_sink:
        reasons.append("sink")
    if is_trust_boundary:
        reasons.append("trust boundary")
    if has_joern_flows:
        reasons.append("Joern taint-to-sink flow")
    if sloc >= _DEEP_DIVE_SLOC:
        reasons.append(f"large ({sloc} SLOC)")
    if branch_count >= _HIGH_COMPLEXITY_BRANCHES:
        reasons.append(f"high complexity ({branch_count} branches)")
    if caller_count >= 5 and (is_sink or has_dangerous_callees):
        reasons.append(f"widely called sink/dangerous ({caller_count} callers)")

    if reasons:
        return TriageResult(
            bucket=TriageBucket.DEEP_DIVE,
            reasons=tuple(reasons),
            token_budget=TOKEN_BUDGETS[TriageBucket.DEEP_DIVE],
            priority_score=priority_score,
        )

    if on_taint_path or has_dangerous_callees:
        reasons.append(
            "on taint path" if on_taint_path else "has dangerous callees"
        )
        return TriageResult(
            bucket=TriageBucket.INVESTIGATE,
            reasons=tuple(reasons),
            token_budget=TOKEN_BUDGETS[TriageBucket.INVESTIGATE],
            priority_score=priority_score,
        )

    if sloc > _GLANCE_MAX_SLOC:
        reasons.append(f"moderate size ({sloc} SLOC)")
        return TriageResult(
            bucket=TriageBucket.INVESTIGATE,
            reasons=tuple(reasons),
            token_budget=TOKEN_BUDGETS[TriageBucket.INVESTIGATE],
            priority_score=priority_score,
        )

    reasons.append("low complexity, no taint exposure")
    return TriageResult(
        bucket=TriageBucket.GLANCE,
        reasons=tuple(reasons),
        token_budget=TOKEN_BUDGETS[TriageBucket.GLANCE],
        priority_score=priority_score,
    )


def classify_all(
    gaps: Sequence[dict[str, Any]],
    *,
    entry_points: frozenset[str] = frozenset(),
    sinks: frozenset[str] = frozenset(),
    trust_boundaries: frozenset[str] = frozenset(),
    taint_path_keys: frozenset[str] = frozenset(),
    joern_flow_keys: frozenset[str] = frozenset(),
    binary_absent_keys: frozenset[str] = frozenset(),
    sink_unreachable_keys: frozenset[str] = frozenset(),
    dangerous_callee_keys: frozenset[str] = frozenset(),
    priority_scores: dict[str, float] | None = None,
    prefilter_results: dict[str, PrefilterResult] | None = None,
) -> dict[str, TriageResult]:
    """Classify all gap functions. Returns {file:function: TriageResult}."""
    scores = priority_scores or {}
    prefilters = prefilter_results or {}
    results: dict[str, TriageResult] = {}

    for gap in gaps:
        bare_key = f"{gap['file']}:{gap['name']}"
        line_start = gap.get("line_start", 0)
        key = f"{bare_key}:{line_start}"
        sloc = gap.get("sloc", (gap.get("line_end", 0) or 0) - (gap.get("line_start", 0) or 0))
        caller_count = len(gap.get("callers", []))

        results[key] = classify_function(
            file=gap["file"],
            function=gap["name"],
            sloc=max(sloc, 0),
            priority_score=scores.get(bare_key, 0.0),
            is_entry_point=bare_key in entry_points,
            is_sink=bare_key in sinks,
            is_trust_boundary=bare_key in trust_boundaries,
            on_taint_path=bare_key in taint_path_keys,
            has_joern_flows=bare_key in joern_flow_keys,
            has_dangerous_callees=bare_key in dangerous_callee_keys,
            binary_absent=bare_key in binary_absent_keys,
            sink_unreachable=bare_key in sink_unreachable_keys,
            prefilter=prefilters.get(bare_key),
            branch_count=gap.get("branch_count", 0),
            caller_count=caller_count,
        )

    return results


def format_triage_summary(results: dict[str, TriageResult]) -> str:
    """One-line summary of triage distribution."""
    counts = {b: 0 for b in TriageBucket}
    for tr in results.values():
        counts[tr.bucket] += 1
    total = len(results)
    if total == 0:
        return "Triage: no functions"
    parts = []
    for bucket in TriageBucket:
        c = counts[bucket]
        pct = 100 * c / total
        parts.append(f"{bucket.value}={c} ({pct:.0f}%)")
    return f"Triage: {total} functions — {', '.join(parts)}"


# ── Generated code detection ─────────────────────────────────────────

_GENERATED_MARKERS = [
    re.compile(r"DO NOT EDIT", re.IGNORECASE),
    re.compile(r"@generated"),
    re.compile(r"auto-generated", re.IGNORECASE),
    re.compile(r"generated by\s+\w+", re.IGNORECASE),
    re.compile(r"Code generated by\s+\w+", re.IGNORECASE),
    re.compile(r"THIS FILE IS GENERATED", re.IGNORECASE),
]

_GENERATED_EXTENSIONS = frozenset({
    "_pb2.py", "_pb2_grpc.py", ".pb.go", ".pb.h", ".pb.cc",
    ".generated.go", ".gen.ts", ".gen.js",
    "_generated.rs", ".g.dart",
})


def detect_generated_files(
    gaps: Sequence[dict[str, Any]],
    *,
    target_path: Path | None = None,
) -> list[str]:
    """Identify generated files that should get reduced review depth."""
    generated: list[str] = []
    seen: set[str] = set()

    for gap in gaps:
        file_path = gap.get("file", "")
        if not file_path or file_path in seen:
            continue
        seen.add(file_path)

        if any(file_path.endswith(ext) for ext in _GENERATED_EXTENSIONS):
            generated.append(file_path)
            continue

        source = gap.get("source", "")
        if not source and target_path:
            source = _read_file_header(file_path, target_path)
        if source:
            first_lines = source[:500]
            if any(m.search(first_lines) for m in _GENERATED_MARKERS):
                generated.append(file_path)

    return generated


def _read_file_header(file_path: str, target_path: Path) -> str:
    """Read the first 512 bytes of a file for generated-marker detection."""
    resolved = safe_join(target_path, file_path)
    if resolved is None:
        return ""
    try:
        with open(resolved, "r", errors="replace") as f:
            return f.read(512)
    except OSError:
        return ""
