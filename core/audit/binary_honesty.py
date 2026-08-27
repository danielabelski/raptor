"""Binary-lane honesty records: gate engagement + channel declarations.

On a binary target most of the source audit's refutation gates cannot
run — no domain model (the study loop never starts on ``binary:``
items), no source-rooted call graph, no function source text. A gate
whose inputs are missing returns ``None`` exactly like a gate that
RAN and found nothing, so without a record a binary run's journal is
indistinguishable from a source run whose gates were all live.

This module makes the difference a recorded fact, without changing
any verdict:

- :func:`diagnose_gate_engagement` mirrors each refutation gate's
  prerequisite chain and reports, per gate, whether it could run and
  what it was blocked on (the ``diagnose_rescue`` pattern applied to
  the demotion gates).
- :func:`record_gate_engagement` journals that diagnosis for binary
  items alongside the gate run itself.
- :func:`declare_binary_channel_skips` journals, once per run, the
  evidence channels that are structurally disabled on a binary
  target and why — a run-level record of "did not run", distinct
  from "ran and found nothing".
- :func:`journal_binary_provenance` journals the checklist's
  per-binary provenance block and persists it in the build-id cache.
- :func:`summarize_gate_engagement` aggregates the per-item records
  into the one-line run summary an operator scans.

Records only: nothing here demotes, promotes, or suppresses.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: The demotion/attribution refutation gates whose engagement is
#: diagnosed (gate 5, the anti-self-refutation rescue, has its own
#: ``diagnose_rescue`` receipt).
REFUTATION_GATES = (
    "architecture",
    "lifecycle",
    "contract",
    "input_bound_t0",
    "callee_inheritance",
)

#: Evidence channels that are structurally disabled on binary targets
#: today, with the missing premise. Declared once per run so the
#: journal records WHY a channel produced nothing. Reasons describe
#: current mechanics — re-enabling a channel for binaries must update
#: this table.
BINARY_DISABLED_CHANNELS: dict[str, str] = {
    "checker_synthesis": (
        "sweeps the source tree under target_path; a compiled artifact"
        " has no source files and the synthesis loop is not wired to"
        " decompilation output"
    ),
    "consistency": (
        "sibling-census premises (peer groups, header contracts) are"
        " source-tree facts; the census over a single-function"
        " decompilation is empty"
    ),
    "prefilter": "source-pattern prefilter is skipped on binary items",
    "joern": "CPG server only starts for source-tree targets",
    "codeql": "requires a build database; none exists for a binary",
    "dark_verify": (
        "verification harness compiles the finding's source file;"
        " binary items have none"
    ),
    "dynamic_sweep": "gated on a compilable source language",
}


def _is_binary_outcome(outcome) -> bool:
    from core.inventory.binary_builder import BINARY_PATH_PREFIX

    return str(getattr(outcome, "file", "") or "").startswith(
        BINARY_PATH_PREFIX,
    )


def diagnose_gate_engagement(
    outcome,
    *,
    domain_model: dict[str, Any] | None,
    checklist: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Mirror each refutation gate's prerequisites for one outcome.

    Returns one record per gate in :data:`REFUTATION_GATES`:
    ``{"gate": name, "engaged": bool, "blocked_on": str | None}``.
    ``engaged=True`` means the gate's inputs were satisfied — it ran
    and its silence means "evaluated, not refuted". ``engaged=False``
    means the gate could NOT run and names the missing prerequisite.

    Outcomes the gate runner never consults (no hypothesis, or
    mechanical tool evidence — refutation is deliberately barred from
    overturning tool receipts) return ``[]``: those are design
    passes, not silent inertia.
    """
    from .evidence_grade import is_tool_evidence
    from .refutation import _get_calls, _get_function_source_and_callees

    if is_tool_evidence(getattr(outcome, "evidence_tool", "") or ""):
        return []
    if not (getattr(outcome, "hypothesis", "") or ""):
        return []

    records: list[dict[str, Any]] = []

    def _record(gate: str, blocked_on: str | None) -> None:
        records.append({
            "gate": gate,
            "engaged": blocked_on is None,
            "blocked_on": blocked_on,
        })

    # Gate 1 — architecture: needs the study loop's threading model.
    arch = (domain_model or {}).get("architecture") or {}
    if not domain_model:
        _record("architecture", "domain_model")
    elif not arch.get("threading_model"):
        _record("architecture", "domain_model.architecture.threading_model")
    else:
        _record("architecture", None)

    # Gate 2 — lifecycle: needs a call graph rooted at main.
    has_calls = False
    caller_names: set[str] = set()
    for fentry in (checklist or {}).get("files", []):
        for c in _get_calls(fentry):
            if c.get("caller") and c.get("chain"):
                has_calls = True
                caller_names.add(c.get("caller"))
    if not has_calls:
        _record("lifecycle", "checklist.call_graph.calls")
    elif "main" not in caller_names:
        _record("lifecycle", "checklist.call_graph.calls[main]")
    else:
        _record("lifecycle", None)

    # Gate 3 — contract provenance: needs study contracts.
    if not domain_model:
        _record("contract", "domain_model")
    elif not (domain_model or {}).get("contracts"):
        _record("contract", "domain_model.contracts")
    else:
        _record("contract", None)

    # Gate 4 — input-bound tier-0: matches hypothesis text only.
    _record("input_bound_t0", None)

    # Gate 6 — callee inheritance: needs function source + callees.
    source, callees = _get_function_source_and_callees(outcome, checklist)
    if not source:
        _record("callee_inheritance", "item.source")
    elif not callees:
        _record("callee_inheritance", "checklist.call_graph.calls")
    else:
        _record("callee_inheritance", None)

    return records


def record_gate_engagement(
    out_dir: Path | None,
    outcome,
    *,
    domain_model: dict[str, Any] | None,
    checklist: dict[str, Any] | None,
    line_start: int = 0,
    phase: str = "review",
) -> list[dict[str, Any]]:
    """Journal the gate-engagement diagnosis for one BINARY outcome.

    Source items are untouched (their gates' inputs exist by
    construction of the source inventory; recording every source
    outcome would bury the signal). Never raises; returns the
    records (empty for non-binary outcomes / consultation skips).
    """
    if out_dir is None:
        return []
    try:
        if not _is_binary_outcome(outcome):
            return []
        records = diagnose_gate_engagement(
            outcome, domain_model=domain_model, checklist=checklist,
        )
        if not records:
            return []
        from .record import append_audit_log

        append_audit_log(Path(out_dir), {
            "action": "refutation_gate_engagement",
            "phase": phase,
            "key": (
                f"{outcome.file}:{outcome.function}:{line_start}"
            ),
            "file": outcome.file,
            "function": outcome.function,
            "gates": records,
        })
        return records
    except Exception:
        logger.debug(
            "gate-engagement record failed for %s:%s",
            getattr(outcome, "file", "?"),
            getattr(outcome, "function", "?"),
            exc_info=True,
        )
        return []


def declare_binary_channel_skips(
    out_dir: Path | None,
    checklist: dict[str, Any] | None,
) -> None:
    """Journal the structurally-disabled channels for a binary run.

    One record per run; records only (the skips themselves already
    happen elsewhere — this makes them visible in the trail instead
    of indistinguishable from "ran and found nothing").
    """
    if out_dir is None:
        return
    try:
        from .record import append_audit_log

        append_audit_log(Path(out_dir), {
            "action": "tool_coverage_declaration",
            "target_kind": "binary",
            "target_path": (checklist or {}).get("target_path", ""),
            "skipped_channels": dict(BINARY_DISABLED_CHANNELS),
        })
    except Exception:
        logger.debug("binary channel declaration failed", exc_info=True)


def journal_binary_provenance(
    out_dir: Path | None,
    checklist: dict[str, Any] | None,
    *,
    source_command: str = "audit-prep",
) -> None:
    """Journal the checklist's binary provenance block; persist it in
    the build-id cache next to the oracle's authority fields.

    Best-effort on both surfaces — a missing block or unavailable
    cache never blocks the run.
    """
    if out_dir is None or not checklist:
        return
    stats = checklist.get("binary_stats")
    if not isinstance(stats, dict):
        return
    try:
        from .record import append_audit_log

        append_audit_log(Path(out_dir), {
            "action": "binary_target_provenance",
            "target_path": checklist.get("target_path", ""),
            "binary_stats": {
                k: stats.get(k)
                for k in (
                    "total_functions", "named_functions", "auto_named",
                    "auto_named_ratio", "name_provenance_counts",
                    "source_tool", "provenance",
                )
                if k in stats
            },
        })
    except Exception:
        logger.debug("binary provenance journal failed", exc_info=True)

    provenance = stats.get("provenance")
    if not isinstance(provenance, dict) or not provenance.get("build_id"):
        return
    try:
        from .build_id_cache import (
            load_build_id_cache,
            store_binary_provenance,
        )

        binary_sha = ""
        for fentry in checklist.get("files", []):
            if isinstance(fentry, dict) and fentry.get("sha256"):
                binary_sha = str(fentry["sha256"])
                break
        store_binary_provenance(
            load_build_id_cache(),
            provenance,
            name_provenance_counts=stats.get("name_provenance_counts"),
            binary_sha256=binary_sha,
            source_command=source_command,
        )
    except Exception:
        logger.debug(
            "binary provenance cache persist failed", exc_info=True,
        )


def summarize_gate_engagement(out_dir: Path | None) -> str | None:
    """One-line-per-gate run summary of binary gate engagement.

    Aggregates the ``refutation_gate_engagement`` journal records;
    returns None when a run produced none (source runs, or binary
    runs with no reviewed positive outcomes).
    """
    if out_dir is None:
        return None
    try:
        from .record import load_audit_log

        entries = load_audit_log(Path(out_dir))
    except Exception:
        logger.debug("gate-engagement summary read failed", exc_info=True)
        return None

    live: dict[str, int] = {}
    blocked: dict[str, dict[str, int]] = {}
    total: dict[str, int] = {}
    seen = False
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("action") != "refutation_gate_engagement":
            continue
        for rec in entry.get("gates") or []:
            if not isinstance(rec, dict):
                continue
            gate = str(rec.get("gate", "") or "")
            if not gate:
                continue
            seen = True
            total[gate] = total.get(gate, 0) + 1
            if rec.get("engaged"):
                live[gate] = live.get(gate, 0) + 1
            else:
                reason = str(rec.get("blocked_on") or "unknown")
                by_reason = blocked.setdefault(gate, {})
                by_reason[reason] = by_reason.get(reason, 0) + 1

    if not seen:
        return None

    parts = []
    for gate in REFUTATION_GATES:
        n_total = total.get(gate, 0)
        if not n_total:
            continue
        n_live = live.get(gate, 0)
        part = f"{gate} {n_live}/{n_total} live"
        reasons = blocked.get(gate)
        if reasons:
            detail = ", ".join(
                f"{reason} x{count}"
                for reason, count in sorted(
                    reasons.items(), key=lambda kv: -kv[1],
                )
            )
            part += f" (could-not-run: {detail})"
        parts.append(part)
    return (
        "Refutation gate engagement (binary items): " + "; ".join(parts)
    )
