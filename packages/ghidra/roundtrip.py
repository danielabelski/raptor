"""Finding round-trip: export RAPTOR findings back to Ghidra projects.

Handles /agentic (orchestrated report records), /audit (review-journal
entries), and operator annotations. Findings are keyed by binary
address and/or function name; name resolution happens inside Ghidra
during the apply step, so no REDatabase load is needed here.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def redb_cache_candidates(gpr_path: Path) -> List[Path]:
    """Return candidate paths for a cached re-database.json.

    Used by context_inject._load_cached_redb (and any future reader
    that wants the cached database without a live import).

    Only RAPTOR-owned output locations qualify: the .gpr's own
    directory is attacker territory (the project arrived as a
    bundle), and a planted cache there would hand the author
    byte-level control of the "derived" database.
    """
    candidates = [
        Path(f"out/ghidra-import-{gpr_path.stem}") / "re-database.json",
    ]
    try:
        from core.project.project import ProjectManager
        mgr = ProjectManager()
        name = mgr.get_active()
        if name:
            project = mgr.load(name)
            candidates.append(
                Path(project.output_dir)
                / f"ghidra-{gpr_path.stem}"
                / "re-database.json",
            )
    except Exception:  # noqa: BLE001
        logger.debug("failed to resolve project for redb cache candidates", exc_info=True)
    return candidates


def _exportable(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Keep findings the enrichment import can place.

    Address-keyed entries pass through; name-keyed entries are
    resolved inside Ghidra by the import script / pyghidra apply
    (unmatched names are skipped there). Entries with neither are
    unplaceable and dropped here.
    """
    out = []
    for f in findings:
        if f.get("address") is None and not f.get("function"):
            alias = f.get("function_name")
            if not alias:
                continue
            f = {**f, "function": alias}
        out.append(f)
    return out


def _apply_findings(
    gpr_path: Path,
    out_dir: Path,
    findings: List[Dict[str, Any]],
) -> int:
    """Apply *findings* to a working copy of the project, once.

    Returns the number of findings submitted (the apply step logs its
    own applied tally — unresolvable names are skipped there).
    """
    exportable = _exportable(findings)
    if not exportable:
        return 0

    export_dir = out_dir / "ghidra-export"
    export_dir.mkdir(exist_ok=True)

    from .bridge import GhidraBridge
    bridge = GhidraBridge(gpr_path)
    out_gpr = bridge.export_enrichments(
        None, export_dir / gpr_path.name, findings=exportable,
    )
    bridge.close()
    logger.info(
        "ghidra round-trip: %d finding(s) submitted → %s",
        len(exportable), out_gpr,
    )
    return len(exportable)


def collect_agentic_findings(
    analysed_results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Collect exportable findings from orchestrated-report records.

    Records carry ``is_true_positive`` and the boolean exploitability
    verdict as ``is_exploitable`` / ``exploitable``; the analysis dict
    (may be null on prep-mode records) has ``reasoning`` /
    ``attack_scenario``, and ``message`` is the scanner-level text.
    """
    exploitable = [
        r for r in (analysed_results or [])
        if r.get("is_true_positive")
        and (r.get("is_exploitable") or r.get("exploitable"))
    ]

    findings = []
    for r in exploitable:
        analysis = r.get("analysis") or {}
        summary = (
            analysis.get("attack_scenario")
            or analysis.get("reasoning")
            or r.get("message")
            or "finding"
        )
        metadata = r.get("metadata") or {}
        findings.append({
            "summary": str(summary)[:300],
            "severity": r.get("level", "warning"),
            "function": metadata.get("name") or r.get("function_name") or "",
            "address": r.get("address"),
        })
    return findings


def collect_journal_findings(out_dir: Path) -> List[Dict[str, Any]]:
    """Collect exportable findings from a run's review journal.

    The journal lives as ``review-journal.jsonl`` directly in the run
    output directory.
    """
    try:
        from core.coverage.journal import JOURNAL_FILENAME, load_entries
    except ImportError:
        logger.debug("journal not available for ghidra round-trip")
        return []

    if not (out_dir / JOURNAL_FILENAME).is_file():
        return []

    entries = list(load_entries(out_dir))
    finding_entries = [
        e for e in entries if e.verdict in ("finding", "suspicious")
    ]

    return [
        {
            "summary": e.body[:200] if e.body else f"{e.verdict}: {e.file}:{e.function}",
            "severity": "High" if e.verdict == "finding" else "Medium",
            "function": e.function,
            "cwe": e.cwe or "",
        }
        for e in finding_entries
    ]


def collect_annotation_findings(out_dir: Path) -> List[Dict[str, Any]]:
    """Collect exportable entries from a run's annotation directory.

    Every annotation becomes a plate comment; only finding/suspicious
    statuses carry a severity and therefore earn a bookmark.
    """
    annotations_dir = out_dir / "annotations"
    if not annotations_dir.is_dir():
        return []

    try:
        from core.annotations.storage import iter_all_annotations
    except ImportError:
        logger.debug("annotations not available for ghidra round-trip")
        return []

    annotations = list(iter_all_annotations(annotations_dir))

    _STATUS_LABELS = {
        "finding": "Finding",
        "suspicious": "Suspicious",
        "clean": "Reviewed (clean)",
        "entry_point": "Entry Point",
        "sink": "Sink",
        "trust_boundary": "Trust Boundary",
        "flow_step": "Flow Step",
        "unchecked_flow": "Unchecked Flow",
        "dormant": "Dormant",
        "error": "Error",
    }
    _BOOKMARK_STATUSES = {"finding", "suspicious"}

    findings = []
    for ann in annotations:
        status = ann.metadata.get("status", "")
        label = _STATUS_LABELS.get(status, status)
        body = ann.body.strip()
        summary = f"[{label}] {ann.function}"
        if body:
            summary += f": {body[:150]}"
        entry: Dict[str, Any] = {
            "summary": summary,
            "function": ann.function,
        }
        if status in _BOOKMARK_STATUSES:
            entry["severity"] = "High" if status == "finding" else "Medium"
        findings.append(entry)
    return findings


def export_all_to_ghidra(
    out_dir: Path,
    gpr_path: Path,
    analysed_results: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, int]:
    """Export every finding source in *out_dir* in ONE apply pass.

    Gathers agentic results, journal findings, and annotations, then
    prepares a single working copy and applies once — several apply
    passes into the same directory would each re-copy the project and
    clobber the previous pass's enrichments. Per-source auto-sync
    entry points return with the attach follow-up (projects-schema
    rework).

    Returns per-source submitted counts plus ``"total"``.
    """
    agentic = collect_agentic_findings(analysed_results or [])
    journal = collect_journal_findings(out_dir)
    annotations = collect_annotation_findings(out_dir)

    combined = agentic + journal + annotations
    total = _apply_findings(gpr_path, out_dir, combined)
    return {
        "agentic": len(_exportable(agentic)),
        "journal": len(_exportable(journal)),
        "annotations": len(_exportable(annotations)),
        "total": total,
    }
