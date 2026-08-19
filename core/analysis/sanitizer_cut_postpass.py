"""Record-only sanitizer-cut post-pass over scan SARIF findings.

The value-bound gate (:mod:`core.analysis.sanitizer_cut`) runs inside
the audit / smt_barrier paths, so a plain ``/scan`` run produced no
``suppressions.jsonl`` evidence and the recall harness's warm scorer
had nothing to measure. This post-pass closes that gap: after the
scanner writes its SARIFs, every finding whose CWE has catalog
sanitizers for the file's language is resolved and evaluated through
the production gate, and ``suppress`` / ``candidate_only`` verdicts
are written as RECORD-ONLY evidence (``dropped: false`` — see the
``sanitizer_dominated`` earning contract in
:mod:`core.analysis.reach_witness`). No finding is mutated, demoted,
or dropped here, in any mode.

Source-line discovery
---------------------

The gate needs a taint-source line. CodeQL findings carry one in their
SARIF codeFlows. Semgrep OSS 1.172 computes taint traces but withholds
them from machine output (``dataflow_trace`` requires login), so
semgrep findings get a conservative locator instead: the file must
contain exactly ONE source-shaped call before the sink line — zero or
several source-shaped lines refuse the finding (counted, never
guessed). A wrong source guess is the false-suppression direction, so
ambiguity always loses. The per-language source shapes are seed sets
(<= 9 names each); project-specific sources must come from learned
vocabulary, never this table.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

logger = logging.getLogger(__name__)

# Languages with a wired resolver leg (python native, java via
# cfg_builder_java, c via the cpp intraproc path). Anything else is
# refused before the resolver is imported.
_SUPPORTED_LANGUAGES = frozenset({"python", "java", "c"})

_EXT_LANGUAGE = {
    ".py": "python",
    ".java": "java",
    ".c": "c",
    ".h": "c",
}

# Source-shaped call patterns per language — seed sets for the unique-
# source locator (growth must come from learned vocabulary, not this
# table). Java: the servlet-request getters the registry taint rules
# themselves treat as sources. Python: the common web-request accessors.
_SOURCE_PATTERNS: Dict[str, tuple] = {
    "java": (
        r"\.getParameter\s*\(",
        r"\.getParameterValues\s*\(",
        r"\.getHeader\s*\(",
        r"\.getCookies\s*\(",
        r"\.getQueryString\s*\(",
    ),
    "python": (
        r"request\.args",
        r"request\.form",
        r"request\.values",
        r"request\.get_json\s*\(",
    ),
    "c": (),
}


@dataclass
class PostpassStats:
    """Counters for the one-line summary and scan_metrics."""

    examined: int = 0
    recorded_suppress: int = 0
    recorded_candidate: int = 0
    refused: int = 0
    refused_reasons: Dict[str, int] = field(default_factory=dict)
    budget_exhausted_skips: int = 0
    elapsed_seconds: float = 0.0

    def refuse(self, reason: str) -> None:
        self.refused += 1
        self.refused_reasons[reason] = self.refused_reasons.get(reason, 0) + 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "examined": self.examined,
            "recorded_suppress": self.recorded_suppress,
            "recorded_candidate": self.recorded_candidate,
            "refused": self.refused,
            "refused_reasons": dict(sorted(self.refused_reasons.items())),
            "budget_exhausted_skips": self.budget_exhausted_skips,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
        }


def _language_for(file_path: str) -> Optional[str]:
    for ext, lang in _EXT_LANGUAGE.items():
        if file_path.lower().endswith(ext):
            return lang
    return None


def _resolver_grammar_available(language: str) -> bool:
    """True when the resolver leg for *language* has its parser.

    Python needs only stdlib ``ast``; java and c need optional
    tree-sitter grammar wheels. Probes the exact parser plumbing the
    resolver uses so a broken grammar classifies the same way the
    resolver would see it.
    """
    try:
        if language == "java":
            from core.analysis.cfg_builder_java import _get_parser
            return _get_parser() is not None
        if language == "c":
            from core.analysis.cfg_builder_cpp import _get_parser
            return _get_parser("c") is not None
    except Exception:  # noqa: BLE001 — a broken grammar counts as absent
        return False
    return True


def _grammar_ok(language: str, cache: Dict[str, bool]) -> bool:
    """Once-per-run grammar probe with the loud degradation signal.

    When the grammar for a supported language is missing, every one
    of its findings degrades to a ``language-unsupported`` refusal
    (the enumerated inconclusive the sibling channels use) instead of
    being silently folded into ``resolver-refused``, and ONE warning
    line names the missing capability — degraded coverage must never
    be indistinguishable from full coverage.
    """
    if language not in cache:
        cache[language] = _resolver_grammar_available(language)
        if not cache[language]:
            logger.warning(
                "sanitizer-cut post-pass: tree-sitter %s grammar not "
                "installed — %s findings degrade to language-unsupported "
                "refusals (no suppression evidence recorded)",
                language, language,
            )
    return cache[language]


# A finding whose file has more source-shaped lines than this before
# the sink is refused outright — evaluating the gate from each
# candidate stays sound at any count, but the cost is per-candidate
# and unbounded fan-out is a DoS surface on hostile input.
_MAX_CANDIDATE_SOURCES = 4


def _candidate_source_lines(
    file_path: Path, sink_line: int, language: str,
    _cache: Dict[Path, Optional[List[int]]],
) -> List[int]:
    """Source-shaped lines before the sink (possibly several).

    The soundness argument for multiple candidates: the taint rule's
    withheld trace started at ONE of these lines, so the gate verdict
    may only suppress when the flow from EVERY candidate is cut — the
    caller enforces all-must-suppress. Zero candidates, an unreadable
    file, or more than :data:`_MAX_CANDIDATE_SOURCES` return ``[]``
    (refusal).
    """
    patterns = _SOURCE_PATTERNS.get(language) or ()
    if not patterns:
        return []
    if file_path not in _cache:
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            _cache[file_path] = None
        else:
            regex = re.compile("|".join(patterns))
            _cache[file_path] = [
                i + 1
                for i, line in enumerate(text.splitlines())
                if regex.search(line)
            ]
    lines = _cache[file_path]
    if lines is None:
        return []
    before_sink = [ln for ln in lines if ln < sink_line]
    if not before_sink or len(before_sink) > _MAX_CANDIDATE_SOURCES:
        return []
    return before_sink


def _locate_unique_source_line(
    file_path: Path, sink_line: int, language: str,
    _cache: Dict[Path, Optional[List[int]]],
) -> Optional[int]:
    """Back-compat single-source form: the file's single source-shaped
    call before the sink, or None when zero/ambiguous/unreadable."""
    lines = _candidate_source_lines(file_path, sink_line, language, _cache)
    if len(lines) != 1:
        return None
    return lines[0]


def _dataflow_source_line(finding: Mapping[str, Any]) -> Optional[int]:
    path = finding.get("dataflow_path") or {}
    source = path.get("source") or {}
    line = source.get("line")
    if isinstance(line, int) and line > 0:
        return line
    return None


def run_postpass(
    sarif_paths: Iterable[Path],
    repo_root: Path,
    out_dir: Path,
    *,
    budget_seconds: float = 180.0,
) -> Dict[str, Any]:
    """Run the record-only gate over every eligible SARIF finding.

    Returns the stats dict (also logged as a one-line summary). Any
    unexpected per-finding failure is a refusal, never an exception —
    the post-pass must not be able to fail a scan.
    """
    from core.analysis.finding_resolver import ResolvedFinding, resolve_finding
    from core.analysis.sanitizer_cut import (
        VERDICT_CANDIDATE_ONLY,
        VERDICT_SUPPRESS,
        evaluate_finding,
        record_sanitizer_cut_suppression,
    )
    from core.dataflow.sanitizer_catalog import sanitizer_callables_for_cwe
    from core.sarif.parser import parse_sarif_findings

    stats = PostpassStats()
    started = time.monotonic()
    source_cache: Dict[Path, Optional[List[int]]] = {}
    text_cache: Dict[Path, str] = {}
    grammar_cache: Dict[str, bool] = {}
    repo_root = Path(repo_root).resolve()

    findings: List[Dict[str, Any]] = []
    for sarif in sarif_paths:
        try:
            findings.extend(parse_sarif_findings(Path(sarif)))
        except Exception as exc:  # noqa: BLE001 — hostile/malformed SARIF must not kill the pass
            logger.warning("sanitizer-cut post-pass: unreadable SARIF %s: %s", sarif, exc)

    # Group by file so the resolver's per-finding parse cost clusters;
    # the source-locator cache is per-file already.
    findings.sort(key=lambda f: str(f.get("file") or ""))

    for finding in findings:
        if time.monotonic() - started > budget_seconds:
            stats.budget_exhausted_skips += 1
            continue

        cwe = finding.get("cwe_id") or ""
        file_path = str(finding.get("file") or "")
        sink_line = finding.get("startLine") or 0
        if not (cwe and file_path and sink_line):
            continue  # not an eligible shape; don't count as examined

        language = _language_for(file_path)
        if language not in _SUPPORTED_LANGUAGES:
            continue

        try:
            if not sanitizer_callables_for_cwe(cwe, language):
                continue  # no catalog coverage for this class/language
        except Exception:  # noqa: BLE001
            continue

        resolved_path = Path(file_path)
        if not resolved_path.is_absolute():
            resolved_path = repo_root / file_path
        try:
            inside = resolved_path.resolve().is_relative_to(repo_root)
        except (OSError, ValueError):
            inside = False
        if not inside or not resolved_path.is_file():
            stats.examined += 1
            stats.refuse("file-outside-target-or-missing")
            continue

        stats.examined += 1

        if not _grammar_ok(language, grammar_cache):
            stats.refuse("language-unsupported")
            continue

        trace_line = _dataflow_source_line(finding)
        if trace_line is not None:
            source_lines = [trace_line]
        else:
            source_lines = _candidate_source_lines(
                resolved_path, int(sink_line), language, source_cache,
            )
        if not source_lines:
            stats.refuse("no-source-candidates")
            continue

        # Evaluate from EVERY candidate source. Suppress only when
        # all candidates suppress (the withheld taint trace started at
        # one of them, so every one must be cut); candidate_only when
        # nothing worse than candidate_only appears; anything else —
        # a no_suppress verdict, a resolver refusal, or a gate error
        # on any candidate — refuses the whole finding.
        verdicts: List[str] = []
        native = None
        for source_line in source_lines:
            native = {
                "cwe": cwe,
                "file_path": str(resolved_path),
                "source_line": int(source_line),
                "sink_line": int(sink_line),
                "language": language,
                "rule_id": finding.get("rule_id") or "",
                "tool": finding.get("tool") or "",
            }
            try:
                resolved = resolve_finding(native)
                if not isinstance(resolved, ResolvedFinding):
                    verdicts = ["resolver-refused"]
                    break
                if language == "java":
                    if resolved_path not in text_cache:
                        try:
                            text_cache[resolved_path] = resolved_path.read_text(
                                encoding="utf-8", errors="replace",
                            )
                        except OSError:
                            text_cache[resolved_path] = ""
                    java_text = text_cache[resolved_path] or None
                else:
                    java_text = None
                result = evaluate_finding(
                    resolved.cfg,
                    [resolved.source_node],
                    resolved.sink_node,
                    cwe=resolved.cwe,
                    language=resolved.language,
                    source_symbols=resolved.source_symbols,
                    sink_arg=resolved.sink_arg,
                    java_source_text=java_text,
                )
            except Exception:  # noqa: BLE001 — arbitrary scanned source can break parsing
                verdicts = ["gate-error"]
                break
            verdicts.append(result.verdict)

        if verdicts == ["resolver-refused"]:
            stats.refuse("resolver-refused")
            continue
        if verdicts == ["gate-error"]:
            stats.refuse("gate-error")
            continue
        if all(v == VERDICT_SUPPRESS for v in verdicts):
            stats.recorded_suppress += 1
        elif all(v in (VERDICT_SUPPRESS, VERDICT_CANDIDATE_ONLY)
                 for v in verdicts):
            stats.recorded_candidate += 1
            if len(verdicts) > 1:
                # Mixed multi-source candidate: counted, not recorded —
                # a record carrying one candidate source's bindings
                # would misattribute the others' evidence.
                continue
        else:
            stats.refuse("no-suppress-verdict")
            continue
        try:
            # Record-only, always: enforce stays False until the
            # sanitizer_dominated witness earns hard suppression.
            record_sanitizer_cut_suppression(out_dir, native, result)
        except Exception as exc:  # noqa: BLE001
            logger.warning("sanitizer-cut post-pass: record failed: %s", exc)

    stats.elapsed_seconds = time.monotonic() - started
    logger.info(
        "sanitizer-cut post-pass: %d examined, %d suppress-verdicts recorded, "
        "%d candidate_only recorded, %d refused, %d skipped on budget (%.1fs)",
        stats.examined, stats.recorded_suppress, stats.recorded_candidate,
        stats.refused, stats.budget_exhausted_skips, stats.elapsed_seconds,
    )
    return stats.to_dict()
