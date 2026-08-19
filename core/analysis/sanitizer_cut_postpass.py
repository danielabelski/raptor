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

# Source-shaped call patterns per language, grouped by SOURCE KIND —
# the taxonomy mirrors the CodeQL threat-model kinds the programme
# already trusts (remote/servlet, console, environment, file,
# properties, database, socket). Seed sets <= 9 patterns per kind;
# growth must come from learned vocabulary, never this table.
#
# Per-kind keys beyond "patterns":
#   file_evidence — regexes of which at least one must appear ANYWHERE
#       in the file for the kind to activate. Line-level matching
#       cannot see receiver chains declared on earlier lines, so this
#       is how readLine stays a console source only where System.in is
#       actually in play — a StringReader-only file activates nothing.
#   exclude_line — line-level negative guards (System.getProperty is
#       the environment kind, not the properties kind).
#   resolver_composed — the properties kind composes with b22's strict
#       resolver, RESOLVER FIRST: a getProperty read proven to yield
#       only file-constant/literal-default values is a CONSTANT, not a
#       source; only unresolved reads are tainted-file candidates.
#
# Widening this table is safety-positive for the gate: candidates are
# combined all-must-suppress, so extra candidates make suppression
# strictly harder — the hazard of a MISSING pattern (the true source
# unmatched while another line matches) shrinks as coverage grows.
_SOURCE_KINDS: Dict[str, Dict[str, Dict[str, Any]]] = {
    "java": {
        "servlet": {
            "patterns": (
                r"\.getParameter\s*\(",
                r"\.getParameterValues\s*\(",
                r"\.getParameterMap\s*\(",
                r"\.getHeader\s*\(",
                r"\.getHeaderNames\s*\(",
                r"\.getHeaders\s*\(",
                r"\.getIntHeader\s*\(",
                r"\.getCookies\s*\(",
                r"\.getQueryString\s*\(",
            ),
        },
        "console": {
            "patterns": (
                r"\.readLine\s*\(",
                r"\.nextLine\s*\(",
                r"\.next\s*\(\s*\)",
            ),
            "file_evidence": (r"System\s*\.\s*in\b",),
        },
        "environment": {
            "patterns": (
                r"System\s*\.\s*getenv\s*\(",
                r"System\s*\.\s*getProperty\s*\(",
            ),
        },
        "file": {
            "patterns": (
                r"\.readLine\s*\(",
                r"\.read\s*\(",
            ),
            "file_evidence": (
                r"new\s+FileReader\b",
                r"new\s+FileInputStream\b",
            ),
        },
        "properties": {
            "patterns": (r"\.getProperty\s*\(",),
            "exclude_line": (r"System\s*\.\s*getProperty",),
            "resolver_composed": True,
        },
        "database": {
            "patterns": (
                r"\.getString\s*\(",
                r"\.getNString\s*\(",
                r"\.getObject\s*\(",
            ),
            "file_evidence": (r"\bResultSet\b", r"\bexecuteQuery\b"),
        },
        "socket": {
            "patterns": (r"\.getInputStream\s*\(",),
            "file_evidence": (r"\bSocket\b",),
        },
    },
    "python": {
        "web": {
            "patterns": (
                r"request\.args",
                r"request\.form",
                r"request\.values",
                r"request\.get_json\s*\(",
            ),
        },
    },
    "c": {},
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
    # Which optional gate mechanisms fired (CFG build_notes such as
    # switch:constant-resolved, plus table-load-resolved constancy) —
    # the refusal/mechanism telemetry that ranks the next iteration.
    mechanism_counts: Dict[str, int] = field(default_factory=dict)
    # Which source KINDS supplied the candidates for examined findings
    # (locator path only; codeFlows findings are counted as "trace").
    source_kind_counts: Dict[str, int] = field(default_factory=dict)

    def source_kind(self, kind: str) -> None:
        self.source_kind_counts[kind] = self.source_kind_counts.get(kind, 0) + 1

    def refuse(self, reason: str) -> None:
        self.refused += 1
        self.refused_reasons[reason] = self.refused_reasons.get(reason, 0) + 1

    def mechanism(self, note: str) -> None:
        self.mechanism_counts[note] = self.mechanism_counts.get(note, 0) + 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "examined": self.examined,
            "recorded_suppress": self.recorded_suppress,
            "recorded_candidate": self.recorded_candidate,
            "refused": self.refused,
            "refused_reasons": dict(sorted(self.refused_reasons.items())),
            "budget_exhausted_skips": self.budget_exhausted_skips,
            "mechanism_counts": dict(sorted(self.mechanism_counts.items())),
            "source_kind_counts": dict(sorted(self.source_kind_counts.items())),
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
    # Alias the imports: the two builders export the same
    # ``_get_parser`` name with different signatures (java takes no
    # argument, cpp takes the language), and importing both bare into
    # one function scope invites exactly the cross-binding mixup that
    # static call checkers flag.
    try:
        if language == "java":
            from core.analysis.cfg_builder_java import (
                _get_parser as _get_java_parser,
            )
            return _get_java_parser() is not None
        if language == "c":
            from core.analysis.cfg_builder_cpp import (
                _get_parser as _get_cpp_parser,
            )
            return _get_cpp_parser("c") is not None
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


def _scan_file_for_kinds(
    file_path: Path, language: str, extra_patterns: tuple,
) -> Optional[List[tuple]]:
    """Per-file scan: ``[(line, frozenset(kinds)), ...]`` or None.

    Kind activation, exclusion, and the properties/resolver
    composition all happen here so the result is cacheable per file.
    """
    kinds_table = _SOURCE_KINDS.get(language) or {}
    if not kinds_table and not extra_patterns:
        return []
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    active: Dict[str, Dict[str, Any]] = {}
    for kind, spec in kinds_table.items():
        evidence = spec.get("file_evidence")
        if evidence and not any(re.search(p, text) for p in evidence):
            continue
        active[kind] = {
            "regex": re.compile("|".join(spec["patterns"])),
            "exclude": [re.compile(p) for p in spec.get("exclude_line", ())],
            "resolver": bool(spec.get("resolver_composed")),
        }
    extra_regex = re.compile("|".join(extra_patterns)) if extra_patterns else None

    resolver = None
    resolver_built = False
    out: List[tuple] = []
    for i, line in enumerate(text.splitlines()):
        lineno = i + 1
        kinds = set()
        for kind, spec in active.items():
            if not spec["regex"].search(line):
                continue
            if any(ex.search(line) for ex in spec["exclude"]):
                continue
            if spec["resolver"]:
                # Resolver first: a proven config constant is not a
                # source. Resolver failure (parser missing, ambiguous
                # line, unresolved read) keeps the line a candidate —
                # the conservative direction for a suppressor.
                if not resolver_built:
                    resolver_built = True
                    try:
                        from core.analysis.config_resolve_java import (
                            make_config_resolver,
                        )
                        resolver = make_config_resolver(
                            text, str(file_path))
                    except Exception:  # noqa: BLE001
                        resolver = None
                if resolver is not None:
                    try:
                        from core.analysis.config_resolve_java import (
                            resolve_line,
                        )
                        if resolve_line(resolver, lineno).resolved:
                            continue
                    except Exception:  # noqa: BLE001
                        pass
            kinds.add(kind)
        if extra_regex is not None and extra_regex.search(line):
            kinds.add("learned")
        if kinds:
            out.append((lineno, frozenset(kinds)))
    return out


def _candidate_source_lines_with_kinds(
    file_path: Path, sink_line: int, language: str,
    _cache: Dict[Path, Optional[List[tuple]]],
    extra_patterns: tuple = (),
) -> List[tuple]:
    """Source-shaped lines before the sink with their source kinds.

    The soundness argument for multiple candidates: the taint rule's
    withheld trace started at ONE of these lines, so the gate verdict
    may only suppress when the flow from EVERY candidate is cut — the
    caller enforces all-must-suppress. Zero candidates, an unreadable
    file, or more than :data:`_MAX_CANDIDATE_SOURCES` return ``[]``
    (refusal).
    """
    if file_path not in _cache:
        _cache[file_path] = _scan_file_for_kinds(
            file_path, language, extra_patterns)
    entries = _cache[file_path]
    if entries is None:
        return []
    before_sink = [(ln, kinds) for ln, kinds in entries if ln < sink_line]
    if not before_sink or len(before_sink) > _MAX_CANDIDATE_SOURCES:
        return []
    return before_sink


def _candidate_source_lines(
    file_path: Path, sink_line: int, language: str,
    _cache: Dict[Path, Optional[List[tuple]]],
    extra_patterns: tuple = (),
) -> List[int]:
    """Back-compat lines-only view of the kinds variant."""
    return [ln for ln, _ in _candidate_source_lines_with_kinds(
        file_path, sink_line, language, _cache, extra_patterns)]


def _locate_unique_source_line(
    file_path: Path, sink_line: int, language: str,
    _cache: Dict[Path, Optional[List[int]]],
    extra_patterns: tuple = (),
) -> Optional[int]:
    """Back-compat single-source form: the file's single source-shaped
    call before the sink, or None when zero/ambiguous/unreadable."""
    lines = _candidate_source_lines(
        file_path, sink_line, language, _cache, extra_patterns)
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


# Learned source-method names must be plain Java identifiers before
# they become regex alternates — anything else is refused (a learned
# name is derived from parsed source, but the boundary revalidates).
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


def _compile_extra_source_patterns(names: Iterable[str]) -> tuple:
    """Run-scoped learned source patterns (e.g. source-wrapper methods).

    Each valid identifier becomes a ``\\.name\\s*(`` call pattern —
    the same shape as the seed table. Invalid names are dropped, not
    escaped: the caller passes mechanically-derived method names, so
    anything non-identifier is a contract violation worth losing.
    """
    out = []
    for name in names or ():
        if isinstance(name, str) and _IDENT_RE.match(name):
            out.append(r"\." + re.escape(name) + r"\s*\(")
    return tuple(out)


def run_postpass(
    sarif_paths: Iterable[Path],
    repo_root: Path,
    out_dir: Path,
    *,
    budget_seconds: float = 180.0,
    extra_source_patterns: Iterable[str] = (),
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
    learned_patterns = _compile_extra_source_patterns(extra_source_patterns)
    if learned_patterns:
        stats.mechanism_counts["learned-source-patterns"] = len(learned_patterns)
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
            if not sanitizer_callables_for_cwe(cwe, language) \
                    and language != "java":
                # No catalog coverage for this class/language. Java
                # proceeds regardless: the constant-definers and
                # collection-guard pre-checks suppress without any
                # call-shaped sanitizer, and sqli/cmdi/pathtrav — the
                # classes with EMPTY Java catalogs — are exactly where
                # the allowlist-guard idiom lives.
                continue
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
            stats.source_kind("trace")
        else:
            with_kinds = _candidate_source_lines_with_kinds(
                resolved_path, int(sink_line), language, source_cache,
                learned_patterns if language == "java" else (),
            )
            source_lines = [ln for ln, _ in with_kinds]
            for kind in sorted({k for _, ks in with_kinds for k in ks}):
                stats.source_kind(kind)
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
                    extra_bindings=resolved.inter_proc_bindings,
                    java_source_text=java_text,
                    java_file_path=str(resolved_path),
                    repo_root=str(repo_root),
                )
            except Exception:  # noqa: BLE001 — arbitrary scanned source can break parsing
                verdicts = ["gate-error"]
                break
            for note in getattr(resolved.cfg, "build_notes", ()) or ():
                stats.mechanism(note)
            reason_text = getattr(result, "reason", "") or ""
            if "constant-table load" in reason_text:
                stats.mechanism("constant:table-load")
            if reason_text.startswith("collection-membership guard"):
                stats.mechanism("collection:membership-guard")
            if ("conduit helper" in reason_text
                    or reason_text.startswith("conduit-constant")):
                stats.mechanism("conduit:constant")
            if "(conduit transparency)" in reason_text:
                stats.mechanism("conduit:transparency")
            if "constant-key collection round-trip" in reason_text:
                stats.mechanism("collection:constant-roundtrip")
            if "tracked local collection" in reason_text:
                stats.mechanism("collection:sanitizer-elements")
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
