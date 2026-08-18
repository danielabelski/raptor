"""Consistency comparators beyond the return census.

Phase-1 dimensions:

* **Flag/mode consistency** (§3.7) — "n opens use ``O_NOFOLLOW`` /
  ``0600``, 1 doesn't; n requests set ``verify=True``, 1 sets
  ``verify=False``". Peer group: same-callee sites with a
  constant-resolvable argument at the same position. For bitmask
  positions the majority vote is **per bit** (a flag present in
  ≥ 75 % of sites and absent in the deviant — set equality is too
  strict); for value/kwarg positions it is a value majority. The
  comparator is vocabulary-free; the Tier-A flag registry
  (:mod:`core.audit.fail_open_roles`, the single Tier-A home) only
  *grades* security relevance afterwards. Detection-grade throughout
  — mode differences are frequently intentional — so every receipt
  carries the ``-majority`` rule-id variant and promotes only through
  cross-namespace aggregation.

* **Error-path resource cleanup** (§3.2) — "n error paths
  free/unlock/close, 1 doesn't". Learned acquire/release pairs only
  (study domain-model ``paired_operations`` +
  ``contract_pairs.discover_project_verbs``); no hardcoded project
  API lists. Promote-capable only when the pair contract is learned
  AND the binding does not escape the function; ownership transfer is
  the classic intentional deviation → ``ownership-unresolved``.

All comparators ride the census's shared parse cache — zero LLM
calls, zero subprocesses.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from .callsite_consistency import (
    USAGE_TESTED,
    _KEYWORDS,
    _SECURITY_CALLEE_RE,
    _callee_name_ts,
    _classify_usage_ts,
    parse_source_cached,
)
from .fail_open_roles import SecurityFlag, security_flag_role
from .peer_evidence import PeerEvidence, PeerExhibit

logger = logging.getLogger(__name__)

try:
    from .ts_extract import (
        _CALL_TYPES,
        _find_enclosing_function,
        _get_func_name,
        _node_line,
        _node_text,
        _walk_descendants,
    )
    _TS_AVAILABLE = True
except ImportError:
    _TS_AVAILABLE = False

DIMENSION_FLAG_MODE = "flag-mode"
DIMENSION_CLEANUP = "cleanup"

MIN_GROUP_SITES = 3
CONSISTENCY_RATIO = 0.75

_FLAG_TOKEN_RE = re.compile(r"\b([A-Z][A-Z0-9_]{2,})\b")
_INT_LITERAL_RE = re.compile(
    r"^(?:0[xX][0-9a-fA-F]+|0[oO][0-7]+|0[0-7]*|[1-9]\d*)$",
)

# Bound the argument-position analysis (varargs tails are noise).
_MAX_ARG_POSITIONS = 6
_MAX_DEVIATIONS = 80


def _parse_int_literal(text: str) -> int | None:
    t = text.strip()
    if not _INT_LITERAL_RE.match(t):
        return None
    try:
        if t.lower().startswith("0x"):
            return int(t, 16)
        if t.lower().startswith("0o"):
            return int(t, base=0)
        if t.startswith("0") and len(t) > 1:
            return int(t, 8)
        return int(t)
    except ValueError:
        return None


@dataclass
class _ArgSite:
    """One call site's argument view."""

    file: str
    line: int
    enclosing_function: str
    args: list[str] = field(default_factory=list)
    kwargs: dict[str, str] = field(default_factory=dict)
    snippet: str = ""


@dataclass
class FlagModeDeviation:
    """One flag/mode outlier (§3.7). Always detection-grade."""

    callee: str
    position: str          # "arg2" | "kwarg:verify"
    kind: str              # "bitmask" | "value" | "kwarg"
    file: str
    line: int
    enclosing_function: str
    majority_repr: str
    deviant_repr: str
    n: int
    conforming: int
    security: SecurityFlag | None = None
    cwe: str = ""
    peer_evidence: PeerEvidence | None = None

    @property
    def ratio(self) -> float:
        return self.conforming / self.n if self.n else 0.0

    @property
    def description(self) -> str:
        graded = (
            f" [{self.cwe}: {self.security.role}]" if self.security
            else ""
        )
        return (
            f"{self.callee}({self.position}): "
            f"{self.conforming}/{self.n} sites use "
            f"{self.majority_repr}; this site uses "
            f"{self.deviant_repr}{graded}"
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "callee": self.callee,
            "position": self.position,
            "kind": self.kind,
            "file": self.file,
            "line": self.line,
            "enclosing_function": self.enclosing_function,
            "majority": self.majority_repr,
            "deviant": self.deviant_repr,
            "n": self.n,
            "conforming": self.conforming,
            "ratio": round(self.ratio, 3),
            "cwe": self.cwe,
        }
        if self.security is not None:
            d["security_role"] = self.security.role
        if self.peer_evidence is not None:
            d["peer_evidence"] = self.peer_evidence.to_dict()
        return d


def _extract_arg_sites(
    source_texts: dict[str, str],
) -> dict[str, list[_ArgSite]]:
    """Per-callee argument views, one parse per file (shared cache)."""
    if not _TS_AVAILABLE:
        return {}
    by_callee: dict[str, list[_ArgSite]] = {}
    for file_path, source in source_texts.items():
        tree, lang = parse_source_cached(file_path, source)
        if tree is None or lang is None:
            continue
        call_types = _CALL_TYPES.get(lang, ())
        if not call_types:
            continue
        src = source.encode("utf-8", errors="replace")
        lines = source.splitlines()
        for node in _walk_descendants(tree.root_node):
            if node.type not in call_types:
                continue
            callee = _callee_name_ts(node, lang, src)
            if not callee or callee in _KEYWORDS or len(callee) < 2:
                continue
            arg_node = node.child_by_field_name("arguments")
            if arg_node is None:
                continue
            args: list[str] = []
            kwargs: dict[str, str] = {}
            for child in arg_node.children:
                if not child.is_named or child.type == "comment":
                    continue
                if child.type == "keyword_argument":
                    kname = child.child_by_field_name("name")
                    kvalue = child.child_by_field_name("value")
                    if kname is not None and kvalue is not None:
                        kwargs[_node_text(kname, src)] = _node_text(
                            kvalue, src,
                        ).strip()
                    continue
                args.append(_node_text(child, src).strip())
            enclosing = _find_enclosing_function(node, lang)
            func_name = (
                _get_func_name(enclosing, lang, src)
                if enclosing else "<module>"
            )
            line = _node_line(node)
            snippet = (
                lines[line - 1].strip()[:200]
                if 1 <= line <= len(lines) else ""
            )
            by_callee.setdefault(callee, []).append(_ArgSite(
                file=file_path,
                line=line,
                enclosing_function=func_name,
                args=args[:_MAX_ARG_POSITIONS],
                kwargs=kwargs,
                snippet=snippet,
            ))
    return by_callee


def _flag_tokens(arg_text: str) -> frozenset[str] | None:
    """Bitmask view of an argument: UPPER_CASE flag tokens. None when
    the argument isn't a flag expression."""
    if "|" not in arg_text and not _FLAG_TOKEN_RE.fullmatch(arg_text.strip()):
        return None
    tokens = frozenset(_FLAG_TOKEN_RE.findall(arg_text))
    return tokens or None


def _resolve_value(
    arg_text: str, constants: dict[str, int] | None,
) -> int | None:
    lit = _parse_int_literal(arg_text)
    if lit is not None:
        return lit
    if constants and arg_text.strip() in constants:
        return constants[arg_text.strip()]
    return None


def _mode_grades_permissive(deviant: int, majority: int) -> bool:
    """Group/world-writable bits present in the deviant but not the
    majority (0666 among 0600 peers)."""
    return bool((deviant & 0o022) & ~(majority & 0o022))


def _peer_evidence_for(
    callee: str,
    position: str,
    deviant: _ArgSite,
    conforming_sites: list[_ArgSite],
    n: int,
) -> PeerEvidence:
    return PeerEvidence(
        dimension=DIMENSION_FLAG_MODE,
        formation="same_callee",
        group_key=f"{callee}[{position}]",
        n=n,
        conforming=len(conforming_sites),
        ratio=len(conforming_sites) / n if n else 0.0,
        deviant=PeerExhibit(deviant.file, deviant.line, deviant.snippet),
        exhibits=[
            PeerExhibit(s.file, s.line, s.snippet)
            for s in conforming_sites[:3]
        ],
        contract_source="majority",
        provenance=f"flag_mode:{position}",
    )


def detect_flag_mode_deviations(
    source_texts: dict[str, str],
    *,
    constants: dict[str, int] | None = None,
    min_sites: int = MIN_GROUP_SITES,
    ratio: float = CONSISTENCY_RATIO,
) -> list[FlagModeDeviation]:
    """Flag/mode consistency comparator (§3.7).

    *constants*: named-constant resolution table
    (``constant_resolution.build_unique_constants(...).as_int_dict()``)
    — reused, never reimplemented.
    """
    deviations: list[FlagModeDeviation] = []
    by_callee = _extract_arg_sites(source_texts)

    for callee, sites in sorted(by_callee.items()):
        if len(sites) < min_sites:
            continue

        # Positional analysis.
        max_pos = max(len(s.args) for s in sites)
        for pos in range(min(max_pos, _MAX_ARG_POSITIONS)):
            with_pos = [s for s in sites if len(s.args) > pos]
            if len(with_pos) < min_sites:
                continue
            position = f"arg{pos}"

            # Bitmask leg: per-bit majority. A position is a mask
            # only when some site actually combines flags — a bare
            # UPPER_CASE token alone is a named constant and belongs
            # to the value leg (where the resolution table decides).
            is_mask_position = any("|" in s.args[pos] for s in with_pos)
            token_sets = {
                id(s): _flag_tokens(s.args[pos]) for s in with_pos
            }
            flagged = [
                s for s in with_pos if token_sets[id(s)] is not None
            ]
            if is_mask_position and len(flagged) >= min_sites:
                all_tokens: set[str] = set()
                for s in flagged:
                    all_tokens |= token_sets[id(s)]
                for token in sorted(all_tokens):
                    have = [
                        s for s in flagged if token in token_sets[id(s)]
                    ]
                    lack = [
                        s for s in flagged
                        if token not in token_sets[id(s)]
                    ]
                    if not lack or len(have) < len(flagged) * ratio \
                            or len(have) <= len(lack):
                        continue
                    sec = security_flag_role(token)
                    for s in lack:
                        deviations.append(FlagModeDeviation(
                            callee=callee,
                            position=position,
                            kind="bitmask",
                            file=s.file,
                            line=s.line,
                            enclosing_function=s.enclosing_function,
                            majority_repr=f"…|{token}",
                            deviant_repr=s.args[pos][:80],
                            n=len(flagged),
                            conforming=len(have),
                            security=sec,
                            cwe=sec.cwe if sec else "",
                            peer_evidence=_peer_evidence_for(
                                callee, f"{position}:{token}", s,
                                have, len(flagged),
                            ),
                        ))
                continue  # a bitmask position is not also a value one

            # Value leg: constant-resolvable majority.
            values = {
                id(s): _resolve_value(s.args[pos], constants)
                for s in with_pos
            }
            resolved = [s for s in with_pos if values[id(s)] is not None]
            if len(resolved) < min_sites \
                    or len(resolved) < len(with_pos) * ratio:
                continue
            counts: dict[int, int] = {}
            for s in resolved:
                counts[values[id(s)]] = counts.get(values[id(s)], 0) + 1
            majority_value = max(counts, key=lambda v: counts[v])
            if counts[majority_value] < len(resolved) * ratio:
                continue
            conforming_sites = [
                s for s in resolved if values[id(s)] == majority_value
            ]
            for s in resolved:
                if values[id(s)] == majority_value:
                    continue
                sec = None
                cwe = ""
                if _mode_grades_permissive(values[id(s)], majority_value):
                    cwe = "CWE-732"
                deviations.append(FlagModeDeviation(
                    callee=callee,
                    position=position,
                    kind="value",
                    file=s.file,
                    line=s.line,
                    enclosing_function=s.enclosing_function,
                    majority_repr=f"0o{majority_value:o}",
                    deviant_repr=s.args[pos][:80],
                    n=len(resolved),
                    conforming=len(conforming_sites),
                    security=sec,
                    cwe=cwe,
                    peer_evidence=_peer_evidence_for(
                        callee, position, s, conforming_sites,
                        len(resolved),
                    ),
                ))

        # Keyword-argument analysis (value majority per kwarg name).
        kwarg_names: set[str] = set()
        for s in sites:
            kwarg_names |= set(s.kwargs)
        for kname in sorted(kwarg_names):
            with_kw = [s for s in sites if kname in s.kwargs]
            if len(with_kw) < min_sites:
                continue
            counts_s: dict[str, int] = {}
            for s in with_kw:
                v = s.kwargs[kname]
                counts_s[v] = counts_s.get(v, 0) + 1
            majority_v = max(counts_s, key=lambda v: counts_s[v])
            if counts_s[majority_v] < len(with_kw) * ratio:
                continue
            conforming_sites = [
                s for s in with_kw if s.kwargs[kname] == majority_v
            ]
            sec = security_flag_role(kname)
            for s in with_kw:
                if s.kwargs[kname] == majority_v:
                    continue
                deviations.append(FlagModeDeviation(
                    callee=callee,
                    position=f"kwarg:{kname}",
                    kind="kwarg",
                    file=s.file,
                    line=s.line,
                    enclosing_function=s.enclosing_function,
                    majority_repr=f"{kname}={majority_v}",
                    deviant_repr=f"{kname}={s.kwargs[kname]}",
                    n=len(with_kw),
                    conforming=len(conforming_sites),
                    security=sec,
                    cwe=sec.cwe if sec else "",
                    peer_evidence=_peer_evidence_for(
                        callee, f"kwarg:{kname}", s, conforming_sites,
                        len(with_kw),
                    ),
                ))

        if len(deviations) >= _MAX_DEVIATIONS:
            break

    deviations.sort(
        key=lambda d: (d.security is None, -d.ratio, d.file, d.line),
    )
    return deviations[:_MAX_DEVIATIONS]


# ── error-path resource cleanup (§3.2) ──────────────────────────────


@dataclass(frozen=True)
class LearnedPair:
    """One learned acquire/release contract pair. Learned only —
    study domain-model ``paired_operations`` or ``contract_pairs``
    verb mining; there is no static fallback list here."""

    acquire: str
    release: str
    kind: str          # "alloc_free" | "lock_unlock" | "mutex" | ...
    source: str        # "domain_model" | "project_verbs"
    provenance: str    # e.g. "paired_operations:mutex"


def learned_cleanup_pairs(
    domain_model: dict[str, Any] | None,
    function_names: set[str] | None = None,
) -> list[LearnedPair]:
    """Acquire/release pairs from the learned surfaces (§3.2):
    domain-model ``paired_operations`` (the proven seam), plus
    ``contract_pairs.discover_project_verbs`` verb pairs bound to the
    actual function names present in the inventory."""
    pairs: list[LearnedPair] = []
    seen: set[tuple[str, str]] = set()

    for entry in (domain_model or {}).get("paired_operations") or []:
        if not isinstance(entry, dict):
            continue
        acquire = str(entry.get("acquire") or "").split("(")[0].strip()
        release = str(entry.get("release") or "").split("(")[0].strip()
        kind = str(entry.get("kind") or "").lower() or "discovered"
        if not acquire or not release:
            continue
        key = (acquire, release)
        if key in seen:
            continue
        seen.add(key)
        pairs.append(LearnedPair(
            acquire=acquire,
            release=release,
            kind=kind,
            source="domain_model",
            provenance=f"paired_operations:{kind}",
        ))

    if function_names:
        try:
            from core.concepts.contract_pairs import discover_project_verbs
            verb_pairs = discover_project_verbs(
                [{"name": n} for n in sorted(function_names)],
            )
        except Exception:
            logger.debug("cleanup pairs: verb discovery failed",
                         exc_info=True)
            verb_pairs = []
        by_prefix: dict[str, list[str]] = {}
        for name in function_names:
            head = name.split("_", 1)[0]
            by_prefix.setdefault(head, []).append(name)
        for producer_verbs, consumer_verbs, kind in verb_pairs:
            for pverb in producer_verbs:
                for acquire in by_prefix.get(pverb, ()):
                    stem = acquire[len(pverb):]
                    if not stem.startswith("_"):
                        continue
                    for cverb in consumer_verbs:
                        release = f"{cverb}{stem}"
                        if release not in function_names:
                            continue
                        key = (acquire, release)
                        if key in seen:
                            continue
                        seen.add(key)
                        pairs.append(LearnedPair(
                            acquire=acquire,
                            release=release,
                            kind=getattr(kind, "value", str(kind)),
                            source="project_verbs",
                            provenance=(
                                f"project_verbs:{pverb}/{cverb}"
                            ),
                        ))
    return pairs


@dataclass
class CleanupDeviation:
    """One error path / sibling caller that omits the learned release."""

    pair: LearnedPair
    leg: str               # "intra_path" | "cross_function"
    file: str
    line: int              # deviant return line / function line
    enclosing_function: str
    binding: str           # captured resource variable ("" if unnamed)
    n: int                 # paths / sibling callers compared
    conforming: int
    ownership_transfer: bool = False
    peer_evidence: PeerEvidence | None = None

    @property
    def ratio(self) -> float:
        return self.conforming / self.n if self.n else 0.0

    @property
    def description(self) -> str:
        what = (
            "error paths release" if self.leg == "intra_path"
            else "sibling callers release"
        )
        suffix = (
            " (binding escapes — ownership transfer unresolved)"
            if self.ownership_transfer else ""
        )
        return (
            f"{self.conforming}/{self.n} {what} "
            f"{self.pair.acquire}()'s resource via "
            f"{self.pair.release}(); this path does not{suffix}"
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "acquire": self.pair.acquire,
            "release": self.pair.release,
            "pair_source": self.pair.source,
            "provenance": self.pair.provenance,
            "leg": self.leg,
            "file": self.file,
            "line": self.line,
            "enclosing_function": self.enclosing_function,
            "binding": self.binding,
            "n": self.n,
            "conforming": self.conforming,
            "ratio": round(self.ratio, 3),
            "ownership_transfer": self.ownership_transfer,
        }
        if self.peer_evidence is not None:
            d["peer_evidence"] = self.peer_evidence.to_dict()
        return d


_RETURN_LINE_RE = re.compile(r"^\s*return\b")


def _function_spans(
    source_texts: dict[str, str],
) -> list[tuple[str, str, int, list[str]]]:
    """(file, function, start_line, body_lines) per function, on the
    shared parse cache."""
    if not _TS_AVAILABLE:
        return []
    from .ts_extract import _FUNCTION_TYPES
    spans: list[tuple[str, str, int, list[str]]] = []
    for file_path, source in source_texts.items():
        tree, lang = parse_source_cached(file_path, source)
        if tree is None or lang is None:
            continue
        func_types = _FUNCTION_TYPES.get(lang, ())
        if not func_types:
            continue
        src = source.encode("utf-8", errors="replace")
        lines = source.splitlines()
        for node in _walk_descendants(tree.root_node):
            if node.type not in func_types:
                continue
            name = _get_func_name(node, lang, src)
            start = node.start_point[0] + 1
            end = node.end_point[0] + 1
            spans.append((file_path, name, start, lines[start - 1:end]))
    return spans


def _acquire_binding(body: list[str], acquire: str) -> tuple[int, str]:
    """(0-based line offset, binding name) of the first capturing
    acquire call, or (-1, "")."""
    pattern = re.compile(
        rf"(?:^|\W)(?:(\w+)\s*(?:=|:=)\s*)?{re.escape(acquire)}\s*\(",
    )
    for idx, line in enumerate(body):
        m = pattern.search(line)
        if m:
            return idx, m.group(1) or ""
    return -1, ""


def _binding_escapes(body: list[str], binding: str) -> bool:
    """Ownership transfer: the binding is returned or stored beyond
    the function's locals (§3.2 escape check)."""
    if not binding:
        return False
    esc = re.compile(
        rf"\breturn\s+{re.escape(binding)}\b"
        rf"|(?:->|\.)\w+\s*=\s*{re.escape(binding)}\b"
        rf"|\*\s*\w+\s*=\s*{re.escape(binding)}\b",
    )
    return any(esc.search(line) for line in body)


def detect_cleanup_deviations(
    source_texts: dict[str, str],
    pairs: list[LearnedPair],
    *,
    min_group: int = MIN_GROUP_SITES,
    ratio: float = CONSISTENCY_RATIO,
) -> list[CleanupDeviation]:
    """Error-path resource cleanup comparator (§3.2), two legs:

    * intra-function: return segments after the acquisition, majority
      of which release — extends ``intra_function``'s cleanup-set
      majority with learned pairs;
    * cross-function: sibling callers of the same acquirer, majority
      of which release somewhere in their body.

    Deviations where the binding escapes the function carry
    ``ownership_transfer=True`` — the verdict layer maps those to
    ``ownership-unresolved`` (the classic intentional deviation).
    """
    if not pairs:
        return []
    deviations: list[CleanupDeviation] = []
    spans = _function_spans(source_texts)

    for pair in pairs:
        release_re = re.compile(
            rf"(?:^|\W){re.escape(pair.release)}\s*\(",
        )

        # Cross-function leg: every function calling the acquirer.
        acquirers: list[tuple[str, str, int, list[str], str]] = []
        for file_path, name, start, body in spans:
            a_idx, binding = _acquire_binding(body, pair.acquire)
            if a_idx >= 0:
                acquirers.append((file_path, name, start, body, binding))

        if len(acquirers) >= min_group:
            releasing = [
                a for a in acquirers
                if any(release_re.search(line) for line in a[3])
            ]
            if len(releasing) >= len(acquirers) * ratio:
                exhibits = [
                    PeerExhibit(a[0], a[2], f"{a[1]} releases via "
                                            f"{pair.release}()")
                    for a in releasing[:3]
                ]
                for a in acquirers:
                    if a in releasing:
                        continue
                    file_path, name, start, body, binding = a
                    escapes = _binding_escapes(body, binding)
                    deviations.append(CleanupDeviation(
                        pair=pair,
                        leg="cross_function",
                        file=file_path,
                        line=start,
                        enclosing_function=name,
                        binding=binding,
                        n=len(acquirers),
                        conforming=len(releasing),
                        ownership_transfer=escapes,
                        peer_evidence=PeerEvidence(
                            dimension=DIMENSION_CLEANUP,
                            formation="same_callee",
                            group_key=(
                                f"{pair.acquire}/{pair.release}"
                            ),
                            n=len(acquirers),
                            conforming=len(releasing),
                            ratio=len(releasing) / len(acquirers),
                            deviant=PeerExhibit(
                                file_path, start,
                                f"{name} never calls "
                                f"{pair.release}()",
                            ),
                            exhibits=exhibits,
                            contract_source=(
                                "domain_model"
                                if pair.source == "domain_model"
                                else "convention"
                            ),
                            provenance=pair.provenance,
                        ),
                    ))

        # Intra-function leg: return segments after the acquisition.
        for file_path, name, start, body, binding in acquirers:
            a_idx, _ = _acquire_binding(body, pair.acquire)
            segments: list[tuple[int, bool]] = []  # (ret line, released)
            released = False
            for idx in range(a_idx + 1, len(body)):
                if release_re.search(body[idx]):
                    released = True
                if _RETURN_LINE_RE.match(body[idx]):
                    segments.append((start + idx, released))
                    released = False
            if len(segments) < min_group:
                continue
            conforming = [s for s in segments if s[1]]
            if len(conforming) < len(segments) * ratio:
                continue
            for ret_line, was_released in segments:
                if was_released:
                    continue
                seg_body = body  # escape judged function-wide
                escapes = _binding_escapes(seg_body, binding)
                deviations.append(CleanupDeviation(
                    pair=pair,
                    leg="intra_path",
                    file=file_path,
                    line=ret_line,
                    enclosing_function=name,
                    binding=binding,
                    n=len(segments),
                    conforming=len(conforming),
                    ownership_transfer=escapes,
                    peer_evidence=PeerEvidence(
                        dimension=DIMENSION_CLEANUP,
                        formation="branch",
                        group_key=(
                            f"{file_path}:{name}:"
                            f"{pair.acquire}/{pair.release}"
                        ),
                        n=len(segments),
                        conforming=len(conforming),
                        ratio=len(conforming) / len(segments),
                        deviant=PeerExhibit(
                            file_path, ret_line,
                            f"return path without {pair.release}()",
                        ),
                        exhibits=[
                            PeerExhibit(
                                file_path, line_no,
                                f"return path releasing via "
                                f"{pair.release}()",
                            )
                            for line_no, ok in segments if ok
                        ][:3],
                        contract_source=(
                            "domain_model"
                            if pair.source == "domain_model"
                            else "convention"
                        ),
                        provenance=pair.provenance,
                    ),
                ))

    deviations.sort(key=lambda d: (d.file, d.line))
    return deviations[:_MAX_DEVIATIONS]


# ── ordering (A-then-B) consistency (§3.5) ──────────────────────────
#
# "n sites do check-then-use, 1 does use-then-check." Peer group:
# functions calling the same callee *pair* (same-callee-pair sites —
# the census's site index generalised to pairs). Consensus is the
# majority first-occurrence order across the group; the deviant is the
# strict minority. Detection-grade THROUGHOUT (rule-id
# ``consistency:ordering-majority``): call order is often semantically
# forced by data dependencies the comparator cannot see, so a
# consensus-only deviation never promotes alone (design §3.5 —
# catalog-matched orders stay ``transform_sequence`` territory).
#
# Flavors are structural, never claimed beyond their witness:
#
# * ``check-before-use`` — the majority-first callee's return feeds a
#   truth test at the majority sites (census usage == tested);
# * ``toctou-shape`` — check-before-use AND the deviant's two calls
#   share an argument identifier (a mechanical same-resource witness;
#   CWE-367 *shape* only — no race window is proven, so the receipt
#   stays detection-grade and says so);
# * ``init-before-use`` — the majority-first callee is the acquire of
#   a *learned* pair (§3.2 sources; no hardcoded vocabulary);
# * ``sequence`` — order consensus with no stronger witness (CWE-696).
#
# Deviants whose order is data-forced (the deviant's earlier call
# binds a value the later call consumes) are returned with
# ``data_dependent=True`` — the verdict layer maps those to the
# enumerated ``order-data-dependent`` inconclusive reason instead of
# emitting a lead.
#
# Bounds: ≥ ``ORDERING_MIN_GROUP`` functions per pair, consensus ratio
# ≥ ``CONSISTENCY_RATIO``, minority strictly smaller; at most
# ``_MAX_EVENTS_PER_FUNCTION`` call events per function and
# ``_MAX_ORDER_PAIRS`` pairs per run (largest groups first); pairs are
# eligible only when a callee is security-relevant (structural stem
# regex) or the pair is learned.

DIMENSION_ORDERING = "ordering"

ORDERING_MIN_GROUP = MIN_GROUP_SITES
_MAX_EVENTS_PER_FUNCTION = 60
_MAX_ORDER_PAIRS = 300
_MAX_ARG_IDENTS = 12


@dataclass
class _CallEvent:
    """One call, in function order, with the structural facts the
    ordering comparator votes on."""

    callee: str
    line: int
    tested: bool
    lhs_names: frozenset[str]
    arg_idents: frozenset[str]
    snippet: str


def _call_lhs_names(call_node, src: bytes) -> frozenset[str]:
    """Identifiers the call's result is bound to (empty when the call
    is not the RHS of an assignment/declaration)."""
    from .callsite_consistency import (
        _ASSIGN_LHS_FIELDS,
        _TRANSPARENT_TYPES,
        _contains,
        _lhs_identifiers,
    )
    node = call_node
    while node.parent is not None:
        parent = node.parent
        lhs_field = _ASSIGN_LHS_FIELDS.get(parent.type)
        if lhs_field is not None:
            lhs = parent.child_by_field_name(lhs_field)
            if lhs is not None and _contains(lhs, call_node):
                return frozenset()
            return frozenset(
                n for n in _lhs_identifiers(lhs, src) if n and n != "_"
            )
        if parent.type in _TRANSPARENT_TYPES:
            node = parent
            continue
        return frozenset()
    return frozenset()


def _call_arg_idents(call_node, src: bytes) -> frozenset[str]:
    """Identifier tokens inside the call's argument list."""
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return frozenset()
    idents: set[str] = set()
    for n in _walk_descendants(args):
        if n.type in ("identifier", "field_identifier", "name"):
            text = _node_text(n, src)
            if text and text != "_" and text not in _KEYWORDS:
                idents.add(text)
            if len(idents) >= _MAX_ARG_IDENTS:
                break
    return frozenset(idents)


def _extract_call_events(
    source_texts: dict[str, str],
) -> dict[tuple[str, str], list[_CallEvent]]:
    """Ordered call events per (file, function), on the shared parse
    cache. Capped at ``_MAX_EVENTS_PER_FUNCTION`` events."""
    if not _TS_AVAILABLE:
        return {}
    events: dict[tuple[str, str], list[_CallEvent]] = {}
    for file_path, source in source_texts.items():
        tree, lang = parse_source_cached(file_path, source)
        if tree is None or lang is None:
            continue
        call_types = _CALL_TYPES.get(lang, ())
        if not call_types:
            continue
        src = source.encode("utf-8", errors="replace")
        lines = source.splitlines()
        for node in _walk_descendants(tree.root_node):
            if node.type not in call_types:
                continue
            callee = _callee_name_ts(node, lang, src)
            if not callee or callee in _KEYWORDS or len(callee) < 2:
                continue
            enclosing = _find_enclosing_function(node, lang)
            if enclosing is None:
                continue
            func_name = _get_func_name(enclosing, lang, src)
            key = (file_path, func_name)
            bucket = events.setdefault(key, [])
            if len(bucket) >= _MAX_EVENTS_PER_FUNCTION:
                continue
            line = _node_line(node)
            bucket.append(_CallEvent(
                callee=callee,
                line=line,
                tested=_classify_usage_ts(node, lang, src)
                == USAGE_TESTED,
                lhs_names=_call_lhs_names(node, src),
                arg_idents=_call_arg_idents(node, src),
                snippet=(
                    lines[line - 1].strip()[:200]
                    if 1 <= line <= len(lines) else ""
                ),
            ))
    return events


@dataclass
class OrderingDeviation:
    """One function whose A/B call order contradicts the consensus."""

    first_op: str          # the majority-first callee
    second_op: str         # the majority-second callee
    file: str
    line: int              # deviant's (out-of-order) earlier call line
    enclosing_function: str
    flavor: str            # check-before-use | toctou-shape |
                           #   init-before-use | sequence
    cwe: str
    n: int                 # functions voting on the pair's order
    conforming: int
    data_dependent: bool = False
    peer_evidence: PeerEvidence | None = None

    @property
    def ratio(self) -> float:
        return self.conforming / self.n if self.n else 0.0

    @property
    def description(self) -> str:
        suffix = {
            "toctou-shape": (
                " [TOCTOU shape: both calls share an argument — no "
                "race window proven, detection grade]"
            ),
            "check-before-use": " [majority tests the first call]",
            "init-before-use": " [learned acquire precedes use]",
        }.get(self.flavor, "")
        return (
            f"{self.conforming}/{self.n} functions call "
            f"{self.first_op}() before {self.second_op}(); "
            f"{self.enclosing_function} orders them the other way"
            f"{suffix}"
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "first_op": self.first_op,
            "second_op": self.second_op,
            "file": self.file,
            "line": self.line,
            "enclosing_function": self.enclosing_function,
            "flavor": self.flavor,
            "cwe": self.cwe,
            "n": self.n,
            "conforming": self.conforming,
            "ratio": round(self.ratio, 3),
            "data_dependent": self.data_dependent,
        }
        if self.peer_evidence is not None:
            d["peer_evidence"] = self.peer_evidence.to_dict()
        return d


def _first_events(
    evs: list[_CallEvent],
) -> dict[str, _CallEvent]:
    firsts: dict[str, _CallEvent] = {}
    for ev in evs:
        if ev.callee not in firsts:
            firsts[ev.callee] = ev
    return firsts


def detect_ordering_deviations(
    source_texts: dict[str, str],
    *,
    pairs: list[LearnedPair] | None = None,
    min_group: int = ORDERING_MIN_GROUP,
    ratio: float = CONSISTENCY_RATIO,
) -> list[OrderingDeviation]:
    """Ordering consistency comparator (§3.5). See the section
    docstring above for flavors, honesty rules and bounds."""
    events = _extract_call_events(source_texts)
    if not events:
        return []
    acquires = {p.acquire for p in (pairs or [])}
    learned_pairs = {(p.acquire, p.release) for p in (pairs or [])}

    # Pair census: functions in which both callees appear, keyed by
    # the sorted callee pair.
    firsts_by_func = {
        key: _first_events(evs) for key, evs in events.items()
    }
    group: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for key, firsts in firsts_by_func.items():
        callees = sorted(firsts)
        for i, a in enumerate(callees):
            for b in callees[i + 1:]:
                if not (
                    _SECURITY_CALLEE_RE.search(a)
                    or _SECURITY_CALLEE_RE.search(b)
                    or (a, b) in learned_pairs
                    or (b, a) in learned_pairs
                ):
                    continue
                group.setdefault((a, b), []).append(key)

    candidates = sorted(
        (
            (pair, funcs) for pair, funcs in group.items()
            if len(funcs) >= min_group
        ),
        key=lambda item: (-len(item[1]), item[0]),
    )[:_MAX_ORDER_PAIRS]

    deviations: list[OrderingDeviation] = []
    for (a, b), funcs in candidates:
        a_first: list[tuple[str, str]] = []
        b_first: list[tuple[str, str]] = []
        for key in funcs:
            firsts = firsts_by_func[key]
            ev_a, ev_b = firsts[a], firsts[b]
            if ev_a.line == ev_b.line:
                continue  # same-line composition — no order signal
            (a_first if ev_a.line < ev_b.line else b_first).append(key)
        n = len(a_first) + len(b_first)
        if n < min_group:
            continue
        if len(a_first) == len(b_first):
            continue
        majority, minority = (
            (a_first, b_first) if len(a_first) > len(b_first)
            else (b_first, a_first)
        )
        if not minority or len(majority) < n * ratio:
            continue
        first_op, second_op = (
            (a, b) if majority is a_first else (b, a)
        )

        # Flavor, from structural witnesses only.
        tested_votes = sum(
            1 for key in majority
            if firsts_by_func[key][first_op].tested
        )
        check_flavor = tested_votes * 2 >= len(majority)
        exhibits = []
        for key in majority[:3]:
            firsts = firsts_by_func[key]
            ev_f, ev_s = firsts[first_op], firsts[second_op]
            exhibits.append(PeerExhibit(
                key[0], ev_f.line,
                f"{first_op}() @L{ev_f.line} precedes "
                f"{second_op}() @L{ev_s.line} in {key[1]}",
            ))

        for key in minority:
            firsts = firsts_by_func[key]
            ev_early = firsts[second_op]   # deviant calls this first
            ev_late = firsts[first_op]
            # Data-dependency: the deviant's earlier call binds a name
            # the later call consumes — the observed order is forced.
            data_dep = bool(ev_early.lhs_names & ev_late.arg_idents)
            shared_arg = bool(ev_early.arg_idents & ev_late.arg_idents)
            if check_flavor and shared_arg:
                flavor, cwe = "toctou-shape", "CWE-367"
            elif check_flavor:
                flavor, cwe = "check-before-use", "CWE-696"
            elif first_op in acquires:
                flavor, cwe = "init-before-use", "CWE-908"
            else:
                flavor, cwe = "sequence", "CWE-696"
            deviations.append(OrderingDeviation(
                first_op=first_op,
                second_op=second_op,
                file=key[0],
                line=ev_early.line,
                enclosing_function=key[1],
                flavor=flavor,
                cwe=cwe,
                n=n,
                conforming=len(majority),
                data_dependent=data_dep,
                peer_evidence=PeerEvidence(
                    dimension=DIMENSION_ORDERING,
                    formation="same_callee_pair",
                    group_key=f"{first_op}->{second_op}",
                    n=n,
                    conforming=len(majority),
                    ratio=len(majority) / n,
                    deviant=PeerExhibit(
                        key[0], ev_early.line,
                        f"{second_op}() @L{ev_early.line} precedes "
                        f"{first_op}() @L{ev_late.line} in {key[1]}",
                    ),
                    exhibits=exhibits,
                    contract_source="majority",
                    provenance=f"ordering:{flavor}",
                ),
            ))
            if len(deviations) >= _MAX_DEVIATIONS:
                return deviations
    deviations.sort(key=lambda d: (d.file, d.line))
    return deviations
