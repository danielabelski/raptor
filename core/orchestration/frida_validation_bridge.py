"""Bridge frida runtime evidence into the validation pipeline.

Discovers frida evidence for a target and produces runtime_evidence
annotations that Stage B can use to floor proximity scores, and
Stage D can use as independent corroboration.

Pattern follows understand_bridge.py -- discovers output from a prior
/frida run and feeds it into the validation pipeline's data model.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from pathlib import Path

from core.logging import get_logger

log = get_logger("orchestration.frida_validation_bridge")

__all__ = [
    "PROXIMITY_FLOOR",
    "RuntimeEvidence",
    "annotate_attack_paths",
    "collect_runtime_evidence",
    "extract_step_function_name",
]

PROXIMITY_FLOOR = 6


@dataclass
class RuntimeEvidence:
    """Runtime evidence from a frida session for one attack path step."""

    function_observed: bool
    call_count: int = 0
    observed_args: list | None = None
    trace_id: str = ""


def collect_runtime_evidence(
    search_dirs: list[Path],
    target_path: str | None = None,
) -> dict[str, RuntimeEvidence]:
    """Discover frida evidence and build a function->RuntimeEvidence map.

    Searches ``search_dirs`` for frida run directories via the shared
    evidence discovery layer.  When ``target_path`` is given, only runs
    whose metadata target matches are used.

    Returns {function_name: RuntimeEvidence} for all functions frida
    observed.  Empty dict if no frida evidence found.
    """
    try:
        from packages.frida import parse_events
        from packages.frida.evidence import discover_evidence
    except ImportError:
        log.debug("packages.frida not importable; skipping frida evidence")
        return {}

    evidence_list = discover_evidence(search_dirs, target_path=target_path)
    if not evidence_list:
        return {}

    result: dict[str, RuntimeEvidence] = {}
    dropped_unattributed = 0
    dropped_callers: dict[str, int] = {}

    for ev in evidence_list:
        if not ev.has_events:
            continue
        events_path = ev.run_dir / "events.jsonl"
        trace_id = str(ev.run_dir)
        target_name = (Path(ev.target_binary).name
                       if ev.target_binary else None)

        # Per-run counters: track call_count within this run, then take
        # the max across runs (represents the hottest single run).
        run_counts: dict[str, int] = {}
        run_first_args: dict[str, list | None] = {}

        for record in parse_events(events_path):
            if not isinstance(record, dict):
                continue
            if record.get("type") != "send":
                continue
            payload = record.get("payload")
            if not isinstance(payload, dict):
                continue
            if "_meta" in payload:
                # Lifecycle / cap markers, not calls (some carry a fn
                # key for operator display).
                continue
            fn = payload.get("fn")
            if not isinstance(fn, str) or not fn:
                continue
            category = payload.get("category")
            if category in _EVIDENCE_EXCLUDED_CATEGORIES:
                # seed-harvest (ingest) exists to produce seeds and
                # emits no callsite; jni maps registration, not calls.
                continue
            if not _attributed_to_target(payload, target_name):
                dropped_unattributed += 1
                caller = payload.get("caller_module")
                if isinstance(caller, str) and caller:
                    dropped_callers[caller] = dropped_callers.get(caller, 0) + 1
                continue

            # Alias groups (IFUNC-shared implementations like
            # memcpy/memmove) credit every name: the hook cannot know
            # which name the call site used, and a finding may name
            # either. Deduplicated — a self-alias (the same fn watched
            # plain and module-scoped) must not double-count — and
            # bounded like every other payload field: the agent runs
            # inside the target process, and an unbounded list would
            # let one forged event mint evidence for thousands of
            # names.
            names = [fn]
            aliases = payload.get("aliases")
            if isinstance(aliases, list):
                names.extend(
                    a for a in aliases[:_MAX_ALIASES]
                    if isinstance(a, str)
                    and 0 < len(a) <= _MAX_OBSERVED_ARG_STR)
            names = list(dict.fromkeys(names))

            args = payload.get("args")
            for name in names:
                run_counts[name] = run_counts.get(name, 0) + 1
                if run_first_args.get(name) is None:
                    run_first_args[name] = _sanitize_observed_args(args)

        for fn, count in run_counts.items():
            if fn in result:
                existing = result[fn]
                new_args = existing.observed_args
                if new_args is None:
                    new_args = run_first_args.get(fn)
                # trace_id follows the run that produced the reported
                # (max) count — a record must never cite a run that did
                # not show its own numbers.
                if count > existing.call_count:
                    new_count, new_trace = count, trace_id
                else:
                    new_count, new_trace = existing.call_count, existing.trace_id
                result[fn] = RuntimeEvidence(
                    function_observed=True,
                    call_count=new_count,
                    observed_args=new_args,
                    trace_id=new_trace,
                )
            else:
                result[fn] = RuntimeEvidence(
                    function_observed=True,
                    call_count=count,
                    observed_args=run_first_args.get(fn),
                    trace_id=trace_id,
                )

    log.info("collected runtime evidence: %d functions from %d runs",
             len(result), len(evidence_list))
    if dropped_unattributed:
        top = sorted(dropped_callers.items(), key=lambda kv: -kv[1])[:3]
        detail = ", ".join(f"{m}×{n}" for m, n in top) or "<none recorded>"
        if result:
            # A handful of pre-main libc startup calls drop on every
            # healthy spawn run — routine, not actionable.
            log.debug(
                "%d sink-family event(s) failed target attribution "
                "(top caller modules: %s)",
                dropped_unattributed, detail)
        else:
            # Never let attribution loss look like "no sink calls
            # occurred": name the dropped callers so the operator can
            # see the evidence exists but could not be tied to the
            # target.
            log.warning(
                "%d sink-family event(s) failed target attribution and "
                "NO evidence was collected (top caller modules: %s) — "
                "evidence requires the target binary on the call stack; "
                "spawn a binary target, and note calls made entirely "
                "inside shipped libraries without the main binary on "
                "the stack cannot be attributed",
                dropped_unattributed, detail)
    return result


def annotate_attack_paths(
    attack_paths: list[dict],
    evidence_map: dict[str, RuntimeEvidence],
) -> list[dict]:
    """Annotate attack paths with runtime_evidence from frida.

    For each attack path step whose function appears in the evidence
    map, adds a ``runtime_evidence`` dict to the step.  If any step
    has runtime evidence, floors the path's proximity at
    ``PROXIMITY_FLOOR`` (precedent: SMT feasible:true floor in
    Stage B).

    Returns a deep copy of attack_paths with annotations.  The
    original list is never mutated.
    """
    if not evidence_map:
        return attack_paths

    result = copy.deepcopy(attack_paths)

    for path in result:
        if not isinstance(path, dict):
            continue

        has_evidence = False
        first_trace_id = None

        steps = path.get("steps")
        if not isinstance(steps, list):
            continue

        for step in steps:
            if not isinstance(step, dict):
                continue

            fn_name = _extract_function_name(step)
            if not fn_name:
                continue

            ev = evidence_map.get(fn_name)
            if ev is None:
                continue

            has_evidence = True
            if first_trace_id is None:
                first_trace_id = ev.trace_id
            step["runtime_evidence"] = {
                "function_observed": ev.function_observed,
                "call_count": ev.call_count,
                "observed_args": ev.observed_args,
                "trace_id": ev.trace_id,
            }

        if has_evidence:
            path["runtime_evidence_available"] = True
            if first_trace_id:
                path["frida_trace_id"] = first_trace_id
            current_proximity = path.get("proximity")
            if isinstance(current_proximity, (int, float)):
                if current_proximity < PROXIMITY_FLOOR:
                    path["proximity"] = PROXIMITY_FLOOR
            else:
                path["proximity"] = PROXIMITY_FLOOR

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


# Event categories that require target attribution before they count
# as runtime evidence. These are the sink/exec/loader hook families:
# their function names (memcpy, system, dlopen, ...) fire constantly
# from library internals — an IDLE process calls memcpy — so an
# unattributed observation says nothing about a finding's call path,
# yet annotate_attack_paths floors path proximity on a bare name
# match. Legacy categories (file/network/parser/process) keep their
# original semantics.
_TARGET_ATTRIBUTED_CATEGORIES = frozenset({"sink", "exec", "load"})

# Categories that never count as call evidence: seed-harvest's ingest
# events exist to produce seeds (no callsite is captured, so they can
# never attribute), and jni events map RegisterNatives registrations,
# not calls to a finding's function.
_EVIDENCE_EXCLUDED_CATEGORIES = frozenset({"ingest", "jni"})

# Observed-args bounds: a template may embed captured payload bytes in
# its args (an execve argv is 30+ target-controlled strings; custom
# scripts may nest data_hex); none of that may ride into
# attack-paths.json and LLM prompts.
_MAX_OBSERVED_ARGS = 8
_MAX_OBSERVED_ARG_STR = 128
_MAX_OBSERVED_DEPTH = 2
_MAX_ATTRIBUTION_FRAMES = 16
# An IFUNC alias group has 2-3 members in practice; anything larger is
# a forged event.
_MAX_ALIASES = 8


def _attributed_to_target(payload: dict, target_name: str | None) -> bool:
    """True when this event may count as runtime evidence.

    The target's code must appear at the call site OR anywhere on the
    captured backtrace: real projects ship the vulnerable code in
    their own libraries and call sinks through wrappers, so requiring
    the immediate caller alone would silently drop that evidence.
    """
    if payload.get("category") not in _TARGET_ATTRIBUTED_CATEGORIES:
        return True
    if not target_name:
        # Attach-by-name run: no binary to attribute against —
        # conservative (evidence promotes, so dropping is safe).
        return False
    caller = payload.get("caller_module")
    if isinstance(caller, str) and caller == target_name:
        return True
    frames = payload.get("backtrace_frames")
    if isinstance(frames, list):
        for frame in frames[:_MAX_ATTRIBUTION_FRAMES]:
            if (isinstance(frame, dict)
                    and frame.get("module") == target_name):
                return True
    return False


def _bound_value(value: object, depth: int = 0) -> object:
    """Recursively bound one observed-args value."""
    if isinstance(value, str):
        if len(value) > _MAX_OBSERVED_ARG_STR:
            return value[:_MAX_OBSERVED_ARG_STR] + "…"
        return value
    if isinstance(value, list):
        if depth >= _MAX_OBSERVED_DEPTH:
            return "…"
        return [_bound_value(v, depth + 1)
                for v in value[:_MAX_OBSERVED_ARGS]]
    if isinstance(value, dict):
        if depth >= _MAX_OBSERVED_DEPTH:
            return "…"
        return {k: _bound_value(v, depth + 1)
                for k, v in list(value.items())[:_MAX_OBSERVED_ARGS]
                if k != "data_hex"}
    return value


def _sanitize_observed_args(args: object) -> list | None:
    """Bound the args sample stored in RuntimeEvidence.observed_args."""
    if isinstance(args, dict):
        values = [v for k, v in args.items() if k != "data_hex"]
    elif isinstance(args, list):
        values = list(args)
    else:
        return None
    return [_bound_value(v) for v in values[:_MAX_OBSERVED_ARGS]]


_ACTION_FN_RE = re.compile(r'\b([a-zA-Z_]\w*)\s*\(')
_KEYWORDS = frozenset({
    "if", "for", "while", "switch", "catch", "return", "sizeof", "typeof",
    "alignof", "decltype", "throw", "new", "delete",
})


def _extract_function_name(step: dict) -> str | None:
    """Extract a function name from an attack path step.

    Steps use varying formats: some have a ``function`` or ``name``
    key, others have ``action`` strings like ``"call strcpy(buf, in)"``.
    For action strings we take the LAST function-call pattern since
    earlier tokens are typically callers, not the vulnerable callee.
    """
    for key in ("function", "name"):
        val = step.get(key)
        if isinstance(val, str) and val:
            return _strip_parens(val)

    action = step.get("action")
    if isinstance(action, str) and action:
        last_match = None
        for m in _ACTION_FN_RE.finditer(action):
            candidate = m.group(1)
            if candidate not in _KEYWORDS:
                last_match = candidate
        if last_match:
            return last_match

    return None


# Public name: packages.frida.sink_watch derives watch lists from
# attack-path steps with the same extraction rules Stage B uses, so
# the two surfaces cannot drift.
def extract_step_function_name(step: dict) -> str | None:
    """Extract a function name from an attack path step (public form
    of :func:`_extract_function_name`)."""
    return _extract_function_name(step)


def _strip_parens(name: str) -> str:
    """Remove trailing parentheses from a function name."""
    name = name.strip()
    if name.endswith("()"):
        return name[:-2]
    idx = name.find("(")
    if idx > 0:
        return name[:idx].strip()
    return name
