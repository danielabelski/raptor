"""Finding-parameterized sink watching.

Renders the ``sink-watch`` template against a specific sink list so a
runtime session watches exactly the functions a finding implicates,
instead of a generic vocabulary. The list comes from either an
operator-written sinks JSON or — mechanically — from a validation
run's ``attack-paths.json``: hand the CLI the finding artifact and the
hooks derive from it, no prompting involved.

Accepted ``--sink-watch`` file shapes:

* ``["memcpy", "system"]`` — bare function names
* ``[{"fn": "EVP_DecryptUpdate", "module": "libcrypto.so.3"}, ...]`` —
  optionally module-scoped (``function`` accepted as an alias of
  ``fn``)
* an ``attack-paths.json`` (a list of path dicts with ``steps``, or a
  ``{"paths": [...]}`` wrapper) — every step function becomes a watch
  candidate, resolved at runtime via export tables with a DebugSymbol
  fallback for project-internal functions

Events land in ``events.jsonl`` with ``category=sink`` and the sink
name in ``fn`` — the exact shape
``core.orchestration.frida_validation_bridge`` counts, so a sink-watch
run feeds ``runtime_evidence`` (observed args included) into
``/validate`` with no extra wiring.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .runner import TEMPLATES_DIR

logger = logging.getLogger(__name__)

__all__ = ["SinkSpec", "render_sink_watch", "specs_from_file"]

_SLOT = "/*__SINK_WATCH__*/ []"

# C-symbol shape, plus $ and . for compiler-mangled locals and : for
# demangled C++ qualification (ns::Class::method — DebugSymbol.fromName
# resolves demangled names on symbol-bearing targets). The rendered
# names land inside a JS script — json.dumps escapes them, but a name
# that fails this pattern is garbage input, not a sink.
_NAME_RE = re.compile(r"^[A-Za-z_$][\w$.@:]*$")
_MODULE_RE = re.compile(r"^[\w.+-]+$")

# Watching every function of a large attack-paths file would turn the
# session into a firehose; cap and say so.
_MAX_SPECS = 64


@dataclass(frozen=True)
class SinkSpec:
    """One sink to watch: a function name, optionally module-scoped."""

    fn: str
    module: str | None = None


def render_sink_watch(specs: Sequence[SinkSpec]) -> str:
    """Render the sink-watch template against *specs*.

    Raises ValueError on an empty list or a spec that does not look
    like a symbol/module name.
    """
    if not specs:
        msg = "no sinks to watch"
        raise ValueError(msg)
    if len(specs) > _MAX_SPECS:
        msg = f"too many sinks ({len(specs)}); cap is {_MAX_SPECS}"
        raise ValueError(msg)
    payload = []
    for spec in specs:
        if not _NAME_RE.match(spec.fn):
            msg = f"not a plausible sink symbol: {spec.fn!r}"
            raise ValueError(msg)
        entry: dict[str, str] = {"fn": spec.fn}
        if spec.module:
            if not _MODULE_RE.match(spec.module):
                msg = f"not a plausible module name: {spec.module!r}"
                raise ValueError(msg)
            entry["module"] = spec.module
        payload.append(entry)

    template = (TEMPLATES_DIR / "sink-watch.js").read_text(encoding="utf-8")
    if _SLOT not in template:
        msg = "sink-watch template is missing its config slot"
        raise RuntimeError(msg)
    return template.replace(_SLOT, json.dumps(payload))


def specs_from_file(path: Path | str) -> list[SinkSpec]:
    """Parse a ``--sink-watch`` file into sink specs.

    Auto-detects the attack-paths shape; anything else is treated as a
    sinks list. Raises ValueError when nothing usable is found.
    """
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(data, dict) and isinstance(data.get("paths"), list):
        specs = _specs_from_attack_paths(data["paths"])
    elif isinstance(data, list):
        # Attack-paths files are LLM-written; a single degenerate
        # steps-less entry must not reclassify the whole file. Route
        # each item by its own shape - and only a NON-EMPTY steps list
        # makes an item a path entry, so `{"steps": [], "fn": "..."}`
        # still contributes its usable fn.
        def _is_path_item(item: object) -> bool:
            return (isinstance(item, dict)
                    and isinstance(item.get("steps"), list)
                    and bool(item["steps"]))

        path_items = [i for i in data if _is_path_item(i)]
        other_items = [i for i in data if not _is_path_item(i)]
        specs = _specs_from_attack_paths(path_items) if path_items else []
        for spec in _specs_from_sink_list(other_items):
            if spec not in specs:
                specs.append(spec)
        if len(specs) > _MAX_SPECS:
            logger.warning(
                "sink-watch: %d sinks derived; watching the first %d "
                "(pass a hand-written sinks list to choose)",
                len(specs), _MAX_SPECS,
            )
            specs = specs[:_MAX_SPECS]
    else:
        msg = (f"unrecognised sinks file shape in {path}: expected a list "
               "of sink names/objects or an attack-paths.json")
        raise ValueError(msg)

    if not specs:
        msg = (f"no usable sink entries in {path} (step names that fail "
               "symbol validation are logged and dropped)")
        raise ValueError(msg)
    return specs


def _specs_from_sink_list(data: list) -> list[SinkSpec]:
    specs: list[SinkSpec] = []
    seen: set[SinkSpec] = set()
    for item in data:
        spec: SinkSpec | None = None
        if isinstance(item, str) and item:
            spec = SinkSpec(fn=item)
        elif isinstance(item, dict):
            fn = item.get("fn") or item.get("function")
            if isinstance(fn, str) and fn:
                module = item.get("module")
                spec = SinkSpec(
                    fn=fn,
                    module=module if isinstance(module, str) and module
                    else None,
                )
        if spec is not None and spec not in seen:
            seen.add(spec)
            specs.append(spec)
    return specs


def _specs_from_attack_paths(paths: list) -> list[SinkSpec]:
    from core.orchestration.frida_validation_bridge import (
        extract_step_function_name,
    )

    names: list[str] = []
    dropped: list[str] = []
    for attack_path in paths:
        if not isinstance(attack_path, dict):
            continue
        steps = attack_path.get("steps")
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            name = extract_step_function_name(step)
            if not name:
                continue
            if not _NAME_RE.match(name):
                dropped.append(name)
                continue
            if name not in names:
                names.append(name)
    if dropped:
        uniq = sorted(set(dropped))
        logger.warning(
            "sink-watch: %d step function name(s) failed symbol "
            "validation and were dropped: %s%s",
            len(uniq), ", ".join(uniq[:8]),
            ", ..." if len(uniq) > 8 else "",
        )
    if len(names) > _MAX_SPECS:
        logger.warning(
            "attack paths name %d distinct functions; watching the first "
            "%d (pass a hand-written sinks list to choose)",
            len(names), _MAX_SPECS,
        )
        names = names[:_MAX_SPECS]
    return [SinkSpec(fn=n) for n in names]
