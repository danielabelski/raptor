"""Ghidra REDatabase context injection for LLM analysis prompts.

Two-phase pattern (mirrors source_intel_inject.py):

1. :func:`prepare_ghidra_context` — called once per run to load
   REDatabases from the project's ghidra_projects list.  Prefers
   cached ``re-database.json`` from a prior ``/ghidra import``; falls
   back to live PyGhidra import when no cache exists.

2. :func:`ghidra_blocks_for_finding` — called per-finding to produce
   :class:`UntrustedBlock` entries with decompilation, type info, and
   cross-references for the finding's function.

Caching: process-global dict keyed by absolute resolved repo path.
One entry per target — multiple findings in one repo share the
loaded REDatabases.
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.security.prompt_envelope import UntrustedBlock

from .model import REDatabase, REFunction

logger = logging.getLogger(__name__)

_GHIDRA_CACHE: Dict[str, List[REDatabase]] = {}
_GHIDRA_FUNC_INDEX: Dict[str, Dict[str, List[REFunction]]] = {}
_GHIDRA_LOCK = threading.RLock()


def _load_cached_redb(gpr_path: Path) -> Optional[REDatabase]:
    """Try to load re-database.json from a prior /ghidra import or attach."""
    from .roundtrip import redb_cache_candidates

    for candidate in redb_cache_candidates(gpr_path):
        if candidate.is_file():
            try:
                with open(candidate) as f:
                    data = json.load(f)
                db = REDatabase.from_dict(data)
                logger.debug(
                    "loaded cached REDatabase from %s (%d functions)",
                    candidate, len(db.functions),
                )
                return db
            except Exception as e:  # noqa: BLE001
                logger.debug("failed to load %s: %s", candidate, e)
    return None


def _live_import(gpr_path: Path) -> Optional[REDatabase]:
    """Import a .gpr via PyGhidra (starts JVM if needed)."""
    try:
        from .bridge import GhidraBridge
    except ImportError:
        logger.debug("packages.ghidra.bridge not importable; skipping")
        return None
    import tempfile
    try:
        with tempfile.TemporaryDirectory(prefix="raptor-ghidra-ctx-") as td:
            bridge = GhidraBridge(gpr_path)
            db = bridge.import_project(Path(td))
            bridge.close()
            logger.info(
                "live-imported Ghidra project %s (%d functions)",
                gpr_path.name, len(db.functions),
            )
            return db
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "live import of %s failed: %s; skipping", gpr_path.name, e,
        )
        return None


def _build_func_index(
    databases: List[REDatabase],
) -> Dict[str, List[REFunction]]:
    """Build a name→function lookup index across all databases."""
    index: Dict[str, List[REFunction]] = {}
    for db in databases:
        for func in db.functions:
            if func.is_auto_named or func.is_thunk or func.is_external:
                continue
            index.setdefault(func.name, []).append(func)
    return index


def _resolve_ghidra_projects(repo_path: Path) -> List[str]:
    """Auto-resolve the project-persisted .gpr list for *repo_path*.

    DEFERRED: project-persisted Ghidra bindings follow the
    projects-schema rework (attach follow-up). Until then callers
    pass ``ghidra_projects`` explicitly; this resolver honestly
    returns an empty list.
    """
    del repo_path
    return []

def prepare_ghidra_context(
    repo_path: Path,
    ghidra_projects: Optional[List[str]] = None,
) -> None:
    """Pre-seed the Ghidra REDatabase cache for a run.

    When *ghidra_projects* is None, auto-resolves from the active
    project's ``ghidra_projects`` list. Loads each .gpr from cached
    JSON or live import. Builds a function-name index for fast
    per-finding lookup.

    Best-effort: individual project failures are logged and skipped.
    """
    if ghidra_projects is None:
        ghidra_projects = _resolve_ghidra_projects(repo_path)
    if not ghidra_projects:
        return

    try:
        key = str(repo_path.resolve())
    except (OSError, ValueError):
        logger.debug(
            "prepare_ghidra_context: unresolvable repo_path %s; skipping",
            repo_path,
        )
        return

    with _GHIDRA_LOCK:
        if key in _GHIDRA_CACHE:
            return

    databases: List[REDatabase] = []
    for gpr_str in ghidra_projects:
        gpr_path = Path(gpr_str)
        if not gpr_path.exists():
            logger.warning("ghidra project not found: %s", gpr_path)
            continue

        db = _load_cached_redb(gpr_path)
        if db is None:
            db = _live_import(gpr_path)
        if db is not None:
            databases.append(db)

    if not databases:
        logger.info(
            "prepare_ghidra_context: no databases loaded from %d projects",
            len(ghidra_projects),
        )
        with _GHIDRA_LOCK:
            _GHIDRA_CACHE[key] = []
            _GHIDRA_FUNC_INDEX[key] = {}
        return

    func_index = _build_func_index(databases)
    total_funcs = sum(len(db.functions) for db in databases)
    named_funcs = sum(
        1 for db in databases
        for f in db.functions
        if not f.is_auto_named
    )

    with _GHIDRA_LOCK:
        _GHIDRA_CACHE[key] = databases
        _GHIDRA_FUNC_INDEX[key] = func_index

    logger.info(
        "prepare_ghidra_context: %d database(s), %d functions "
        "(%d named, %d indexed)",
        len(databases), total_funcs, named_funcs, len(func_index),
    )


def ghidra_blocks_for_finding(
    finding: Dict[str, Any],
) -> Tuple[UntrustedBlock, ...]:
    """Build Ghidra context UntrustedBlocks for one finding.

    Returns () when any of:
    - no repo_path on the finding
    - cache miss (prepare_ghidra_context wasn't called)
    - no function match in the REDatabase
    - matched function has no useful context to inject

    Otherwise returns a 1-tuple with decompilation, types, and xrefs.
    """
    repo_raw = finding.get("repo_path")
    if not repo_raw:
        return ()
    try:
        key = str(Path(repo_raw).resolve())
    except (OSError, ValueError):
        return ()

    with _GHIDRA_LOCK:
        func_index = _GHIDRA_FUNC_INDEX.get(key)
        databases = _GHIDRA_CACHE.get(key)

    if not func_index or not databases:
        return ()

    function_name = (
        (finding.get("metadata") or {}).get("name")
        or finding.get("function")
        or finding.get("function_name")
        or ""
    )
    if not function_name:
        return ()

    matches = func_index.get(function_name)
    if not matches:
        return ()

    matched = matches[0]
    owning_db = _find_owning_db(databases, matched)

    parts = _render_function_context(matched, owning_db)
    if not parts:
        return ()

    content = "\n\n".join(parts)
    origin = "ghidra:%s:%s" % (
        owning_db.binary_path or "unknown",
        matched.name,
    )

    logger.debug(
        "ghidra context injected for finding function=%s "
        "(%d context sections)",
        function_name, len(parts),
    )

    return (
        UntrustedBlock(
            content=content,
            kind="ghidra-context",
            origin=origin,
        ),
    )


def _find_owning_db(
    databases: List[REDatabase], func: REFunction,
) -> REDatabase:
    """Find which database owns a function (by address match)."""
    for db in databases:
        if db.function_by_address(func.address) is func:
            return db
        for f in db.functions:
            if f is func:
                return db
    return databases[0]


def _render_function_context(
    func: REFunction,
    db: REDatabase,
) -> List[str]:
    """Render all available context for a function."""
    parts: List[str] = []

    if func.decompilation:
        parts.append(
            "## Ghidra Decompilation: %s\n\n```c\n%s\n```"
            % (func.name, func.decompilation)
        )

    if func.signature:
        parts.append("## Function Signature\n\n`%s`" % func.signature)

    callers = [
        x for x in db.xrefs
        if x.to_addr == func.address and x.kind == "call"
    ]
    callees = []
    for x in db.xrefs:
        if x.kind != "call":
            continue
        owner = db.function_containing_address(x.from_addr)
        if owner is not None and owner.address == func.address:
            callees.append(x)

    if callers or callees:
        xref_lines = []
        if callers:
            caller_names = [
                _resolve_name(db, x.from_addr) for x in callers[:15]
            ]
            xref_lines.append("Called by: " + ", ".join(caller_names))
        if callees:
            callee_names = [
                _resolve_name(db, x.to_addr) for x in callees[:15]
            ]
            xref_lines.append("Calls: " + ", ".join(callee_names))
        parts.append("## Cross-References\n\n" + "\n".join(xref_lines))

    related_types = _find_related_types(func, db)
    if related_types:
        type_lines = []
        for t in related_types[:5]:
            header = "%s %s" % (t.kind, t.name)
            if t.size is not None:
                header += " (size: %d)" % t.size
            if t.fields:
                field_strs = []
                for fld in t.fields:
                    offset = fld.get("offset")
                    fname = fld.get("name", "?")
                    ftype = fld.get("type", "?")
                    fsize = fld.get("size")
                    if isinstance(offset, int):
                        s = "  offset 0x%x: %s %s" % (offset, ftype, fname)
                    else:
                        s = "  %s %s" % (ftype, fname)
                    if fsize:
                        s += " (%d bytes)" % fsize
                    field_strs.append(s)
                header += "\n" + "\n".join(field_strs)
            type_lines.append(header)
        parts.append(
            "## Related Types\n\n```\n" + "\n\n".join(type_lines) + "\n```"
        )

    comments = [
        c for c in db.comments
        if c.function == func.name
    ]
    if comments:
        comment_lines = [
            "[%s] %s" % (c.kind, c.text) for c in comments[:10]
        ]
        parts.append(
            "## Ghidra project comments (untrusted)\n\n" + "\n".join(comment_lines)
        )

    return parts


def _resolve_name(db: REDatabase, addr: int) -> str:
    """Resolve an instruction address to its containing function's name."""
    func = db.function_containing_address(addr)
    if func is not None:
        return func.name
    return "sub_%x" % addr


def _find_related_types(func: REFunction, db: REDatabase) -> list:
    """Find types referenced in a function's signature or decompilation."""
    if not db.types:
        return []
    text = (func.signature or "") + " " + (func.decompilation or "")
    words = set(text.replace("*", " ").replace("(", " ").replace(")", " ")
                .replace(",", " ").replace(";", " ").split())
    return [t for t in db.types if t.name in words]


def clear_ghidra_cache() -> None:
    """Drop every cached REDatabase."""
    with _GHIDRA_LOCK:
        _GHIDRA_CACHE.clear()
        _GHIDRA_FUNC_INDEX.clear()
