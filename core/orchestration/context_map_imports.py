"""Mechanically extract imports from checklist.json call_graph data.

Enriches context-map.json with an ``imports`` key derived from the
per-file ``call_graph.imports`` dict (absolute) and
``call_graph.relative_imports`` list (Python ``from .x import y``),
both produced by the inventory parser (ast for Python, tree-sitter
for other languages).  Ground-truth module names — no LLM enumeration.
"""
from __future__ import annotations

from typing import Any


def _resolve_relative_import(
    file_path: str, level: int, module: str, name: str,
) -> str | None:
    """Resolve a Python relative import to a qualified module name.

    Uses the file's directory components as the package hierarchy.
    Mirrors the resolution in ``core.analysis.reachability`` (including
    the ``src/`` strip heuristic) but produces a single best-effort
    qualified name rather than candidate-expanding.

    Returns None when resolution fails (level exceeds directory depth).
    """
    # Directory parts = package hierarchy.
    if "/" in file_path:
        dir_parts = file_path.rsplit("/", 1)[0].split("/")
    else:
        dir_parts = []

    # src/ strip: if the path starts with src/, the package root is
    # likely one level in.  Use the stripped form when it's deeper;
    # keeps resolved names matching how Python actually sees the package.
    if len(dir_parts) > 1 and dir_parts[0] == "src":
        dir_parts = dir_parts[1:]

    # level=1 → current package, level=2 → parent, etc.
    ascend = level - 1
    if ascend < 0:
        return None
    if ascend > len(dir_parts):
        return None

    base = dir_parts[:len(dir_parts) - ascend] if ascend else dir_parts

    components = list(base)
    if module:
        components.extend(module.split("."))
    components.append(name)
    return ".".join(components)


def extract_imports_from_checklist(
    checklist: dict[str, Any],
) -> list[dict[str, str]]:
    """Return ``[{module, file}]`` from checklist call_graph imports.

    Processes both absolute imports (``call_graph.imports``) and
    Python relative imports (``call_graph.relative_imports``).
    Deduplicates per (file, module) pair.  Returns sorted by file
    then module for stable output.
    """
    seen: set[tuple[str, str]] = set()
    result: list[dict[str, str]] = []

    def _add(file_path: str, module: str) -> None:
        key = (file_path, module)
        if key not in seen:
            seen.add(key)
            result.append({"module": module, "file": file_path})

    for file_entry in checklist.get("files") or []:
        if file_entry.get("_excluded"):
            continue
        file_path = file_entry.get("path") or ""
        if not file_path:
            continue
        cg = file_entry.get("call_graph")
        if not isinstance(cg, dict):
            continue

        # Absolute imports: {binding: qualified_module}
        abs_imports = cg.get("imports")
        if isinstance(abs_imports, dict):
            for _binding, module in abs_imports.items():
                if module:
                    _add(file_path, module)

        # Relative imports (Python only): [[level, module, name, asname]]
        rel_imports = cg.get("relative_imports")
        if isinstance(rel_imports, list):
            for ri in rel_imports:
                if not isinstance(ri, (list, tuple)) or len(ri) < 3:
                    continue
                try:
                    level = int(ri[0])
                except (TypeError, ValueError):
                    continue
                module = str(ri[1] or "")
                name = str(ri[2] or "")
                if level <= 0 or not name:
                    continue
                resolved = _resolve_relative_import(
                    file_path, level, module, name,
                )
                if resolved:
                    _add(file_path, resolved)

    result.sort(key=lambda x: (x["file"], x["module"]))
    return result


def enrich_context_map_imports(
    context_map: dict[str, Any],
    checklist: dict[str, Any],
) -> int:
    """Merge mechanical imports into context_map.  Returns count added."""
    imports = extract_imports_from_checklist(checklist)
    if not imports:
        return 0
    context_map["imports"] = imports
    return len(imports)
