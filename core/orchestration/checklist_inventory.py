"""Checklist-to-inventory promotion for context-map enrichment.

checklist.json is the serialized inventory: ``build_checklist``
(packages.exploitability_validation) wraps ``build_inventory`` +
``save_checklist``, so an on-disk checklist with a populated ``files``
list already carries everything the source enrichers need (file
records, function items with line ranges, per-file call graphs).
Reusing it avoids a full re-parse of the target tree.

Binary checklists (``core.inventory.binary_builder.
build_binary_checklist``) ALSO carry a populated ``files`` list; they
are safe to promote because their items carry addresses, not source
line ranges, so ``core.analysis.reachability.enclosing_function``
resolves no hosts and the source enrichers no-op on them.
"""

from __future__ import annotations

from typing import Any


def inventory_from_checklist(checklist: Any) -> dict[str, Any] | None:
    """Return ``checklist`` when it can serve as the in-memory inventory.

    Requires a dict with a non-empty ``files`` list — the shape both
    ``build_inventory`` and ``build_binary_checklist`` emit. Anything
    else (missing / empty ``files``, non-dict) returns ``None``, keeping
    the caller on its build-from-tree fallback.
    """
    if not isinstance(checklist, dict):
        return None
    files = checklist.get("files")
    if isinstance(files, list) and files:
        return checklist
    return None


__all__ = ["inventory_from_checklist"]
