"""Apply Ghidra diff priority to a checklist.

When a version-diff.json exists (from a prior ``/ghidra diff`` run),
marks changed and added functions as ``priority=high`` in the
checklist so they are analysed first by ``/agentic`` or ``/audit``.

The diff is found by scanning the project's output dirs for
``version-diff.json``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional, Set

logger = logging.getLogger(__name__)


def _find_version_diff(target_path: Path) -> Optional[Path]:
    """Find the most recent version-diff.json for the target."""
    try:
        from core.project.project import ProjectManager
        mgr = ProjectManager()
        project = mgr.find_project_for_target(str(target_path))
        if project is None:
            return None
        for run_dir in project.get_run_dirs():
            candidate = run_dir / "version-diff.json"
            if candidate.is_file():
                return candidate
    except Exception:  # noqa: BLE001
        pass

    for candidate in Path("out").glob("ghidra-diff-*/version-diff.json"):
        if candidate.is_file():
            return candidate

    return None


def _load_changed_names(diff_path: Path) -> Set[str]:
    """Load changed/added function names from a version-diff.json."""
    with open(diff_path) as f:
        data = json.load(f)

    names = set()
    for entry in data.get("added", []):
        name = entry.get("name", "")
        if name:
            names.add(name)
    for entry in data.get("changed", []):
        name = entry.get("name", "")
        if name:
            names.add(name)

    return names


def apply_diff_priority(
    target_path: Path,
    checklist_path: Path,
) -> int:
    """Boost changed functions in a checklist.

    Returns the number of functions boosted.
    """
    diff_path = _find_version_diff(target_path)
    if diff_path is None:
        return 0

    changed_names = _load_changed_names(diff_path)
    if not changed_names:
        return 0

    with open(checklist_path) as f:
        checklist = json.load(f)

    items = []
    for file_entry in checklist.get("files", []):
        items.extend(file_entry.get("items", []))
    boosted = 0
    for item in items:
        func_name = item.get("function", item.get("name", ""))
        if func_name in changed_names:
            existing = item.get("priority", "")
            if existing != "high":
                item["priority"] = "high"
                item["priority_reason"] = (
                    item.get("priority_reason", "")
                    + " [ghidra-diff: changed between versions]"
                ).strip()
                boosted += 1

    if boosted > 0:
        with open(checklist_path, "w") as f:
            json.dump(checklist, f, indent=2)
        logger.info(
            "diff priority: boosted %d functions from %s",
            boosted, diff_path.name,
        )

    return boosted
