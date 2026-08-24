"""Parse Ghidra export JSON into an REDatabase."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict

from .model import (
    REComment,
    REDatabase,
    REFunction,
    RESegment,
    REType,
    REXref,
)

logger = logging.getLogger(__name__)


def parse_export(path: Path) -> REDatabase:
    """Parse a Ghidra export JSON file into an REDatabase.

    Args:
        path: Path to the JSON file produced by the export script (ExportRaptor.java).

    Returns:
        An REDatabase populated with the Ghidra project data.

    Raises:
        ValueError: If the JSON is malformed or missing required fields.
    """
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        raise ValueError(f"failed to read Ghidra export: {e}") from e

    if not isinstance(data, dict):
        raise ValueError("Ghidra export must be a JSON object")

    return parse_dict(data)


def parse_dict(data: Dict[str, Any]) -> REDatabase:
    """Parse a Ghidra export dict into an REDatabase.

    Separated from :func:`parse_export` so tests can pass dicts
    directly without writing JSON files.
    """
    functions = [
        _parse_function(f) for f in data.get("functions", [])
    ]

    xrefs = [
        REXref.from_dict(x) for x in data.get("xrefs", [])
    ]

    types = [
        REType.from_dict(t) for t in data.get("types", [])
    ]

    comments = [
        REComment.from_dict(c) for c in data.get("comments", [])
    ]

    segments = [
        RESegment.from_dict(s) for s in data.get("segments", [])
    ]

    return REDatabase(
        source_tool=str(data.get("source_tool", "ghidra")),
        binary_path=data.get("binary_path"),
        architecture=str(data.get("architecture", "")),
        functions=functions,
        xrefs=xrefs,
        types=types,
        comments=comments,
        segments=segments,
        imports=data.get("imports", []),
        exports=data.get("exports", []),
        strings=data.get("strings", []),
        bookmarks=data.get("bookmarks", []),
        metadata=data.get("metadata", {}),
    )


def _parse_function(d: Dict[str, Any]) -> REFunction:
    """Parse a function dict with Ghidra-specific auto-name detection."""
    name = str(d.get("name", ""))
    is_auto = bool(d.get("is_auto_named", False))

    # Belt-and-braces: detect auto-naming patterns the export script
    # might not have flagged (e.g. older Ghidra versions).
    if not is_auto and _looks_auto_named(name):
        is_auto = True

    return REFunction(
        name=name,
        address=int(d.get("address", 0)),
        size=int(d.get("size", 0)),
        signature=d.get("signature"),
        calling_convention=d.get("calling_convention"),
        is_auto_named=is_auto,
        is_thunk=bool(d.get("is_thunk", False)),
        is_external=bool(d.get("is_external", False)),
        decompilation=d.get("decompilation"),
        source_tool=str(d.get("source_tool", "ghidra")),
    )


def _looks_auto_named(name: str) -> bool:
    """Heuristic: does this function name look auto-generated?

    Ghidra uses ``FUN_XXXXXXXX`` for auto-analysed functions.
    r2 uses ``fcn.XXXXXXXX``.  IDA uses ``sub_XXXXXXXX``.
    """
    if not name:
        return True
    prefixes = ("FUN_", "fcn.", "sub_", "thunk_FUN_", "Ordinal_")
    return name.startswith(prefixes)
