"""Cross-version comparison of Ghidra RE databases.

Given two REDatabase instances (typically from different firmware or
binary versions), produces a structured diff showing added, removed,
and changed functions — plus annotation/comment deltas.

Primary matching is by function name. Address-based matching is
unreliable across compilation versions since addresses shift.

Usage::

    from packages.ghidra.diff import diff_databases

    diff = diff_databases(db_old, db_new)
    print(diff.summary())
    diff.write_json(output_dir / "version-diff.json")
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .model import REDatabase, REFunction

logger = logging.getLogger(__name__)


@dataclass
class FunctionChange:
    """A single function that changed between versions."""

    name: str
    address_old: int
    address_new: int
    size_old: int
    size_new: int
    signature_old: Optional[str] = None
    signature_new: Optional[str] = None
    calling_convention_old: Optional[str] = None
    calling_convention_new: Optional[str] = None
    decompilation_changed: bool = False

    @property
    def size_delta(self) -> int:
        return self.size_new - self.size_old

    @property
    def address_shifted(self) -> bool:
        return self.address_old != self.address_new

    @property
    def signature_changed(self) -> bool:
        return self.signature_old != self.signature_new

    @property
    def calling_convention_changed(self) -> bool:
        return self.calling_convention_old != self.calling_convention_new

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "address_old": self.address_old,
            "address_new": self.address_new,
            "size_old": self.size_old,
            "size_new": self.size_new,
            "size_delta": self.size_delta,
        }
        if self.signature_changed:
            d["signature_old"] = self.signature_old
            d["signature_new"] = self.signature_new
        if self.calling_convention_changed:
            d["calling_convention_old"] = self.calling_convention_old
            d["calling_convention_new"] = self.calling_convention_new
        if self.address_shifted:
            d["address_shifted"] = True
        if self.decompilation_changed:
            d["decompilation_changed"] = True
        return d


@dataclass
class CommentDelta:
    """A comment that was added, removed, or changed."""

    function: Optional[str]
    address: int
    kind: str
    action: str  # "added", "removed", "changed"
    text_old: Optional[str] = None
    text_new: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "address": self.address,
            "kind": self.kind,
            "action": self.action,
        }
        if self.function:
            d["function"] = self.function
        if self.text_old is not None:
            d["text_old"] = self.text_old
        if self.text_new is not None:
            d["text_new"] = self.text_new
        return d


@dataclass
class REDiff:
    """Structured diff between two REDatabase instances."""

    label_old: str
    label_new: str
    added: List[REFunction] = field(default_factory=list)
    removed: List[REFunction] = field(default_factory=list)
    changed: List[FunctionChange] = field(default_factory=list)
    comment_deltas: List[CommentDelta] = field(default_factory=list)
    import_deltas: Dict[str, List[str]] = field(default_factory=dict)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed
                     or self.comment_deltas)

    def summary(self) -> str:
        """Human-readable summary of the diff."""
        lines = [f"{self.label_old} -> {self.label_new}", ""]

        if self.added:
            lines.append(f"Added ({len(self.added)} functions):")
            for f in self.added[:20]:
                lines.append(
                    f"  {f.name}  {f.address:#x}  size={f.size}"
                )
            if len(self.added) > 20:
                lines.append(f"  ... and {len(self.added) - 20} more")
            lines.append("")

        if self.removed:
            lines.append(f"Removed ({len(self.removed)} functions):")
            for f in self.removed[:20]:
                lines.append(
                    f"  {f.name}  (was {f.address:#x}, size={f.size})"
                )
            if len(self.removed) > 20:
                lines.append(f"  ... and {len(self.removed) - 20} more")
            lines.append("")

        if self.changed:
            lines.append(f"Changed ({len(self.changed)} functions):")
            for c in self.changed[:30]:
                parts = [f"  {c.name}"]
                if c.size_delta != 0:
                    sign = "+" if c.size_delta > 0 else ""
                    parts.append(
                        f"size: {c.size_old} -> {c.size_new} "
                        f"({sign}{c.size_delta} bytes)"
                    )
                if c.signature_changed:
                    parts.append("signature changed")
                if c.calling_convention_changed:
                    parts.append("calling convention changed")
                if c.decompilation_changed:
                    parts.append("code changed")
                if c.address_shifted:
                    parts.append(f"moved {c.address_old:#x} -> {c.address_new:#x}")
                lines.append("  ".join(parts))
            if len(self.changed) > 30:
                lines.append(f"  ... and {len(self.changed) - 30} more")
            lines.append("")

        if self.comment_deltas:
            added_c = [d for d in self.comment_deltas if d.action == "added"]
            removed_c = [d for d in self.comment_deltas if d.action == "removed"]
            changed_c = [d for d in self.comment_deltas if d.action == "changed"]
            parts = []
            if added_c:
                parts.append(f"{len(added_c)} added")
            if removed_c:
                parts.append(f"{len(removed_c)} removed")
            if changed_c:
                parts.append(f"{len(changed_c)} changed")
            lines.append(f"Comments: {', '.join(parts)}")
            lines.append("")

        if self.import_deltas:
            added_i = self.import_deltas.get("added", [])
            removed_i = self.import_deltas.get("removed", [])
            if added_i:
                lines.append(f"New imports ({len(added_i)}):")
                for name in added_i[:10]:
                    lines.append(f"  {name}")
                if len(added_i) > 10:
                    lines.append(f"  ... and {len(added_i) - 10} more")
            if removed_i:
                lines.append(f"Removed imports ({len(removed_i)}):")
                for name in removed_i[:10]:
                    lines.append(f"  {name}")

        if not self.has_changes:
            lines.append("No differences found.")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label_old": self.label_old,
            "label_new": self.label_new,
            "added": [
                {"name": f.name, "address": f.address, "size": f.size}
                for f in self.added
            ],
            "removed": [
                {"name": f.name, "address": f.address, "size": f.size}
                for f in self.removed
            ],
            "changed": [c.to_dict() for c in self.changed],
            "comment_deltas": [d.to_dict() for d in self.comment_deltas],
            "import_deltas": self.import_deltas,
            "stats": {
                "added_count": len(self.added),
                "removed_count": len(self.removed),
                "changed_count": len(self.changed),
                "comment_delta_count": len(self.comment_deltas),
            },
        }

    @property
    def changed_function_names(self) -> List[str]:
        """Names of all added or changed functions (priority targets)."""
        names = [f.name for f in self.added if not f.is_auto_named]
        names.extend(c.name for c in self.changed)
        return names

    def write_json(self, path: Path) -> None:
        """Write the diff to a JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        logger.info("wrote version diff: %s", path)


def diff_databases(
    old: REDatabase,
    new: REDatabase,
    *,
    label_old: str = "",
    label_new: str = "",
) -> REDiff:
    """Compare two REDatabase instances and produce a structured diff.

    Matches functions by name. Functions present in *new* but not *old*
    are ``added``; present in *old* but not *new* are ``removed``.
    Functions present in both are compared for size, signature, calling
    convention, and decompilation changes.

    Args:
        old: The older / baseline REDatabase.
        new: The newer / comparison REDatabase.
        label_old: Human label for the old version (e.g. "v7.20_rel411").
        label_new: Human label for the new version.

    Returns:
        An REDiff with the comparison results.
    """
    if not label_old:
        label_old = old.metadata.get("program_name", "old")
    if not label_new:
        label_new = new.metadata.get("program_name", "new")

    old_by_name = {f.name: f for f in old.functions}
    new_by_name = {f.name: f for f in new.functions}

    old_names = set(old_by_name.keys())
    new_names = set(new_by_name.keys())

    added = sorted(
        [new_by_name[n] for n in (new_names - old_names)],
        key=lambda f: f.address,
    )
    removed = sorted(
        [old_by_name[n] for n in (old_names - new_names)],
        key=lambda f: f.address,
    )

    changed = []
    for name in sorted(old_names & new_names):
        fo = old_by_name[name]
        fn = new_by_name[name]

        decomp_changed = (
            (fo.decompilation or None) != (fn.decompilation or None)
        )

        if (fo.size != fn.size
                or fo.signature != fn.signature
                or fo.calling_convention != fn.calling_convention
                or fo.address != fn.address
                or decomp_changed):
            changed.append(FunctionChange(
                name=name,
                address_old=fo.address,
                address_new=fn.address,
                size_old=fo.size,
                size_new=fn.size,
                signature_old=fo.signature,
                signature_new=fn.signature,
                calling_convention_old=fo.calling_convention,
                calling_convention_new=fn.calling_convention,
                decompilation_changed=decomp_changed,
            ))

    comment_deltas = _diff_comments(old, new)
    import_deltas = _diff_imports(old, new)

    return REDiff(
        label_old=label_old,
        label_new=label_new,
        added=added,
        removed=removed,
        changed=changed,
        comment_deltas=comment_deltas,
        import_deltas=import_deltas,
    )


def _diff_comments(old: REDatabase, new: REDatabase) -> list[CommentDelta]:
    """Diff comments by (address, kind) key."""
    old_comments = {
        (c.address, c.kind): c for c in old.comments
    }
    new_comments = {
        (c.address, c.kind): c for c in new.comments
    }

    deltas = []
    for key in sorted(set(old_comments) | set(new_comments)):
        co = old_comments.get(key)
        cn = new_comments.get(key)

        if co and not cn:
            deltas.append(CommentDelta(
                function=co.function,
                address=key[0],
                kind=key[1],
                action="removed",
                text_old=co.text,
            ))
        elif cn and not co:
            deltas.append(CommentDelta(
                function=cn.function,
                address=key[0],
                kind=key[1],
                action="added",
                text_new=cn.text,
            ))
        elif co and cn and co.text != cn.text:
            deltas.append(CommentDelta(
                function=cn.function,
                address=key[0],
                kind=key[1],
                action="changed",
                text_old=co.text,
                text_new=cn.text,
            ))

    return deltas


def _diff_imports(old: REDatabase, new: REDatabase) -> dict[str, list[str]]:
    """Diff import symbols by name."""
    old_names = {i["name"] for i in old.imports if "name" in i}
    new_names = {i["name"] for i in new.imports if "name" in i}

    result: dict[str, list[str]] = {}
    added = sorted(new_names - old_names)
    removed = sorted(old_names - new_names)
    if added:
        result["added"] = added
    if removed:
        result["removed"] = removed
    return result
