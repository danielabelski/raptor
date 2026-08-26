"""Tool-agnostic reverse engineering database model.

Populated by tool-specific parsers (Ghidra, r2, IDA, ...).
Consumed by RAPTOR's analysis pipeline.  ``BinaryContextMap`` and
``context-map.json`` are derivable from this.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class REFunction:
    """A function identified by an RE tool."""

    name: str
    address: int
    size: int
    signature: Optional[str] = None
    calling_convention: Optional[str] = None
    is_auto_named: bool = False
    is_thunk: bool = False
    is_external: bool = False
    decompilation: Optional[str] = None
    source_tool: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "address": self.address,
            "size": self.size,
            "source_tool": self.source_tool,
        }
        if self.signature is not None:
            d["signature"] = self.signature
        if self.calling_convention is not None:
            d["calling_convention"] = self.calling_convention
        if self.is_auto_named:
            d["is_auto_named"] = True
        if self.is_thunk:
            d["is_thunk"] = True
        if self.is_external:
            d["is_external"] = True
        if self.decompilation is not None:
            d["decompilation"] = self.decompilation
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> REFunction:
        return cls(
            name=str(d.get("name", "")),
            address=int(d.get("address", 0)),
            size=int(d.get("size", 0)),
            # str-coerced like ``name``: a wrong-typed value in a
            # planted cache otherwise trips the renderers'
            # AttributeError, silently disabling injection for the
            # function via the callers' blanket excepts.
            signature=(None if d.get("signature") is None
                       else str(d.get("signature"))),
            calling_convention=d.get("calling_convention"),
            is_auto_named=bool(d.get("is_auto_named", False)),
            is_thunk=bool(d.get("is_thunk", False)),
            is_external=bool(d.get("is_external", False)),
            decompilation=(None if d.get("decompilation") is None
                           else str(d.get("decompilation"))),
            source_tool=str(d.get("source_tool", "")),
        )


@dataclass
class REXref:
    """A cross-reference between two addresses."""

    from_addr: int
    to_addr: int
    kind: str  # "call", "data", "string"
    source_tool: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_addr": self.from_addr,
            "to_addr": self.to_addr,
            "kind": self.kind,
            "source_tool": self.source_tool,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> REXref:
        return cls(
            from_addr=int(d.get("from_addr", 0)),
            to_addr=int(d.get("to_addr", 0)),
            kind=str(d.get("kind", "")),
            source_tool=str(d.get("source_tool", "")),
        )


@dataclass
class REType:
    """A type definition recovered by an RE tool."""

    name: str
    kind: str  # "struct", "enum", "typedef", "function_sig"
    size: Optional[int] = None
    fields: Optional[List[Dict[str, Any]]] = None
    source_tool: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "kind": self.kind,
            "source_tool": self.source_tool,
        }
        if self.size is not None:
            d["size"] = self.size
        if self.fields is not None:
            d["fields"] = self.fields
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> REType:
        # size/fields are type-gated like the function text fields: a
        # planted cache carrying a prose size or fields crashed the
        # renderer's %d / .get, silently disabling injection via the
        # callers' blanket excepts.
        size = d.get("size")
        if isinstance(size, bool) or not isinstance(size, int):
            size = None
        fields = d.get("fields")
        if isinstance(fields, list):
            fields = [f for f in fields if isinstance(f, dict)]
        else:
            fields = None
        return cls(
            name=str(d.get("name", "")),
            kind=str(d.get("kind", "")),
            size=size,
            fields=fields,
            source_tool=str(d.get("source_tool", "")),
        )


@dataclass
class REComment:
    """A comment placed by a researcher or tool."""

    address: int
    function: Optional[str]
    kind: str  # "eol", "plate", "pre", "post"
    text: str
    source_tool: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "address": self.address,
            "kind": self.kind,
            "text": self.text,
            "source_tool": self.source_tool,
        }
        if self.function is not None:
            d["function"] = self.function
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> REComment:
        return cls(
            address=int(d.get("address", 0)),
            function=d.get("function"),
            kind=str(d.get("kind", "")),
            text=str(d.get("text", "")),
            source_tool=str(d.get("source_tool", "")),
        )


@dataclass
class RESegment:
    """A memory segment / section.

    ``end`` is the last address IN the segment (inclusive), matching
    Ghidra's ``MemoryBlock.getEnd()`` semantics.  For exclusive-end,
    use ``end + 1``.
    """

    name: str
    start: int
    end: int
    permissions: str  # "rwx", "r-x", etc.

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "start": self.start,
            "end": self.end,
            "permissions": self.permissions,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> RESegment:
        return cls(
            name=str(d.get("name", "")),
            start=int(d.get("start", 0)),
            end=int(d.get("end", 0)),
            permissions=str(d.get("permissions", "")),
        )


@dataclass
class REDatabase:
    """Tool-agnostic reverse engineering database.

    Populated by tool-specific parsers (Ghidra, r2, IDA, ...).
    Consumed by RAPTOR's analysis pipeline.
    """

    source_tool: str
    binary_path: Optional[str] = None
    architecture: str = ""
    functions: List[REFunction] = field(default_factory=list)
    xrefs: List[REXref] = field(default_factory=list)
    types: List[REType] = field(default_factory=list)
    comments: List[REComment] = field(default_factory=list)
    segments: List[RESegment] = field(default_factory=list)
    imports: List[Dict[str, Any]] = field(default_factory=list)
    exports: List[Dict[str, Any]] = field(default_factory=list)
    strings: List[Dict[str, Any]] = field(default_factory=list)
    bookmarks: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def auto_named_ratio(self) -> float:
        """Fraction of functions that are auto-named (FUN_XXXXX etc.)."""
        if not self.functions:
            return 0.0
        auto = sum(1 for f in self.functions if f.is_auto_named)
        return auto / len(self.functions)

    def _addr_index(self):
        """(starts, functions-sorted-by-address, first-by-exact-addr,
        function-identity set) — built lazily, invalidated when the
        function count changes (the enrich path appends functions).

        Per-lookup linear scans made every xref resolution
        O(xrefs x functions) PER RENDERED FINDING on the prompt
        assembly hot path — a cost a large real binary pays in
        minutes and an attacker-authored cache maximizes for free
        within the 64MiB read ceiling.
        """
        cached = getattr(self, "_addr_index_cache", None)
        if cached is not None and cached[0] == len(self.functions):
            return cached[1:]
        # Only SIZED functions join the containment ladder: size-0
        # entries (nm-fallback symbols without .size, ARM mapping
        # symbols) can never satisfy the containment predicate but
        # would consume the bounded walk-back budget — dozens of them
        # inside one large function's range silently turned real
        # containment hits into misses. Exact-address lookups are
        # served by by_addr, which keeps every function.
        ordered = sorted(
            (f for f in self.functions
             if isinstance(f.address, int)
             and isinstance(f.size, int) and f.size > 0),
            key=lambda f: f.address,
        )
        starts = [f.address for f in ordered]
        by_addr: Dict[int, REFunction] = {}
        for f in self.functions:
            if isinstance(f.address, int):
                # setdefault keeps the FIRST list entry — parity with
                # the pre-index linear scan on duplicate addresses.
                by_addr.setdefault(f.address, f)
        ids = {id(f) for f in self.functions}
        self._addr_index_cache = (
            len(self.functions), starts, ordered, by_addr, ids)
        return starts, ordered, by_addr, ids

    def function_by_address(self, addr: int) -> Optional[REFunction]:
        """Look up a function by address (indexed)."""
        _starts, _ordered, by_addr, _ids = self._addr_index()
        try:
            return by_addr.get(addr)
        except TypeError:  # unhashable junk addr
            return None

    def function_containing_address(self, addr: int) -> Optional[REFunction]:
        """Find the function whose body contains *addr*.

        Returns the function where ``f.address <= addr < f.address + f.size``,
        or falls back to exact-match via :meth:`function_by_address`.
        Indexed: bisect to the nearest preceding start, then a short
        bounded walk-back (real layouts don't overlap; a hostile cache
        with deeply overlapping ranges degrades to a miss rather than
        restoring the quadratic scan).
        """
        if not isinstance(addr, int) or isinstance(addr, bool):
            return None
        import bisect
        starts, ordered, _by_addr, _ids = self._addr_index()
        i = bisect.bisect_right(starts, addr) - 1
        for j in range(i, max(-1, i - 64), -1):
            f = ordered[j]
            if (isinstance(f.size, int) and f.size > 0
                    and f.address <= addr < f.address + f.size):
                return f
        return self.function_by_address(addr)


    def _estimate_base_delta(self, other: "REDatabase") -> int:
        """Rebase delta from *other*'s address space into ours.

        Uses the modal address difference across same-named non-auto
        functions — robust to a few name collisions and independent
        of either engine's image_base metadata (which fallback
        importers may not populate). Returns 0 when there is no
        consistent evidence.
        """
        from collections import Counter

        ours = {
            f.name: f.address for f in self.functions
            if not f.is_auto_named
        }
        deltas = Counter()
        for f in other.functions:
            if f.is_auto_named:
                continue
            addr = ours.get(f.name)
            if addr is not None:
                deltas[addr - f.address] += 1
        if not deltas:
            return 0
        delta, votes = deltas.most_common(1)[0]
        # Demand agreement from at least 3 names (or all of a small
        # overlap) so a coincidental single match can't rebase.
        if votes >= 3 or votes == sum(deltas.values()) >= 2:
            return delta
        return 0

    def merge(self, other: REDatabase) -> REDatabase:
        """Merge *other* into a new REDatabase.  ``self`` is the primary
        (higher trust); ``other`` provides additive enrichment.

        - Functions: union by address.  Same address → self wins metadata.
        - Xrefs: union, dedup by (from_addr, to_addr, kind).
        - Types: self wins on name conflicts.
        - Comments: both kept (no overwrite).
        - Segments: self wins.
        - Imports/exports/strings: union by address.
        - Bookmarks: union.
        """
        result = REDatabase(
            source_tool=self.source_tool,
            binary_path=self.binary_path or other.binary_path,
            architecture=self.architecture or other.architecture,
            metadata={**other.metadata, **self.metadata},
        )

        # Different engines rebase the image differently (Ghidra
        # defaults PIE binaries to 0x100000, r2 to their file base),
        # so an address-keyed union without normalisation matches
        # NOTHING and duplicates every function. Estimate the delta
        # from shared function names and rebase *other* first.
        delta = self._estimate_base_delta(other)
        other_functions = other.functions
        if delta:
            other_functions = [
                REFunction(
                    name=f.name,
                    address=f.address + delta,
                    size=f.size,
                    is_auto_named=f.is_auto_named,
                    is_thunk=f.is_thunk,
                    is_external=f.is_external,
                    signature=f.signature,
                    calling_convention=f.calling_convention,
                    decompilation=f.decompilation,
                    source_tool=f.source_tool,
                )
                for f in other.functions
            ]

        # Functions — union by address, self wins
        by_addr: Dict[int, REFunction] = {}
        for f in other_functions:
            by_addr[f.address] = f
        for f in self.functions:
            by_addr[f.address] = f
        result.functions = sorted(by_addr.values(), key=lambda f: f.address)

        # Xrefs — union, dedup
        seen_xrefs: set[tuple[int, int, str]] = set()
        for xref in (*self.xrefs, *other.xrefs):
            key = (xref.from_addr, xref.to_addr, xref.kind)
            if key not in seen_xrefs:
                seen_xrefs.add(key)
                result.xrefs.append(xref)

        # Types — self wins on name conflicts
        by_name: Dict[str, REType] = {}
        for t in other.types:
            by_name[t.name] = t
        for t in self.types:
            by_name[t.name] = t
        result.types = list(by_name.values())

        # Comments — both kept
        result.comments = [*self.comments, *other.comments]

        # Segments — self wins
        result.segments = list(self.segments) if self.segments else list(other.segments)

        # Imports/exports/strings — union by name+address
        for attr in ("imports", "exports", "strings"):
            self_items = getattr(self, attr)
            other_items = getattr(other, attr)
            seen: set = set()
            merged: List[Dict[str, Any]] = []
            for item in (*self_items, *other_items):
                key = (
                    item.get("name", item.get("value", "")),
                    item.get("address"),
                )
                if key not in seen:
                    seen.add(key)
                    merged.append(item)
            setattr(result, attr, merged)

        # Bookmarks — union
        result.bookmarks = [*self.bookmarks, *other.bookmarks]

        return result

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_tool": self.source_tool,
            "binary_path": self.binary_path,
            "architecture": self.architecture,
            "functions": [f.to_dict() for f in self.functions],
            "xrefs": [x.to_dict() for x in self.xrefs],
            "types": [t.to_dict() for t in self.types],
            "comments": [c.to_dict() for c in self.comments],
            "segments": [s.to_dict() for s in self.segments],
            "imports": self.imports,
            "exports": self.exports,
            "strings": self.strings,
            "bookmarks": self.bookmarks,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> REDatabase:
        if not isinstance(d, dict):
            raise ValueError(
                f"REDatabase document must be a dict, got {type(d).__name__}"
            )
        return cls(
            source_tool=str(d.get("source_tool", "")),
            binary_path=d.get("binary_path"),
            architecture=str(d.get("architecture", "")),
            functions=[REFunction.from_dict(f) for f in d.get("functions", [])],
            xrefs=[REXref.from_dict(x) for x in d.get("xrefs", [])],
            types=[REType.from_dict(t) for t in d.get("types", [])],
            comments=[REComment.from_dict(c) for c in d.get("comments", [])],
            segments=[RESegment.from_dict(s) for s in d.get("segments", [])],
            imports=d.get("imports", []),
            exports=d.get("exports", []),
            strings=d.get("strings", []),
            bookmarks=d.get("bookmarks", []),
            metadata=d.get("metadata", {}),
        )
