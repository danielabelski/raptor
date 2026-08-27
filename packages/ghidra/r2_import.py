"""Import a binary into REDatabase via radare2.

Provides Tier 1 (r2 analysis) and Tier 2 (r2 + decompiler) without
Ghidra. Uses :class:`~packages.binary_analysis.radare2_understand.BinaryUnderstand`
for the heavy lifting, then converts the output to
:class:`~packages.ghidra.model.REDatabase`.

Falls back to :func:`objdump_import` when r2 is unavailable.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from typing import Tuple

from .model import (
    NAME_PROVENANCE_DWARF,
    NAME_PROVENANCE_DYNSYM_PLT,
    NAME_PROVENANCE_SYMTAB,
    NAME_PROVENANCE_TOOL_SYNTHETIC,
    REDatabase,
    REFunction,
    looks_tool_synthetic,
)

logger = logging.getLogger(__name__)


def r2_available() -> bool:
    """Check if radare2 and r2pipe are available."""
    try:
        from packages.binary_analysis.radare2_understand import probe_capability
        caps = probe_capability()
        return caps.get("available", False)
    except ImportError:
        return False


def _normalise_r2_name(name: str) -> str:
    """Strip r2 namespace prefixes so names match other engines.

    Ghidra and objdump/nm both report the plain symbol (``greet``);
    r2 prefixes DWARF-derived names with ``dbg.`` and symbol-table
    names with ``sym.`` — a cross-engine consumer keying findings by
    name would silently miss. Import thunks (``sym.imp.*``) keep the
    full prefix: they are distinct entities from the real function.
    """
    if name.startswith("sym.imp."):
        return name
    for prefix in ("dbg.", "sym."):
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


def _classify_r2_name(
    raw_name: str,
    *,
    is_imported: bool = False,
) -> Tuple[str, str, bool]:
    """Classify an r2 flag name BEFORE normalisation discards prefixes.

    r2's namespaces carry exactly the provenance the cross-engine
    name normalisation strips: ``dbg.`` (DWARF-derived), ``sym.``
    (symbol table), ``sym.imp.`` (import thunk — dynamic symbols),
    ``fcn.``/``loc.``/``entry0`` (r2-invented placeholders).

    Returns ``(normalised_name, name_provenance, is_auto_named)``.
    A placeholder-looking name is always ``tool_synthetic`` even when
    it wears a better namespace (``sym.fcn.**`` — a forged symbol
    table entry must not launder a placeholder into a real name).
    Unprefixed non-placeholder names stay at unknown provenance
    unless the caller knows they came from the import table.
    """
    if raw_name.startswith(("sym.imp.", "imp.")):
        provenance = NAME_PROVENANCE_DYNSYM_PLT
    elif raw_name.startswith("dbg."):
        provenance = NAME_PROVENANCE_DWARF
    elif raw_name.startswith("sym."):
        provenance = NAME_PROVENANCE_SYMTAB
    elif is_imported:
        provenance = NAME_PROVENANCE_DYNSYM_PLT
    else:
        provenance = ""

    name = _normalise_r2_name(raw_name)
    if looks_tool_synthetic(name):
        return name, NAME_PROVENANCE_TOOL_SYNTHETIC, True
    return name, provenance, False


def import_binary_r2(
    binary_path: Path,
    *,
    decompile_limit: int = 50,
) -> REDatabase:
    """Import a binary via r2 analysis into an REDatabase.

    Parameters
    ----------
    binary_path:
        Path to the ELF/PE/Mach-O binary.
    decompile_limit:
        Maximum number of functions to decompile (for T2). 0 = skip
        decompilation entirely (T1 only).

    Returns
    -------
    REDatabase
        Populated with functions, xrefs, imports, exports, strings.

    Raises
    ------
    ImportError
        If r2pipe or radare2_understand is not available.
    RuntimeError
        If r2 analysis fails.
    """
    from packages.binary_analysis.radare2_understand import (
        BinaryUnderstand,
    )

    bu = BinaryUnderstand(binary_path)
    ctx = bu.analyse(
        max_decompile=decompile_limit,
    )

    return _context_map_to_redb(ctx, binary_path)


def context_map_to_redb(
    context_map: Dict[str, Any],
    binary_path: Optional[Path] = None,
) -> REDatabase:
    """Convert a serialised BinaryContextMap dict to REDatabase.

    Useful when a prior ``/understand`` run has already produced a
    ``binary-context-map.json`` — avoids re-running r2.
    """
    bp = binary_path or Path(context_map.get("binary", "unknown"))
    return _context_map_to_redb_dict(context_map, bp)


def _context_map_to_redb(ctx, binary_path: Path) -> REDatabase:
    """Convert a BinaryContextMap object to REDatabase."""
    functions: List[REFunction] = []
    seen_addrs = set()

    for fn in ctx.interesting_functions:
        if fn.address in seen_addrs:
            continue
        seen_addrs.add(fn.address)
        name, provenance, is_auto = _classify_r2_name(
            fn.name, is_imported=fn.is_imported,
        )
        functions.append(REFunction(
            name=name,
            address=fn.address,
            size=fn.size,
            is_auto_named=is_auto,
            is_external=fn.is_imported,
            decompilation=fn.decompiled or None,
            source_tool="r2",
            name_provenance=provenance,
        ))

    for fn in ctx.imported_functions:
        if fn.address in seen_addrs:
            continue
        seen_addrs.add(fn.address)
        name, provenance, is_auto = _classify_r2_name(
            fn.name, is_imported=True,
        )
        functions.append(REFunction(
            name=name,
            address=fn.address,
            size=fn.size,
            is_auto_named=is_auto,
            is_external=True,
            source_tool="r2",
            name_provenance=provenance,
        ))

    imports = [{"name": name} for name in ctx.imports]
    exports = [{"name": name} for name in ctx.exports]
    strings = [
        {"value": s, "address": 0}
        for s in ctx.strings_sample
    ]

    db = REDatabase(
        source_tool="r2",
        binary_path=str(binary_path),
        architecture="%s %d-bit" % (ctx.arch, ctx.bits) if ctx.arch else "",
        functions=sorted(functions, key=lambda f: f.address),
        imports=imports,
        exports=exports,
        strings=strings,
        metadata={
            "binary_format": ctx.binary_format,
            "image_base": ctx.image_base,
            "decompiler": ctx.decompiler,
            "analysis_depth": ctx.analysis_depth,
        },
    )

    logger.info(
        "r2 import: %d functions (%d with decompilation), "
        "%d imports, %d exports from %s",
        len(functions),
        sum(1 for f in functions if f.decompilation),
        len(imports),
        len(exports),
        binary_path.name,
    )

    return db


def _context_map_to_redb_dict(
    ctx_dict: Dict[str, Any],
    binary_path: Path,
) -> REDatabase:
    """Convert a serialised context-map dict to REDatabase."""
    functions: List[REFunction] = []
    seen_addrs = set()

    for fn_list_key in ("interesting_functions", "imported_functions"):
        for fn in ctx_dict.get(fn_list_key, []):
            addr = _parse_addr(fn.get("address"))
            if addr in seen_addrs:
                continue
            seen_addrs.add(addr)
            is_imported = bool(
                fn.get("is_imported", False)
                or fn_list_key == "imported_functions",
            )
            name, provenance, is_auto = _classify_r2_name(
                fn.get("name", ""), is_imported=is_imported,
            )
            functions.append(REFunction(
                name=name,
                address=addr,
                size=fn.get("size", 0) or 0,
                is_auto_named=is_auto,
                is_external=is_imported,
                source_tool="r2",
                name_provenance=provenance,
            ))

    imports = [{"name": name} for name in ctx_dict.get("imports", [])]
    exports = [{"name": name} for name in ctx_dict.get("exports", [])]
    strings = [
        {"value": s, "address": 0}
        for s in ctx_dict.get("strings_sample", [])
    ]

    return REDatabase(
        source_tool="r2",
        binary_path=str(binary_path),
        architecture="%s %d-bit" % (
            ctx_dict.get("arch", ""),
            ctx_dict.get("bits", 0),
        ) if ctx_dict.get("arch") else "",
        functions=sorted(functions, key=lambda f: f.address),
        imports=imports,
        exports=exports,
        strings=strings,
        metadata={
            "binary_format": ctx_dict.get("binary_format", ""),
            "image_base": ctx_dict.get("image_base", 0),
            "decompiler": ctx_dict.get("decompiler", ""),
        },
    )


def _parse_addr(value) -> int:
    """Parse an address that may be hex string or int.

    Returns -1 for unparseable values (0 is a valid address in firmware).
    """
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value.startswith("0x") else int(value)
        except (ValueError, TypeError):
            return -1
    return -1
