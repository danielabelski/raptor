"""Tier 0 binary import: objdump + nm → REDatabase.

Zero external dependencies beyond standard binutils. Produces a minimal
REDatabase with functions from the symbol table and raw disassembly.
No decompilation, no xrefs, no types.

This is the fallback when neither Ghidra nor r2 is available — the
LLM can still reason about raw disassembly to find vulnerabilities.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .model import (
    NAME_PROVENANCE_DYNSYM_PLT,
    NAME_PROVENANCE_SYMTAB,
    NAME_PROVENANCE_TOOL_SYNTHETIC,
    REDatabase,
    REFunction,
    looks_tool_synthetic,
)

logger = logging.getLogger(__name__)


def _run_binutil(argv, binary_path: Path, timeout: int = 30):
    """Run a binutils tool on an attacker-supplied binary, sandboxed.

    Repo convention for binary-touching tools (same as the
    binary-oracle's readelf/nm/objdump invocations): BFD has a deep
    parsing-CVE history, so the tool runs network-denied with reads
    scoped to the binary's directory. Returns the CompletedProcess or
    None on launch failure/timeout.
    """
    from core.sandbox import run as _sandbox_run
    target = str(Path(binary_path).resolve().parent)
    try:
        return _sandbox_run(
            argv, block_network=True, target=target,
            capture_output=True, text=True, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        logger.warning("%s failed on %s: %s", argv[0], binary_path, e)
        return None


def objdump_available() -> bool:
    """Check if objdump and nm are in PATH."""
    return (
        shutil.which("objdump") is not None
        and shutil.which("nm") is not None
    )


def import_binary_objdump(binary_path: Path) -> REDatabase:
    """Import a binary using only objdump and nm.

    Parameters
    ----------
    binary_path:
        Path to an ELF/PE/Mach-O binary.

    Returns
    -------
    REDatabase
        Minimal database with functions from nm, no decompilation.
    """
    functions = _extract_functions_nm(binary_path)
    imports = _extract_imports_nm(binary_path)
    arch = _detect_arch(binary_path)

    db = REDatabase(
        source_tool="objdump",
        binary_path=str(binary_path),
        architecture=arch,
        functions=sorted(functions, key=lambda f: f.address),
        imports=imports,
        metadata={"tier": "T0"},
    )

    logger.info(
        "objdump import: %d functions, %d imports from %s (%s)",
        len(functions), len(imports), binary_path.name, arch,
    )

    return db


def disassemble_function(
    binary_path: Path,
    address: int,
    size: int,
) -> str:
    """Disassemble a single function using objdump.

    Returns the disassembly text, or an error message.
    """
    start = "0x%x" % address
    stop = "0x%x" % (address + size)
    result = _run_binutil(
        [
            "objdump", "-d",
            "--start-address=%s" % start,
            "--stop-address=%s" % stop,
            str(binary_path),
        ],
        binary_path,
    )
    if result is None:
        return "(objdump failed to run)"
    if result.returncode == 0 and result.stdout:
        return result.stdout
    return "(objdump returned no output for 0x%x)" % address


def _extract_functions_nm(binary_path: Path) -> List[REFunction]:
    """Extract function symbols from nm output.

    Plain ``nm`` reads the static symbol table (``symtab``
    provenance); the ``nm -D`` fallback for stripped binaries reads
    the dynamic symbol table (``dynsym_plt``). The distinction rides
    on each function so downstream consumers can tell which symbol
    source minted the name.
    """
    provenance = NAME_PROVENANCE_SYMTAB
    result = _run_binutil(
        ["nm", "--defined-only", "-S", str(binary_path)], binary_path,
    )
    if result is None:
        return []

    if result.returncode != 0:
        provenance = NAME_PROVENANCE_DYNSYM_PLT
        result = _run_binutil(
            ["nm", "-D", "-S", str(binary_path)], binary_path,
        )
        if result is None:
            return []

    functions = []
    for line in result.stdout.splitlines():
        parsed = _parse_nm_line(line)
        if parsed is None:
            continue
        addr, size, kind, name = parsed
        if kind not in ("T", "t", "W", "w"):
            continue
        # A symbol table entry wearing a placeholder name (forged or
        # repacked binary) must not ride as a real symbol name.
        synthetic = looks_tool_synthetic(name)
        functions.append(REFunction(
            name=name,
            address=addr,
            size=size,
            is_auto_named=synthetic,
            source_tool="nm",
            name_provenance=(
                NAME_PROVENANCE_TOOL_SYNTHETIC if synthetic
                else provenance
            ),
        ))

    return functions


def _parse_nm_line(line: str) -> Optional[Tuple[int, int, str, str]]:
    """Parse one nm -S output line.

    Format: ``<addr> <size> <type> <name>``
    or:     ``<addr> <type> <name>`` (no -S size)
    """
    parts = line.split()
    if len(parts) == 4:
        try:
            addr = int(parts[0], 16)
            size = int(parts[1], 16)
            return (addr, size, parts[2], parts[3])
        except ValueError:
            return None
    elif len(parts) == 3:
        try:
            addr = int(parts[0], 16)
            return (addr, 0, parts[1], parts[2])
        except ValueError:
            return None
    return None


def _extract_imports_nm(binary_path: Path) -> List[Dict[str, Any]]:
    """Extract undefined (imported) symbols."""
    result = _run_binutil(
        ["nm", "-D", "--undefined-only", str(binary_path)], binary_path,
    )
    if result is None or result.returncode != 0:
        return []

    imports = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-2] == "U":
            imports.append({"name": parts[-1]})
        elif len(parts) == 1:
            imports.append({"name": parts[0]})

    return imports


_ARCH_RE = re.compile(r"file format\s+(\S+)")


def _detect_arch(binary_path: Path) -> str:
    """Detect architecture via objdump -f."""
    result = _run_binutil(
        ["objdump", "-f", str(binary_path)], binary_path, timeout=10,
    )
    if result is not None and result.returncode == 0:
        m = _ARCH_RE.search(result.stdout)
        if m:
            return m.group(1)
    return ""
