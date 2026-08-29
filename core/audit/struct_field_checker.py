"""Struct-field-size vs copy-length mismatch detection.

Works on decompiled C where Ghidra has recovered struct layouts
(especially with DWARF). Finds cases where:

  1. A struct field at a known offset has a known size (from DWARF
     type info or from the decompiler's struct recovery)
  2. A memcpy/memmove writes into that field using a length that
     can exceed the field size

Ghidra decompiler patterns for struct field access:
  - Direct: ptr->field or (*ptr).field
  - Offset: *(type *)(ptr + 0x10) or *(type *)((long)ptr + offset)
  - Array-style: ptr[offset]  (when ptr is char*)

This checker extracts struct field sizes from:
  - Explicit struct definitions in the decompilation
  - Offset arithmetic (consecutive field offsets imply sizes)
  - DWARF-recovered type annotations in comments
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence


@dataclass
class StructFieldFinding:
    function: str
    file: str = ""
    line: int = 0
    struct_type: str = ""
    field_name: str = ""
    field_offset: int = -1
    field_size: int = -1
    copy_size: str = ""
    copy_call: str = ""
    evidence: str = ""
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "function": self.function,
            "evidence": self.evidence,
            "confidence": self.confidence,
        }
        if self.file:
            d["file"] = self.file
        if self.line:
            d["line"] = self.line
        if self.struct_type:
            d["struct_type"] = self.struct_type
        if self.field_name:
            d["field_name"] = self.field_name
        if self.field_offset >= 0:
            d["field_offset"] = self.field_offset
        if self.field_size >= 0:
            d["field_size"] = self.field_size
        if self.copy_size:
            d["copy_size"] = self.copy_size
        if self.copy_call:
            d["copy_call"] = self.copy_call
        return d


_TYPE_SIZES: Dict[str, int] = {
    "char": 1, "uchar": 1, "byte": 1, "uint8_t": 1, "int8_t": 1,
    "undefined": 1, "undefined1": 1, "BYTE": 1,
    "short": 2, "ushort": 2, "uint16_t": 2, "int16_t": 2,
    "undefined2": 2, "WORD": 2,
    "int": 4, "uint": 4, "uint32_t": 4, "int32_t": 4,
    "float": 4, "undefined4": 4, "DWORD": 4,
    "long": 8, "ulong": 8, "uint64_t": 8, "int64_t": 8,
    "double": 8, "undefined8": 8, "longlong": 8,
    "pointer": 8, "void *": 8, "addr": 8,
}

_STRUCT_DEF_RE = re.compile(
    r'struct\s+(\w+)\s*\{([^}]+)\}',
    re.DOTALL,
)

_STRUCT_FIELD_RE = re.compile(
    r'(\w+(?:\s*\*)?)\s+(\w+)'
    r'(?:\[(\d+)\])?\s*;',
)

_OFFSET_DEREF_RE = re.compile(
    r'\*\s*\((\w+(?:\s*\*)?)\s*\)\s*\('
    r'(?:\((?:long|ulong|char\s*\*)\)\s*)?'
    r'(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)',
)

_COPY_INTO_OFFSET_RE = re.compile(
    r'\b(memcpy|memmove)\s*\('
    r'(?:\(void\s*\*\)\s*)?'
    r'(?:\((?:long|ulong|char\s*\*)\)\s*)?'
    r'(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)'
    r'\s*,'
    r'([^,]+),'
    r'([^)]+)\)',
)


def _parse_int(s: str) -> Optional[int]:
    s = s.strip()
    try:
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        return int(s)
    except (ValueError, TypeError):
        return None


def _find_line(source: str, pos: int) -> int:
    return source[:pos].count('\n') + 1


def _extract_struct_layouts(
    source: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """Extract struct definitions with field offsets and sizes."""
    layouts: Dict[str, List[Dict[str, Any]]] = {}

    for m in _STRUCT_DEF_RE.finditer(source):
        struct_name = m.group(1)
        body = m.group(2)
        offset = 0
        fields: List[Dict[str, Any]] = []

        for fm in _STRUCT_FIELD_RE.finditer(body):
            field_type = fm.group(1).strip()
            field_name = fm.group(2)
            array_size = _parse_int(fm.group(3)) if fm.group(3) else None

            base_type = field_type.rstrip(' *')
            is_pointer = '*' in field_type
            if is_pointer:
                elem_size = 8
            else:
                elem_size = _TYPE_SIZES.get(base_type, 4)

            total_size = elem_size * array_size if array_size else elem_size

            fields.append({
                "name": field_name,
                "type": field_type,
                "offset": offset,
                "size": total_size,
                "array_count": array_size,
            })
            offset += total_size

        if fields:
            layouts[struct_name] = fields

    return layouts


def _extract_offset_accesses(
    source: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """Extract base_ptr → [(offset, type, pos)] from offset dereferences."""
    accesses: Dict[str, List[Dict[str, Any]]] = {}

    for m in _OFFSET_DEREF_RE.finditer(source):
        deref_type = m.group(1).strip()
        base_ptr = m.group(2)
        offset = _parse_int(m.group(3))
        if offset is None:
            continue

        base_type = deref_type.rstrip(' *')
        is_pointer = '*' in deref_type
        if is_pointer:
            elem_size = 8
        else:
            elem_size = _TYPE_SIZES.get(base_type, None)

        if base_ptr not in accesses:
            accesses[base_ptr] = []
        accesses[base_ptr].append({
            "offset": offset,
            "type": deref_type,
            "size": elem_size,
            "pos": m.start(),
        })

    return accesses


def _infer_field_sizes(
    accesses: List[Dict[str, Any]],
) -> Dict[int, int]:
    """Given sorted offset accesses, infer field sizes from gaps."""
    if not accesses:
        return {}

    sorted_acc = sorted(accesses, key=lambda a: a["offset"])
    sizes: Dict[int, int] = {}

    for i, acc in enumerate(sorted_acc):
        if acc["size"] is not None:
            sizes[acc["offset"]] = acc["size"]
        elif i + 1 < len(sorted_acc):
            gap = sorted_acc[i + 1]["offset"] - acc["offset"]
            if 0 < gap <= 1024:
                sizes[acc["offset"]] = gap

    return sizes


def check_struct_field_copy(
    function_name: str,
    source: str,
    *,
    file: str = "",
) -> List[StructFieldFinding]:
    """Analyse one function for struct-field vs copy-length mismatches."""
    findings: List[StructFieldFinding] = []

    layouts = _extract_struct_layouts(source)
    offset_accesses = _extract_offset_accesses(source)

    known_fields: Dict[str, Dict[int, Dict[str, Any]]] = {}

    for struct_name, fields in layouts.items():
        for f in fields:
            local_re = re.compile(
                r'\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?'
                + re.escape(struct_name) + r'\b',
            )
            for m in local_re.finditer(source):
                var = m.group(1)
                if var not in known_fields:
                    known_fields[var] = {}
                known_fields[var][f["offset"]] = {
                    "name": f["name"],
                    "size": f["size"],
                    "struct": struct_name,
                }

    for base_ptr, accs in offset_accesses.items():
        inferred = _infer_field_sizes(accs)
        if base_ptr not in known_fields:
            known_fields[base_ptr] = {}
        for offset, size in inferred.items():
            if offset not in known_fields[base_ptr]:
                known_fields[base_ptr][offset] = {
                    "name": f"field_at_{offset:#x}",
                    "size": size,
                    "struct": "",
                }

    if not known_fields:
        return findings

    for m in _COPY_INTO_OFFSET_RE.finditer(source):
        copy_fn = m.group(1)
        base_ptr = m.group(2)
        offset_str = m.group(3)
        copy_len = m.group(5).strip()

        offset = _parse_int(offset_str)
        if offset is None:
            continue

        if base_ptr not in known_fields:
            continue
        field_info = known_fields[base_ptr].get(offset)
        if field_info is None:
            continue

        field_size = field_info["size"]
        copy_len_int = _parse_int(copy_len)

        if copy_len_int is not None:
            if copy_len_int > field_size:
                findings.append(StructFieldFinding(
                    function=function_name,
                    file=file,
                    line=_find_line(source, m.start()),
                    struct_type=field_info.get("struct", ""),
                    field_name=field_info["name"],
                    field_offset=offset,
                    field_size=field_size,
                    copy_size=copy_len,
                    copy_call=copy_fn,
                    evidence=(
                        f"{copy_fn} into {base_ptr}+{offset:#x} "
                        f"(field '{field_info['name']}', {field_size} "
                        f"bytes) with constant length {copy_len_int} — "
                        f"overflows by {copy_len_int - field_size} bytes"
                    ),
                    confidence="high",
                ))
        else:
            findings.append(StructFieldFinding(
                function=function_name,
                file=file,
                line=_find_line(source, m.start()),
                struct_type=field_info.get("struct", ""),
                field_name=field_info["name"],
                field_offset=offset,
                field_size=field_size,
                copy_size=copy_len,
                copy_call=copy_fn,
                evidence=(
                    f"{copy_fn} into {base_ptr}+{offset:#x} "
                    f"(field '{field_info['name']}', {field_size} bytes) "
                    f"with variable length '{copy_len}' — "
                    f"verify bounded to {field_size}"
                ),
                confidence="medium",
            ))

    return findings


def format_findings(findings: Sequence[StructFieldFinding]) -> str:
    if not findings:
        return "struct field checker: no field-size vs copy-length mismatches found"

    lines = [f"### Struct field checker: {len(findings)} findings"]
    for f in findings:
        struct_label = f" ({f.struct_type})" if f.struct_type else ""
        lines.append(
            f"- `{f.function}()` line {f.line}: "
            f"field `{f.field_name}`{struct_label} at offset "
            f"{f.field_offset:#x}, size {f.field_size}"
        )
        lines.append(f"  {f.evidence}")
        lines.append(f"  confidence: {f.confidence}")
    return "\n".join(lines)
