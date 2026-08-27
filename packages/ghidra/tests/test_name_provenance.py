"""Name-provenance minting at the binary import seams.

A binary-derived function name is only as trustworthy as the place it
came from: debug info, a symbol table, the dynamic import table, a
tool's pattern matcher, or the tool's own placeholder generator.
These tests pin that the distinction is minted where the facts are
born (Ghidra export parse, r2 import, objdump/nm fallback), survives
serialisation, and can never be laundered upward by a hostile or
weird binary.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from packages.ghidra.model import (
    KNOWN_NAME_PROVENANCES,
    REDatabase,
    REFunction,
    looks_tool_synthetic,
    normalise_name_provenance,
)


def _fn(name, addr, size=64, is_imported=False, decompiled=""):
    return SimpleNamespace(
        name=name, address=addr, size=size,
        is_imported=is_imported, decompiled=decompiled,
    )


def _ctx(interesting=(), imported=()):
    return SimpleNamespace(
        interesting_functions=list(interesting),
        imported_functions=list(imported),
        imports=[], exports=[], strings_sample=[],
        arch="x86", bits=64, binary_format="elf",
        image_base=0x400000, decompiler="", analysis_depth="aa",
    )


# ── r2 import seam ───────────────────────────────────────────────────


class TestR2NameProvenance:
    def test_stripped_binary_auto_names_arrive_tool_synthetic(self):
        """r2 fcn.* placeholder names on a fully stripped binary must
        import as tool_synthetic / auto-named, and auto_named_ratio
        must be honest (1.0) — not read 0.00 because the seam never
        set the flag."""
        from packages.ghidra.r2_import import _context_map_to_redb

        ctx = _ctx(interesting=[
            _fn("fcn.00401000", 0x401000),
            _fn("fcn.00401100", 0x401100),
            _fn("loc.00401200", 0x401200),
        ])
        db = _context_map_to_redb(ctx, __import__("pathlib").Path("/x/t"))

        assert all(f.is_auto_named for f in db.functions)
        assert all(
            f.name_provenance == "tool_synthetic" for f in db.functions
        )
        assert db.auto_named_ratio == 1.0

    def test_dbg_prefix_mints_dwarf_and_sym_mints_symtab(self):
        """r2's dbg./sym. namespaces carry exactly the provenance the
        cross-engine normalisation used to discard."""
        from packages.ghidra.r2_import import _context_map_to_redb

        ctx = _ctx(interesting=[
            _fn("dbg.parse_packet", 0x1000),
            _fn("sym.helper", 0x2000),
        ])
        db = _context_map_to_redb(ctx, __import__("pathlib").Path("/x/t"))

        by_name = {f.name: f for f in db.functions}
        assert by_name["parse_packet"].name_provenance == "dwarf"
        assert by_name["helper"].name_provenance == "symtab"
        assert not by_name["parse_packet"].is_auto_named

    def test_import_thunks_mint_dynsym_plt(self):
        from packages.ghidra.r2_import import _context_map_to_redb

        ctx = _ctx(imported=[
            _fn("sym.imp.strcpy", 0x3000, is_imported=True),
            _fn("__isoc99_scanf", 0x3010, is_imported=True),
        ])
        db = _context_map_to_redb(ctx, __import__("pathlib").Path("/x/t"))

        assert {f.name_provenance for f in db.functions} == {"dynsym_plt"}
        # Import thunks keep their full name (distinct entity).
        assert "sym.imp.strcpy" in {f.name for f in db.functions}

    def test_placeholder_wearing_symbol_namespace_stays_synthetic(self):
        """Hostile/weird binary: a symbol table entry literally named
        like a placeholder (sym.fcn.00401000 — forged symtab or a
        repack) must NOT launder into a symtab-trusted name."""
        from packages.ghidra.r2_import import _classify_r2_name

        name, prov, auto = _classify_r2_name("sym.fcn.00401000")
        assert prov == "tool_synthetic"
        assert auto is True
        assert name == "fcn.00401000"

        name, prov, auto = _classify_r2_name("dbg.fcn.00401000")
        assert prov == "tool_synthetic"
        assert auto is True

    def test_serialised_context_map_path_mints_same_tags(self):
        from packages.ghidra.r2_import import context_map_to_redb

        ctx = {
            "binary": "/x/t",
            "arch": "x86", "bits": 64,
            "interesting_functions": [
                {"name": "fcn.00401000", "address": "0x401000", "size": 64},
                {"name": "dbg.main", "address": "0x401100", "size": 64},
            ],
            "imported_functions": [
                {"name": "sym.imp.read", "address": "0x401200", "size": 16},
            ],
        }
        db = context_map_to_redb(ctx)
        by_name = {f.name: f for f in db.functions}
        assert by_name["fcn.00401000"].name_provenance == "tool_synthetic"
        assert by_name["main"].name_provenance == "dwarf"
        assert by_name["sym.imp.read"].name_provenance == "dynsym_plt"
        assert by_name["sym.imp.read"].is_external


# ── Ghidra export parse seam ─────────────────────────────────────────


class TestGhidraParserProvenance:
    def _parse(self, **fields):
        from packages.ghidra.parser import _parse_function

        d = {"name": "f", "address": 0x1000, "size": 64}
        d.update(fields)
        return _parse_function(d)

    def test_default_source_is_tool_synthetic(self):
        f = self._parse(name="FUN_00401000", symbol_source="default")
        assert f.name_provenance == "tool_synthetic"
        assert f.is_auto_named

    def test_analysis_source_is_pattern_recovered_not_real(self):
        """FunctionID-applied names are heuristics, not symbols —
        the old export conflated them into 'not auto'."""
        f = self._parse(name="curl_easy_init", symbol_source="analysis")
        assert f.name_provenance == "pattern_recovered"

    def test_analysis_source_with_decoration_is_demangled(self):
        f = self._parse(
            name="std::vector<int>::push_back(int)",
            symbol_source="analysis",
        )
        assert f.name_provenance == "demangled"

    def test_imported_source_is_symtab_provisionally(self):
        f = self._parse(name="parse_header", symbol_source="imported")
        assert f.name_provenance == "symtab"

    def test_user_defined_source_stays_unknown(self):
        f = self._parse(name="renamed_by_analyst",
                        symbol_source="user_defined")
        assert f.name_provenance == ""

    def test_placeholder_name_beats_claimed_import_source(self):
        """Dangerous direction: a FUN_* name arriving with a forged
        'imported' claim must stay tool_synthetic."""
        f = self._parse(name="FUN_00401234", symbol_source="imported")
        assert f.name_provenance == "tool_synthetic"

    def test_legacy_export_without_symbol_source(self):
        auto = self._parse(name="FUN_00401000", is_auto_named=True)
        assert auto.name_provenance == "tool_synthetic"
        named = self._parse(name="main")
        assert named.name_provenance == ""


# ── Model carrier ────────────────────────────────────────────────────


class TestProvenanceCarrier:
    def test_round_trips_redatabase_json(self):
        db = REDatabase(
            source_tool="r2",
            functions=[
                REFunction(name="main", address=0x1000, size=64,
                           name_provenance="dwarf"),
                REFunction(name="fcn.2000", address=0x2000, size=64,
                           is_auto_named=True,
                           name_provenance="tool_synthetic"),
            ],
        )
        restored = REDatabase.from_dict(
            json.loads(json.dumps(db.to_dict())),
        )
        assert restored.functions[0].name_provenance == "dwarf"
        assert restored.functions[1].name_provenance == "tool_synthetic"

    def test_unknown_tag_collapses_to_unknown(self):
        """A tag outside the vocabulary (planted cache) must not ride
        into consumers as if it carried trust."""
        f = REFunction.from_dict({
            "name": "x", "address": 1, "size": 1,
            "name_provenance": "definitely_trusted",
        })
        assert f.name_provenance == ""
        assert normalise_name_provenance(12) == ""
        assert normalise_name_provenance(None) == ""
        for tag in KNOWN_NAME_PROVENANCES:
            assert normalise_name_provenance(tag) == tag

    def test_merge_rebase_keeps_provenance(self):
        primary = REDatabase(
            source_tool="ghidra",
            functions=[
                REFunction(name="anchor%d" % i, address=0x1000 + i * 0x100,
                           size=64, name_provenance="symtab")
                for i in range(3)
            ],
        )
        other = REDatabase(
            source_tool="r2",
            functions=[
                REFunction(name="anchor%d" % i, address=0x2000 + i * 0x100,
                           size=64, name_provenance="dwarf")
                for i in range(3)
            ] + [
                REFunction(name="extra", address=0x2500, size=64,
                           name_provenance="dwarf"),
            ],
        )
        merged = primary.merge(other)
        extra = next(f for f in merged.functions if f.name == "extra")
        assert extra.name_provenance == "dwarf"

    def test_looks_tool_synthetic_covers_all_engines(self):
        for name in ("FUN_00401000", "fcn.00401000", "sub_401000",
                     "loc.00401000", "entry0", "thunk_FUN_00401000", ""):
            assert looks_tool_synthetic(name), name
        for name in ("main", "parse_packet", "sym.imp.read",
                     "entry_point_handler"):
            assert not looks_tool_synthetic(name), name


# ── objdump/nm fallback seam ─────────────────────────────────────────


class _FakeProc(SimpleNamespace):
    pass


class TestNmProvenance:
    def _run_import(self, monkeypatch, results):
        """Drive _extract_functions_nm with canned nm output.

        *results* maps the nm argv marker to (returncode, stdout);
        markers: "defined" (plain nm) and "dynamic" (nm -D).
        """
        from packages.ghidra import objdump_import

        def fake_run(argv, binary_path, timeout=30):
            marker = "dynamic" if "-D" in argv else "defined"
            entry = results.get(marker)
            if entry is None:
                return None
            rc, out = entry
            return _FakeProc(returncode=rc, stdout=out, stderr="")

        monkeypatch.setattr(objdump_import, "_run_binutil", fake_run)
        return objdump_import._extract_functions_nm(
            __import__("pathlib").Path("/x/bin"),
        )

    def test_static_symbols_mint_symtab(self, monkeypatch):
        fns = self._run_import(monkeypatch, {
            "defined": (0, "0000000000401000 00000040 T main\n"),
        })
        assert fns[0].name == "main"
        assert fns[0].name_provenance == "symtab"
        assert not fns[0].is_auto_named

    def test_stripped_fallback_mints_dynsym_plt(self, monkeypatch):
        """When plain nm fails (stripped binary) the -D fallback reads
        the DYNAMIC symbol table — the name class must say so."""
        fns = self._run_import(monkeypatch, {
            "defined": (1, ""),
            "dynamic": (0, "0000000000401000 00000040 T exported_fn\n"),
        })
        assert fns[0].name_provenance == "dynsym_plt"

    def test_forged_placeholder_symbol_stays_synthetic(self, monkeypatch):
        fns = self._run_import(monkeypatch, {
            "defined": (0, "0000000000401000 00000040 T fcn.00401000\n"),
        })
        assert fns[0].name_provenance == "tool_synthetic"
        assert fns[0].is_auto_named
