"""Binary fact-provenance probe: section facts, build-id, fortification.

Unit tests run everywhere (no toolchain needed); the compiled-fixture
tests exercise the real readelf path and skip with the missing tool
named when the environment lacks cc/readelf/strip/objcopy.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from core.analysis.binary_provenance import (
    binary_provenance_block,
    fortified_import_names,
    probe_binary,
)
from packages.ghidra.model import REDatabase, REFunction


class TestFortifiedImports:
    def test_chk_imports_detected(self):
        hits = fortified_import_names([
            "strcpy", "__strcpy_chk", "__memcpy_chk@GLIBC_2.3.4",
            "printf", "__vsnprintf_chk",
        ])
        assert hits == [
            "__memcpy_chk", "__strcpy_chk", "__vsnprintf_chk",
        ]

    def test_no_false_positives(self):
        assert fortified_import_names(
            ["strcpy", "check_input", "_chk", ""],
        ) == []

    def test_forged_import_table_is_bounded(self):
        """A hostile import table with thousands of __*_chk entries
        must not bloat journal/cache records."""
        hits = fortified_import_names(
            [f"__forged{i:04d}_chk" for i in range(5000)],
        )
        assert len(hits) == 32


class TestProbeDegradation:
    def test_non_elf_file_is_declared_not_probed(self, tmp_path):
        f = tmp_path / "notelf.bin"
        f.write_bytes(b"MZ\x90\x00" + b"\0" * 64)
        result = probe_binary(f)
        assert result["probe"] == "not_elf"
        assert result["has_dwarf"] is None
        assert result["stripped"] is None

    def test_missing_file_is_unavailable(self, tmp_path):
        result = probe_binary(tmp_path / "nope")
        assert result["probe"] == "unavailable"
        assert result["build_id"] is None

    def test_block_without_binary_still_reports_fortify(self):
        block = binary_provenance_block(None, ["__strcpy_chk"])
        assert block["probe"] == "unavailable"
        assert block["fortified"] is True
        assert block["fortified_imports"] == ["__strcpy_chk"]
        assert block["has_dwarf"] is None


class TestDebugInfoHeaderSanity:
    """Unit lane for the CU-header check — no toolchain needed."""

    def _sane(self, tmp_path, payload, little_endian=True, size=None):
        from core.analysis.binary_provenance import (
            _debug_info_header_sane,
        )

        f = tmp_path / "section"
        f.write_bytes(payload)
        return _debug_info_header_sane(
            f, 0, size if size is not None else len(payload),
            little_endian,
        )

    def test_real_dwarf32_header_passes(self, tmp_path):
        # unit_length=0x40 (fits a 0x100 section), version=4
        payload = (0x40).to_bytes(4, "little") \
            + (4).to_bytes(2, "little") + b"\0" * 250
        assert self._sane(tmp_path, payload) is True

    def test_dwarf64_header_passes(self, tmp_path):
        payload = b"\xff\xff\xff\xff" \
            + (0x40).to_bytes(8, "little") \
            + (5).to_bytes(2, "little") + b"\0" * 242
        assert self._sane(tmp_path, payload) is True

    def test_big_endian_header_passes(self, tmp_path):
        payload = (0x40).to_bytes(4, "big") \
            + (4).to_bytes(2, "big") + b"\0" * 250
        assert self._sane(tmp_path, payload,
                          little_endian=False) is True

    def test_compressed_section_tag_passes(self, tmp_path):
        payload = (1).to_bytes(4, "little") + b"\0" * 60  # ZLIB Chdr
        assert self._sane(tmp_path, payload) is True

    def test_garbage_bytes_fail(self, tmp_path):
        assert self._sane(tmp_path, b"\xde\xad\xbe\xef" * 128) is False

    def test_unit_length_beyond_section_fails(self, tmp_path):
        payload = (0x10000).to_bytes(4, "little") \
            + (4).to_bytes(2, "little") + b"\0" * 58
        assert self._sane(tmp_path, payload) is False

    def test_unknown_dwarf_version_fails(self, tmp_path):
        payload = (0x20).to_bytes(4, "little") \
            + (77).to_bytes(2, "little") + b"\0" * 58
        assert self._sane(tmp_path, payload) is False

    def test_tiny_or_unreadable_section_fails(self, tmp_path):
        from core.analysis.binary_provenance import (
            _debug_info_header_sane,
        )

        assert self._sane(tmp_path, b"\x01\x02\x03") is False
        assert _debug_info_header_sane(
            tmp_path / "missing", 0, 64, True,
        ) is False


def _compile(tmp_path, name, extra_flags):
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        pytest.skip("no C compiler (cc/gcc) on this runner")
    if shutil.which("readelf") is None:
        pytest.skip("no readelf on this runner")
    src = tmp_path / "t.c"
    src.write_text(
        "#include <stdio.h>\n"
        "int main(void){ printf(\"hi\\n\"); return 0; }\n"
    )
    out = tmp_path / name
    proc = subprocess.run(
        [cc, "-o", str(out), str(src), "-Wl,--build-id=sha1",
         *extra_flags],
        capture_output=True, text=True, timeout=60,
    )
    if proc.returncode != 0:
        pytest.skip(f"fixture compile failed: {proc.stderr[:200]}")
    return out


class TestCompiledFixture:
    def test_dwarf_build_probes_dwarf_and_build_id(self, tmp_path):
        binary = _compile(tmp_path, "dwarf_bin", ["-g", "-O1"])
        result = probe_binary(binary)
        assert result["probe"] == "readelf"
        assert result["has_dwarf"] is True
        assert result["has_symtab"] is True
        assert result["stripped"] is False
        assert result["build_id"] and all(
            c in "0123456789abcdef" for c in result["build_id"]
        )

    def test_stripped_build_probes_stripped_no_dwarf(self, tmp_path):
        if shutil.which("strip") is None:
            pytest.skip("no strip on this runner")
        binary = _compile(tmp_path, "stripped_bin", ["-g", "-O1"])
        subprocess.run(["strip", str(binary)], check=True, timeout=60)
        result = probe_binary(binary)
        assert result["probe"] == "readelf"
        assert result["has_dwarf"] is False
        assert result["stripped"] is True
        assert result["has_dynsym"] is True

    def test_planted_debug_section_does_not_upgrade(self, tmp_path):
        """Hostile shapes: neither a zero-size .debug_info nor a
        non-empty one glued on WITHOUT its .debug_abbrev sibling may
        read as DWARF presence."""
        if shutil.which("strip") is None or shutil.which("objcopy") is None:
            pytest.skip("no strip/objcopy on this runner")
        binary = _compile(tmp_path, "fake_dwarf_bin", ["-O1"])
        subprocess.run(["strip", str(binary)], check=True, timeout=60)
        empty = tmp_path / "empty"
        empty.write_bytes(b"")
        subprocess.run(
            ["objcopy", "--add-section", f".debug_info={empty}",
             str(binary)],
            check=True, timeout=60,
        )
        result = probe_binary(binary)
        assert result["probe"] == "readelf"
        assert result["has_dwarf"] is False

        binary2 = _compile(tmp_path, "fake_dwarf_bin2", ["-O1"])
        subprocess.run(["strip", str(binary2)], check=True, timeout=60)
        garbage = tmp_path / "garbage"
        garbage.write_bytes(b"\xde\xad\xbe\xef" * 16)
        subprocess.run(
            ["objcopy", "--add-section", f".debug_info={garbage}",
             str(binary2)],
            check=True, timeout=60,
        )
        result = probe_binary(binary2)
        assert result["probe"] == "readelf"
        assert result["has_dwarf"] is False

    def test_garbage_glued_into_both_debug_sections_does_not_upgrade(
            self, tmp_path):
        """Section PRESENCE is one objcopy away: garbage bytes glued
        into BOTH .debug_info and .debug_abbrev must still refuse
        has_dwarf — the leading CU header (unit length bounded by the
        section, DWARF version 2-5) is what presence must mean."""
        if shutil.which("strip") is None or shutil.which("objcopy") is None:
            pytest.skip("no strip/objcopy on this runner")
        binary = _compile(tmp_path, "fake_dwarf_pair_bin", ["-O1"])
        subprocess.run(["strip", str(binary)], check=True, timeout=60)
        garbage = tmp_path / "garbage512"
        garbage.write_bytes(b"\xde\xad\xbe\xef" * 128)
        subprocess.run(
            ["objcopy",
             "--add-section", f".debug_info={garbage}",
             "--add-section", f".debug_abbrev={garbage}",
             str(binary)],
            check=True, timeout=60,
        )
        result = probe_binary(binary)
        assert result["probe"] == "readelf"
        assert result["has_dwarf"] is False
        # ... and the IMPORTED-split refinement therefore never
        # upgrades a provisional symtab tag on this file.
        db = REDatabase(
            source_tool="ghidra",
            binary_path=str(binary),
            functions=[REFunction(
                name="f1", address=0x1000, size=64,
                source_tool="ghidra", name_provenance="symtab",
            )],
        )
        from core.analysis.binary_provenance import (
            refine_import_provenance,
        )
        refine_import_provenance(db)
        assert db.functions[0].name_provenance != "dwarf"


# ── IMPORTED split refinement ────────────────────────────────────────


class TestRefineImportProvenance:
    def _db(self, tag="symtab", tool="ghidra", binary_path="/x/bin"):
        return REDatabase(
            source_tool=tool,
            binary_path=binary_path,
            functions=[
                REFunction(name="f1", address=0x1000, size=64,
                           source_tool=tool, name_provenance=tag),
            ],
        )

    def _probe(self, monkeypatch, result):
        import core.analysis.binary_provenance as bp

        monkeypatch.setattr(bp, "probe_binary", lambda p: dict(result))

    def test_dwarf_binary_upgrades_provisional_symtab(
            self, monkeypatch, tmp_path):
        from core.analysis.binary_provenance import (
            refine_import_provenance,
        )

        binary = tmp_path / "bin"
        binary.write_bytes(b"\x7fELF" + b"\0" * 12)
        self._probe(monkeypatch, {
            "probe": "readelf", "build_id": "ab12",
            "has_dwarf": True, "has_symtab": True, "has_dynsym": True,
        })
        db = self._db(binary_path=str(binary))
        assert refine_import_provenance(db) == 1
        assert db.functions[0].name_provenance == "dwarf"
        assert db.metadata["name_provenance_probe"]["has_dwarf"] is True

    def test_dynsym_only_binary_downgrades_to_dynsym_plt(
            self, monkeypatch, tmp_path):
        from core.analysis.binary_provenance import (
            refine_import_provenance,
        )

        binary = tmp_path / "bin"
        binary.write_bytes(b"\x7fELF" + b"\0" * 12)
        self._probe(monkeypatch, {
            "probe": "readelf", "build_id": None,
            "has_dwarf": False, "has_symtab": False, "has_dynsym": True,
        })
        db = self._db(binary_path=str(binary))
        assert refine_import_provenance(db) == 1
        assert db.functions[0].name_provenance == "dynsym_plt"

    def test_probe_unavailable_leaves_conservative_tag(
            self, monkeypatch, tmp_path):
        from core.analysis.binary_provenance import (
            refine_import_provenance,
        )

        binary = tmp_path / "bin"
        binary.write_bytes(b"\x7fELF" + b"\0" * 12)
        self._probe(monkeypatch, {"probe": "unavailable"})
        db = self._db(binary_path=str(binary))
        assert refine_import_provenance(db) == 0
        assert db.functions[0].name_provenance == "symtab"

    def test_missing_binary_never_retags(self, monkeypatch):
        from core.analysis.binary_provenance import (
            refine_import_provenance,
        )

        db = self._db(binary_path="/nonexistent/path/bin")
        assert refine_import_provenance(db) == 0
        assert db.functions[0].name_provenance == "symtab"

    def test_r2_per_name_tags_never_rewritten(self, monkeypatch, tmp_path):
        """r2's dbg./sym. tags are per-NAME facts; the per-binary
        split must not repaint them."""
        from core.analysis.binary_provenance import (
            refine_import_provenance,
        )

        binary = tmp_path / "bin"
        binary.write_bytes(b"\x7fELF" + b"\0" * 12)
        self._probe(monkeypatch, {
            "probe": "readelf", "build_id": None,
            "has_dwarf": True, "has_symtab": True, "has_dynsym": True,
        })
        db = self._db(tag="symtab", tool="r2", binary_path=str(binary))
        assert refine_import_provenance(db) == 0
        assert db.functions[0].name_provenance == "symtab"
