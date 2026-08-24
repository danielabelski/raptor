"""Binary-target fuzz coverage: PC traces onto the binary checklist."""

import json
import struct

from packages.fuzzing.coverage_bridge import (
    emit_binary_fuzz_coverage,
    find_pc_dumps,
)


def _checklist(tmp_path):
    cl = {
        "target_path": str(tmp_path / "t"),
        "target_kind": "binary",
        "files": [{
            "path": "binary:t",
            "language": "binary",
            "sha256": "ab" * 32,
            "items": [
                {"name": "vuln", "kind": "function",
                 "address": 0x1000, "size": 0x80},
                {"name": "quiet", "kind": "function",
                 "address": 0x2000, "size": 0x80},
            ],
        }],
    }
    (tmp_path / "checklist.json").write_text(json.dumps(cl))
    return cl


def _sancov(path, pcs):
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", 0xC0BFFFFFFFFFFF64))
        for pc in pcs:
            f.write(struct.pack("<Q", pc))


class TestBinaryFuzzCoverage:
    def test_pcs_map_to_functions(self, tmp_path):
        _checklist(tmp_path)
        binary = tmp_path / "t"
        binary.write_bytes(b"\x7fELF")
        _sancov(tmp_path / "run.sancov", [0x1004, 0x1040])

        out = emit_binary_fuzz_coverage(
            tmp_path, binary=binary, iterations=7, crashes=1,
        )
        assert out is not None
        doc = json.loads(out.read_text())
        funcs = doc["files"]["binary:t"]["functions"]
        assert set(funcs) == {"vuln"}
        assert funcs["vuln"]["pcs"] == 2
        assert doc["tool"] == "fuzz"
        assert doc["functions_analysed"] == [
            {"file": "binary:t", "function": "vuln"},
        ]

    def test_no_traces_no_output(self, tmp_path):
        _checklist(tmp_path)
        binary = tmp_path / "t"
        binary.write_bytes(b"\x7fELF")
        assert emit_binary_fuzz_coverage(tmp_path, binary=binary) is None

    def test_no_binary_checklist_no_output(self, tmp_path):
        binary = tmp_path / "t"
        binary.write_bytes(b"\x7fELF")
        _sancov(tmp_path / "run.sancov", [0x1004])
        assert emit_binary_fuzz_coverage(tmp_path, binary=binary) is None

    def test_out_of_range_pcs_ignored(self, tmp_path):
        _checklist(tmp_path)
        binary = tmp_path / "t"
        binary.write_bytes(b"\x7fELF")
        _sancov(tmp_path / "run.sancov", [0x9999])
        assert emit_binary_fuzz_coverage(tmp_path, binary=binary) is None

    def test_dump_discovery(self, tmp_path):
        (tmp_path / "a.sancov").write_bytes(b"")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "b.drcov").write_bytes(b"")
        found = {p.name for p in find_pc_dumps(tmp_path)}
        assert found == {"a.sancov", "b.drcov"}

    def test_drcov_module_filtered_and_rebased(self, tmp_path):
        _checklist(tmp_path)
        binary = tmp_path / "t"
        binary.write_bytes(b"\x7fELF")
        # minimal drcov: module table + one BB record for our module
        # (module-relative offset 0x1004 with base 0 = file-relative).
        header = (
            "DRCOV VERSION: 2\n"
            "Module Table: version 2, count 2\n"
            "Columns: id, base, end, entry, path\n"
            f"0, 0x0, 0x5000, 0x0, {binary}\n"
            "1, 0x7f0000000000, 0x7f0000100000, 0x0, /lib/other.so\n"
            "BB Table: 2 bbs\n"
        )
        import struct as _struct
        with open(tmp_path / "trace.drcov", "wb") as f:
            f.write(header.encode())
            f.write(_struct.pack("<IHH", 0x1004, 8, 0))   # ours
            f.write(_struct.pack("<IHH", 0x2004, 8, 1))   # other module
        out = emit_binary_fuzz_coverage(tmp_path, binary=binary)
        assert out is not None
        doc = json.loads(out.read_text())
        funcs = doc["files"]["binary:t"]["functions"]
        # only OUR module's PC mapped; the other module's 0x2004
        # (which collides with 'quiet') must not leak in.
        assert set(funcs) == {"vuln"}
