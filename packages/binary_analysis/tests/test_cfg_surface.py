"""Tests for the per-function CFG / cyclomatic surface in binary analysis.

r2-free: drives ``_extract_function_cfgs`` with a fake r2 handle and
checks the ``cyclomatic`` field's serialisation contract — populated
only under ``extract_cfgs=True``, absent from default-run output.
"""

import json
from pathlib import Path

from packages.binary_analysis import function_cfg
from packages.binary_analysis.radare2_understand import (
    BinaryContextMap,
    BinaryUnderstand,
    FunctionInfo,
)

# afbj-style basic-block shapes ---------------------------------------------

_LOOP = [  # while loop: cyclomatic 1
    {"addr": 0x100, "jump": 0x110},
    {"addr": 0x110, "jump": 0x120, "fail": 0x130},
    {"addr": 0x120, "jump": 0x110},
    {"addr": 0x130},
]
_SPIN = [{"addr": 0x200, "jump": 0x200}]  # single-block self-loop: cyclomatic 1


class _FakeR2:
    """Minimal r2 stand-in: answers ``afbj @ <addr>`` from a canned map."""

    def __init__(self, blocks_by_addr):
        self._blocks = blocks_by_addr

    def cmd(self, command):
        addr = int(command.split("@")[1].strip())
        return json.dumps(self._blocks.get(addr, []))


def _understand(binary: Path) -> BinaryUnderstand:
    u = BinaryUnderstand.__new__(BinaryUnderstand)
    u.binary = binary
    return u


def _ctx(binary: Path, fns) -> BinaryContextMap:
    ctx = BinaryContextMap(binary_path=binary)
    ctx.interesting_functions = fns
    return ctx


class TestExtractFunctionCfgs:
    def test_populates_cfg_and_cyclomatic(self, tmp_path, monkeypatch):
        monkeypatch.setattr(function_cfg, "_cache_dir", lambda: tmp_path / "cache")
        binary = tmp_path / "t.bin"
        binary.write_bytes(b"\x7fELF fake")
        fns = [FunctionInfo(name="loop_fn", address=0x100),
               FunctionInfo(name="spin_fn", address=0x200)]
        ctx = _ctx(binary, fns)
        _understand(binary)._extract_function_cfgs(
            _FakeR2({0x100: _LOOP, 0x200: _SPIN}), ctx)
        loop_fn, spin_fn = fns
        assert loop_fn.basic_block_cfg is not None
        assert loop_fn.basic_block_cfg.block_count == 4
        assert loop_fn.cyclomatic == 1
        # Self-loop regression: the spin function keeps its self-edge and
        # reports McCabe 1, not 0.
        assert spin_fn.basic_block_cfg.successors(0x200) == [0x200]
        assert spin_fn.cyclomatic == 1

    def test_imported_functions_skipped(self, tmp_path, monkeypatch):
        monkeypatch.setattr(function_cfg, "_cache_dir", lambda: tmp_path / "cache")
        binary = tmp_path / "t.bin"
        binary.write_bytes(b"\x7fELF fake")
        imp = FunctionInfo(name="sym.imp.strcpy", address=0x300, is_imported=True)
        ctx = _ctx(binary, [imp])
        _understand(binary)._extract_function_cfgs(_FakeR2({}), ctx)
        assert imp.basic_block_cfg is None
        assert imp.cyclomatic is None

    def test_failure_on_one_function_is_isolated(self, tmp_path, monkeypatch):
        monkeypatch.setattr(function_cfg, "_cache_dir", lambda: tmp_path / "cache")
        binary = tmp_path / "t.bin"
        binary.write_bytes(b"\x7fELF fake")

        class _BrokenThenGood(_FakeR2):
            def cmd(self, command):
                if "256" in command:  # 0x100 — first function wedges
                    raise TimeoutError("afbj wedged")
                return super().cmd(command)

        fns = [FunctionInfo(name="bad", address=0x100),
               FunctionInfo(name="good", address=0x200)]
        ctx = _ctx(binary, fns)
        _understand(binary)._extract_function_cfgs(
            _BrokenThenGood({0x200: _SPIN}), ctx)
        assert fns[0].basic_block_cfg is None
        assert fns[0].cyclomatic is None
        assert fns[1].cyclomatic == 1

    def test_second_run_hits_cache(self, tmp_path, monkeypatch):
        monkeypatch.setattr(function_cfg, "_cache_dir", lambda: tmp_path / "cache")
        binary = tmp_path / "t.bin"
        binary.write_bytes(b"\x7fELF fake")
        ctx1 = _ctx(binary, [FunctionInfo(name="loop_fn", address=0x100)])
        _understand(binary)._extract_function_cfgs(_FakeR2({0x100: _LOOP}), ctx1)

        class _RefusingR2:
            def cmd(self, command):
                raise AssertionError("afbj re-issued despite warm cache")

        ctx2 = _ctx(binary, [FunctionInfo(name="loop_fn", address=0x100)])
        _understand(binary)._extract_function_cfgs(_RefusingR2(), ctx2)
        assert ctx2.interesting_functions[0].cyclomatic == 1

    def test_empty_cfg_leaves_cyclomatic_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(function_cfg, "_cache_dir", lambda: tmp_path / "cache")
        binary = tmp_path / "t.bin"
        binary.write_bytes(b"\x7fELF fake")
        fn = FunctionInfo(name="ghost", address=0x400)
        ctx = _ctx(binary, [fn])
        _understand(binary)._extract_function_cfgs(_FakeR2({}), ctx)  # afbj -> []
        assert fn.basic_block_cfg is not None
        assert fn.basic_block_cfg.block_count == 0
        assert fn.cyclomatic is None


class TestToDictSurfacing:
    def test_cyclomatic_absent_by_default(self):
        ctx = _ctx(Path("/tmp/x.bin"), [FunctionInfo(name="plain", address=0x1)])
        d = ctx.to_dict()
        assert "cyclomatic" not in d["interesting_functions"][0]

    def test_cyclomatic_present_when_computed(self):
        fn = FunctionInfo(name="loop_fn", address=0x1)
        fn.cyclomatic = 3
        ctx = _ctx(Path("/tmp/x.bin"), [fn])
        d = ctx.to_dict()
        assert d["interesting_functions"][0]["cyclomatic"] == 3

    def test_cyclomatic_zero_is_emitted(self):
        # 0 is a real measurement (straight-line function), not "absent".
        fn = FunctionInfo(name="line_fn", address=0x2)
        fn.cyclomatic = 0
        ctx = _ctx(Path("/tmp/x.bin"), [fn])
        d = ctx.to_dict()
        assert d["interesting_functions"][0]["cyclomatic"] == 0
