"""Tests for the audit's binary context assembly and routing."""

from pathlib import Path

from core.audit.binary_context import assemble_binary_context
from core.inventory.binary_builder import (
    BINARY_PATH_PREFIX,
    binary_path_key,
    is_binary_item,
)
from packages.ghidra.model import REDatabase, REFunction, REXref


def _make_func(name, addr, size=64, decomp=None, signature=None):
    return REFunction(
        name=name, address=addr, size=size,
        source_tool="ghidra",
        decompilation=decomp, signature=signature,
    )


def _make_db(functions=None, xrefs=None):
    return REDatabase(
        source_tool="ghidra",
        binary_path="/x/target",
        functions=functions or [],
        xrefs=xrefs or [],
    )


class TestIsBinaryItem:
    def test_sentinel_detected(self):
        assert is_binary_item({"file": "binary:target", "name": "main"})

    def test_address_detected(self):
        assert is_binary_item({"file": "", "name": "f", "address": 0x1000})

    def test_address_zero_detected(self):
        assert is_binary_item({"file": "", "name": "f", "address": 0})

    def test_source_item_not_binary(self):
        assert not is_binary_item(
            {"file": "src/main.c", "name": "main", "line_start": 10},
        )

    def test_key_matches_predicate(self):
        assert is_binary_item({"file": binary_path_key("/x/target")})


class TestAssembleBinaryContext:
    def _checklist(self, func_name, address):
        return {
            "files": [{
                "path": "binary:target",
                "items": [{
                    "name": func_name,
                    "kind": "function",
                    "address": address,
                    "size": 64,
                    "metadata": {"address": address, "size": 64},
                }],
            }],
        }

    def test_decompilation_becomes_source(self):
        func = _make_func(
            "vuln", 0x1000,
            decomp="void vuln(char *s) { strcpy(buf, s); }",
        )
        ctx = assemble_binary_context(
            target_path=Path("/x/target"),
            file_path="binary:target",
            function_name="vuln",
            checklist=self._checklist("vuln", 0x1000),
            db=_make_db(functions=[func]),
        )
        assert ctx["is_binary"] is True
        assert ctx["address"] == 0x1000
        assert "strcpy" in ctx["source"]
        assert ctx["representation"] == "decompilation"
        assert ctx["line_start"] == 0

    def test_stub_when_no_decompilation(self):
        func = _make_func("stub", 0x1000)
        ctx = assemble_binary_context(
            target_path=Path("/x/target"),
            file_path="binary:target",
            function_name="stub",
            checklist=self._checklist("stub", 0x1000),
            db=_make_db(functions=[func]),
        )
        assert ctx["representation"] == "stub"
        assert "no decompilation" in ctx["source"]

    def test_callers_callees_from_xrefs(self):
        target = _make_func("target_fn", 0x1000, decomp="x")
        caller = _make_func("caller_fn", 0x2000)
        callee = _make_func("callee_fn", 0x3000, decomp="y")
        xrefs = [
            REXref(from_addr=0x2000, to_addr=0x1000, kind="call"),
            REXref(from_addr=0x1000, to_addr=0x3000, kind="call"),
        ]
        ctx = assemble_binary_context(
            target_path=Path("/x/target"),
            file_path="binary:target",
            function_name="target_fn",
            checklist=self._checklist("target_fn", 0x1000),
            db=_make_db(functions=[target, caller, callee], xrefs=xrefs),
        )
        assert [c["name"] for c in ctx["callers"]] == ["caller_fn"]
        assert [c["name"] for c in ctx["callees"]] == ["callee_fn"]
        assert ctx["callees"][0]["source_snippet"] == "y"
        assert ctx["callers"][0]["file"].startswith(BINARY_PATH_PREFIX)

    def test_name_lookup_when_address_missing(self):
        func = _make_func("by_name", 0x4000, decomp="z")
        ctx = assemble_binary_context(
            target_path=Path("/x/target"),
            file_path="binary:target",
            function_name="by_name",
            checklist=None,
            db=_make_db(functions=[func]),
        )
        assert ctx["address"] == 0x4000
        assert ctx["source"] == "z"

    def test_missing_function_degrades(self):
        ctx = assemble_binary_context(
            target_path=Path("/x/target"),
            file_path="binary:target",
            function_name="ghost",
            checklist=None,
            db=_make_db(),
        )
        assert ctx["representation"] == "unknown"
        assert "not found" in ctx["source"]

    def test_prompt_formatting_end_to_end(self):
        from core.audit.context import format_context_for_prompt
        func = _make_func(
            "vuln", 0x1000,
            decomp="void vuln(char *s) { strcpy(buf, s); }",
            signature="void vuln(char *s)",
        )
        ctx = assemble_binary_context(
            target_path=Path("/x/target"),
            file_path="binary:target",
            function_name="vuln",
            checklist=self._checklist("vuln", 0x1000),
            db=_make_db(functions=[func]),
        )
        prompt = format_context_for_prompt(ctx)
        assert "decompilation at 0x1000" in prompt
        assert "strcpy" in prompt


class TestAssembleContextDispatch:
    def test_binary_sentinel_routes_to_binary_assembler(self, tmp_path):
        from core.audit.context import assemble_context
        # No REDatabase anywhere — the binary branch still returns the
        # binary shape (degraded source) instead of "(file not found)".
        ctx = assemble_context(
            target_path=tmp_path,
            file_path="binary:target",
            function_name="main",
            line_start=0,
            out_dir=tmp_path,
        )
        assert ctx["is_binary"] is True
        assert "file not found" not in ctx["source"]
