"""Tests for context_map_imports — mechanical import extraction."""
from __future__ import annotations

from core.orchestration.context_map_imports import (
    _resolve_relative_import,
    enrich_context_map_imports,
    extract_imports_from_checklist,
)


def _checklist(*file_entries):
    return {"files": list(file_entries)}


def _file(path, imports=None, relative_imports=None, excluded=False):
    entry = {"path": path}
    if excluded:
        entry["_excluded"] = True
    cg = {}
    if imports is not None:
        cg["imports"] = imports
    if relative_imports is not None:
        cg["relative_imports"] = relative_imports
    if cg:
        entry["call_graph"] = cg
    return entry


# ── _resolve_relative_import ──────────────────────────────────────


class TestResolveRelativeImport:
    def test_level_1_same_package(self):
        r = _resolve_relative_import("src/auth/views.py", 1, "models", "User")
        assert r == "auth.models.User"

    def test_level_1_no_module(self):
        r = _resolve_relative_import("src/auth/views.py", 1, "", "utils")
        assert r == "auth.utils"

    def test_level_2_parent_package(self):
        r = _resolve_relative_import("src/auth/views.py", 2, "utils", "helper")
        assert r == "utils.helper"

    def test_level_exceeds_depth(self):
        r = _resolve_relative_import("src/auth/views.py", 4, "", "x")
        assert r is None

    def test_root_level_file(self):
        r = _resolve_relative_import("views.py", 1, "models", "User")
        assert r == "models.User"

    def test_root_level_file_level_2_fails(self):
        r = _resolve_relative_import("views.py", 2, "", "x")
        assert r is None

    def test_negative_level(self):
        assert _resolve_relative_import("a/b.py", -1, "", "x") is None

    def test_zero_level(self):
        assert _resolve_relative_import("a/b.py", 0, "", "x") is None

    def test_deep_nesting(self):
        r = _resolve_relative_import(
            "src/pkg/sub/deep/mod.py", 1, "sibling", "Cls",
        )
        assert r == "pkg.sub.deep.sibling.Cls"

    def test_deep_nesting_level_3(self):
        r = _resolve_relative_import(
            "src/pkg/sub/deep/mod.py", 3, "", "top_util",
        )
        assert r == "pkg.top_util"

    def test_src_strip_applied(self):
        r = _resolve_relative_import("src/mypackage/mod.py", 1, "", "util")
        assert r == "mypackage.util"

    def test_no_src_strip_for_non_src(self):
        r = _resolve_relative_import("lib/mypackage/mod.py", 1, "", "util")
        assert r == "lib.mypackage.util"

    def test_dotted_module(self):
        r = _resolve_relative_import("src/pkg/mod.py", 1, "sub.deep", "Cls")
        assert r == "pkg.sub.deep.Cls"

    def test_init_py(self):
        r = _resolve_relative_import(
            "src/auth/__init__.py", 1, "models", "User",
        )
        assert r == "auth.models.User"


# ── extract_imports_from_checklist ────────────────────────────────


class TestExtractImports:
    def test_empty_checklist(self):
        assert extract_imports_from_checklist({}) == []

    def test_no_files(self):
        assert extract_imports_from_checklist({"files": []}) == []

    def test_single_file_single_import(self):
        cl = _checklist(_file("src/auth.py", {"bcrypt": "bcrypt"}))
        result = extract_imports_from_checklist(cl)
        assert result == [{"module": "bcrypt", "file": "src/auth.py"}]

    def test_qualified_import(self):
        cl = _checklist(_file("src/app.py", {
            "Flask": "flask.Flask",
            "jsonify": "flask.jsonify",
        }))
        result = extract_imports_from_checklist(cl)
        assert len(result) == 2
        modules = {r["module"] for r in result}
        assert modules == {"flask.Flask", "flask.jsonify"}

    def test_multiple_files(self):
        cl = _checklist(
            _file("src/a.py", {"os": "os"}),
            _file("src/b.py", {"sys": "sys"}),
        )
        result = extract_imports_from_checklist(cl)
        assert len(result) == 2
        assert result[0]["file"] == "src/a.py"
        assert result[1]["file"] == "src/b.py"

    def test_same_module_different_files(self):
        cl = _checklist(
            _file("src/a.py", {"requests": "requests"}),
            _file("src/b.py", {"requests": "requests"}),
        )
        result = extract_imports_from_checklist(cl)
        assert len(result) == 2

    def test_excluded_files_skipped(self):
        cl = _checklist(
            _file("src/a.py", {"os": "os"}),
            _file("vendor/lib.py", {"x": "x"}, excluded=True),
        )
        result = extract_imports_from_checklist(cl)
        assert len(result) == 1
        assert result[0]["file"] == "src/a.py"

    def test_no_call_graph(self):
        cl = _checklist({"path": "src/a.py"})
        assert extract_imports_from_checklist(cl) == []

    def test_empty_imports(self):
        cl = _checklist(_file("src/a.py", {}))
        assert extract_imports_from_checklist(cl) == []

    def test_dedup_same_module_same_file(self):
        cl = _checklist(_file("src/a.py", {
            "r": "requests",
            "requests": "requests",
        }))
        result = extract_imports_from_checklist(cl)
        assert len(result) == 1

    def test_sorted_output(self):
        cl = _checklist(
            _file("src/z.py", {"b": "b_mod"}),
            _file("src/a.py", {"a": "a_mod"}),
        )
        result = extract_imports_from_checklist(cl)
        assert result[0]["file"] == "src/a.py"
        assert result[1]["file"] == "src/z.py"

    def test_empty_module_skipped(self):
        cl = _checklist(_file("src/a.py", {"x": ""}))
        assert extract_imports_from_checklist(cl) == []

    # ── relative imports ──

    def test_relative_import_resolved(self):
        cl = _checklist(_file(
            "src/auth/views.py",
            relative_imports=[[1, "models", "User", None]],
        ))
        result = extract_imports_from_checklist(cl)
        assert len(result) == 1
        assert result[0] == {
            "module": "auth.models.User", "file": "src/auth/views.py",
        }

    def test_relative_and_absolute_combined(self):
        cl = _checklist(_file(
            "src/auth/views.py",
            imports={"bcrypt": "bcrypt"},
            relative_imports=[[1, "models", "User", None]],
        ))
        result = extract_imports_from_checklist(cl)
        assert len(result) == 2
        modules = {r["module"] for r in result}
        assert modules == {"bcrypt", "auth.models.User"}

    def test_relative_import_dedup_with_absolute(self):
        cl = _checklist(_file(
            "src/auth/views.py",
            imports={"User": "auth.models.User"},
            relative_imports=[[1, "models", "User", None]],
        ))
        result = extract_imports_from_checklist(cl)
        assert len(result) == 1

    def test_relative_import_malformed_skipped(self):
        cl = _checklist(_file(
            "src/a.py",
            relative_imports=[
                [1, "models", "User", None],  # valid
                [1],                           # too short
                "not a list",                  # wrong type
                [0, "x", "y", None],           # level 0
            ],
        ))
        result = extract_imports_from_checklist(cl)
        assert len(result) == 1

    def test_relative_import_unresolvable_skipped(self):
        cl = _checklist(_file(
            "mod.py",
            relative_imports=[[3, "", "x", None]],
        ))
        assert extract_imports_from_checklist(cl) == []


# ── enrich_context_map_imports ────────────────────────────────────


class TestEnrichContextMap:
    def test_enriches(self):
        cm: dict = {"sources": []}
        cl = _checklist(_file("src/a.py", {"os": "os"}))
        count = enrich_context_map_imports(cm, cl)
        assert count == 1
        assert cm["imports"] == [{"module": "os", "file": "src/a.py"}]

    def test_no_imports_returns_zero(self):
        cm: dict = {"sources": []}
        count = enrich_context_map_imports(cm, _checklist())
        assert count == 0
        assert "imports" not in cm

    def test_overwrites_existing(self):
        cm: dict = {"imports": [{"module": "old", "file": "old.py"}]}
        cl = _checklist(_file("src/a.py", {"new": "new_mod"}))
        enrich_context_map_imports(cm, cl)
        assert len(cm["imports"]) == 1
        assert cm["imports"][0]["module"] == "new_mod"
