"""b37: taint-free fold tier, cross-file static-final / returns-literal
resolution, and the string-op fold extensions — boundary discipline
first (TAINT_FREE must never escape a value-only consumer)."""
from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.const_fold_java import (  # noqa: E402
    REFUSE,
    TAINT_FREE,
    JavaConstIndex,
    definers_all_fold,
    fold_expr,
    fold_expr_at,
)
from core.analysis.java_xfile_const import make_xfile_resolver  # noqa: E402


def _expr_node(expr: str, decls: str = ""):
    src = ("public class T {\n    public void m(String x) {\n"
           + decls
           + f"        Object r = {expr};\n"
           + "    }\n}\n")
    from core.analysis.cfg_builder_java import _get_parser
    tree = _get_parser().parse(src.encode())
    nodes = []

    def find(n):
        if n.type == "variable_declarator":
            name = n.child_by_field_name("name")
            if name is not None and name.text.decode() == "r":
                nodes.append(n.child_by_field_name("value"))
        for c in n.children:
            find(c)

    find(tree.root_node)
    assert nodes, "fixture must contain the r declarator"
    return nodes[0]


def _fold(expr: str, allow_tf: bool = False, xfile=None):
    return fold_expr(_expr_node(expr), lambda _n, _d: REFUSE,
                     allow_taint_free=allow_tf, xfile_resolver=xfile)


class TestTaintFreeBoundary:
    def test_system_getproperty_refuses_by_default(self):
        assert _fold('System.getProperty("user.dir")') is REFUSE

    def test_system_getproperty_refuses_without_write_proof(self):
        # System properties are runtime-writable; without the
        # cross-file resolver's tree-wide no-setProperty proof a
        # property read is NOT taint-free (the b22 corpus fixture pins
        # the gate-level consequence).
        assert _fold('System.getProperty("user.dir")',
                     allow_tf=True) is REFUSE

    def test_getenv_literal_tf(self):
        # No self-write API for the environment — unconditionally
        # taint-free, no scan needed.
        assert _fold('System.getenv("HOME")', allow_tf=True) is TAINT_FREE

    def test_variable_property_name_refuses(self):
        assert _fold("System.getProperty(x)", allow_tf=True) is REFUSE

    def test_file_separator_tf(self):
        assert _fold("File.separator", allow_tf=True) is TAINT_FREE
        assert _fold("File.separator") is REFUSE

    def test_non_system_receiver_refuses(self):
        assert _fold('request.getProperty("a")', allow_tf=True) is REFUSE


class TestTaintFreeAlgebra:
    def test_concat_tf_with_constant_is_tf(self):
        assert _fold('System.getenv("HOME") + "x"',
                     allow_tf=True) is TAINT_FREE

    def test_concat_tf_with_unfoldable_refuses(self):
        assert _fold('System.getenv("HOME") + x',
                     allow_tf=True) is REFUSE

    def test_comparison_on_tf_refuses(self):
        assert _fold('System.getenv("OS") == "Linux"',
                     allow_tf=True) is REFUSE

    def test_ternary_join_both_branches_const_is_tf(self):
        assert _fold('x != null ? "a" : "b"', allow_tf=True) is TAINT_FREE

    def test_ternary_join_refuses_without_opt_in(self):
        assert _fold('x != null ? "a" : "b"') is REFUSE

    def test_ternary_join_tainted_branch_refuses(self):
        assert _fold('x != null ? "a" : x', allow_tf=True) is REFUSE


class TestStringOps:
    def test_substring_folds(self):
        assert _fold('"constant".substring(2)') == "nstant"
        assert _fold('"constant".substring(1, 3)') == "on"

    def test_substring_out_of_bounds_refuses(self):
        assert _fold('"abc".substring(9)') is REFUSE

    def test_case_ops_ascii_only(self):
        assert _fold('"MiXeD".toLowerCase()') == "mixed"
        assert _fold('"MiXeD".toUpperCase()') == "MIXED"

    def test_case_op_with_locale_arg_refuses(self):
        assert _fold('"A".toLowerCase(java.util.Locale.US)') is REFUSE

    def test_trim_and_concat(self):
        assert _fold('" a ".trim()') == "a"
        assert _fold('"a".concat("b")') == "ab"

    def test_string_valueof(self):
        assert _fold("String.valueOf(42)") == "42"
        assert _fold("String.valueOf(true)") == "true"

    def test_ops_on_tf_receiver_stay_tf(self):
        v = _fold('System.getenv("HOME").substring(1)', allow_tf=True)
        assert v is TAINT_FREE
        assert _fold('System.getenv("HOME").substring(1)') is REFUSE


# ---- cross-file fixtures ------------------------------------------------


CFG_CLASS = (
    "package app;\n"
    "import java.io.File;\n"
    "public class Cfg {\n"
    '    public static final String SAFE = "safe-const";\n'
    '    public static final String BASE = SAFE + "-2";\n'
    "    public static final String USERDIR = "
    'System.getProperty("user.dir") + File.separator;\n'
    '    public static String MUTABLE = "not-final";\n'
    '    public String getTheValue(String p) { return "bar"; }\n'
    '    public String echo(String p) { return p; }\n'
    '    public String twoStmt(String p) { String a = "x"; return a; }\n'
    "}\n"
)

CALLER = (
    "package app;\n"
    "public class T {\n"
    "    public void m(String x) {\n"
    "        Object r = REPLACED;\n"
    "    }\n"
    "}\n"
)


@pytest.fixture()
def xroot(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "Cfg.java").write_text(CFG_CLASS, encoding="utf-8")
    caller = tmp_path / "app" / "T.java"
    caller.write_text(CALLER, encoding="utf-8")
    return tmp_path, caller


def _xfold(xroot, expr: str, allow_tf: bool = False, decls: str = ""):
    root, caller = xroot
    caller.write_text(CALLER.replace("REPLACED", expr), encoding="utf-8")
    xfile = make_xfile_resolver(str(caller), str(root))
    assert xfile is not None
    return _fold(expr, allow_tf=allow_tf, xfile=xfile), xfile


class TestCrossFileField:
    def test_literal_static_final_folds(self, xroot):
        v, _ = _xfold(xroot, "Cfg.SAFE")
        assert v == "safe-const"

    def test_recursive_static_final_folds(self, xroot):
        v, _ = _xfold(xroot, "Cfg.BASE")
        assert v == "safe-const-2"

    def test_tf_initializer_is_tf_only_with_opt_in(self, xroot):
        v, _ = _xfold(xroot, "Cfg.USERDIR", allow_tf=True)
        assert v is TAINT_FREE
        v2, _ = _xfold(xroot, "Cfg.USERDIR")
        assert v2 is REFUSE

    def test_non_final_field_refuses(self, xroot):
        v, _ = _xfold(xroot, "Cfg.MUTABLE")
        assert v is REFUSE

    def test_unknown_class_refuses(self, xroot):
        v, _ = _xfold(xroot, "Nope.SAFE")
        assert v is REFUSE

    def test_ambiguous_class_refuses(self, xroot, tmp_path):
        (tmp_path / "b").mkdir()
        (tmp_path / "b" / "Cfg.java").write_text(
            CFG_CLASS, encoding="utf-8")
        v, _ = _xfold(xroot, "Cfg.SAFE")
        assert v is REFUSE


class TestCrossFileMethod:
    def test_returns_literal_via_creation(self, xroot):
        v, _ = _xfold(xroot, 'new Cfg().getTheValue("k")')
        assert v == "bar"

    def test_returns_param_refuses(self, xroot):
        v, _ = _xfold(xroot, 'new Cfg().echo("k")')
        assert v is REFUSE

    def test_multi_statement_body_refuses(self, xroot):
        v, _ = _xfold(xroot, 'new Cfg().twoStmt("k")')
        assert v is REFUSE

    def test_creation_typed_local_receiver(self, xroot, tmp_path):
        root, caller = xroot
        src = (
            "package app;\n"
            "public class T {\n"
            "    public void m(String x) {\n"
            "        Cfg scr = new Cfg();\n"
            '        Object r = scr.getTheValue("k");\n'
            "    }\n"
            "}\n"
        )
        caller.write_text(src, encoding="utf-8")
        n_lines = src.count("\n") + 1
        index = JavaConstIndex(src, (1, n_lines),
                               java_file_path=str(caller),
                               repo_root=str(root))
        assert index.receiver_type("scr") == "Cfg"
        assert index.xfile is not None

    def test_reassigned_receiver_poisons_type(self):
        src = (
            "public class T { public void m(Object o) {\n"
            "    Cfg scr = new Cfg();\n"
            "    scr = other();\n"
            "} }\n"
        )
        index = JavaConstIndex(src, (1, 5))
        assert index.receiver_type("scr") is None


class TestGateConsumers:
    def _rd_setup(self, decls: str, use: str):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        from core.analysis.dataflow import reaching_defs
        src = ("public class T {\n"
               "    public void m(String x) {\n"
               + decls
               + f"        sink({use});\n"
               "    }\n"
               "}\n")
        graph = build_java_intraproc_cfg(src, "m")
        assert graph is not None
        n_lines = src.count("\n") + 1
        index = JavaConstIndex(src, (1, n_lines))
        rd = reaching_defs(graph)
        sink_node = None
        for n in graph.nodes():
            if getattr(n, "lineno", 0) == src.count("\n") - 2:
                sink_node = n
        assert sink_node is not None
        return rd, sink_node, index

    def test_definers_all_fold_accepts_tf(self):
        rd, sink, index = self._rd_setup(
            '        String v = System.getenv("HOME");\n', "v")
        assert definers_all_fold(rd, sink, "v", index)

    def test_fold_expr_at_stays_value_only_by_default(self):
        from core.analysis.cfg_builder_java import _get_parser
        src = ("public class T {\n"
               "    public void m(String x) {\n"
               '        String v = System.getenv("HOME");\n'
               "        sink(v);\n"
               "    }\n"
               "}\n")
        rd, sink, index = self._rd_setup(
            '        String v = System.getenv("HOME");\n', "v")
        tree = _get_parser().parse(src.encode())
        exprs = []

        def find(n):
            if n.type == "method_invocation" and n.text.decode(
                    ).startswith("System.getenv"):
                exprs.append(n)
            for ch in n.children:
                find(ch)

        find(tree.root_node)
        # Value-only consumers (switch pruning, weak-name matching)
        # must never see TAINT_FREE.
        assert fold_expr_at(rd, sink, exprs[0], index) is REFUSE


class TestPropertyWriteScan:
    def test_clean_tree_allows_property_tf(self, xroot):
        v, _ = _xfold(xroot, 'System.getProperty("user.dir")',
                      allow_tf=True)
        assert v is TAINT_FREE

    def test_written_key_refuses(self, xroot, tmp_path):
        (tmp_path / "app" / "W.java").write_text(
            "package app;\npublic class W {\n"
            "    void w(String t) { "
            'System.setProperty("user.dir", t); }\n}\n',
            encoding="utf-8")
        v, _ = _xfold(xroot, 'System.getProperty("user.dir")',
                      allow_tf=True)
        assert v is REFUSE

    def test_written_other_key_still_tf(self, xroot, tmp_path):
        (tmp_path / "app" / "W.java").write_text(
            "package app;\npublic class W {\n"
            "    void w(String t) { "
            'System.setProperty("other.key", t); }\n}\n',
            encoding="utf-8")
        v, _ = _xfold(xroot, 'System.getProperty("user.dir")',
                      allow_tf=True)
        assert v is TAINT_FREE

    def test_variable_key_poisons_all(self, xroot, tmp_path):
        (tmp_path / "app" / "W.java").write_text(
            "package app;\npublic class W {\n"
            "    void w(String k, String t) { "
            "System.setProperty(k, t); }\n}\n",
            encoding="utf-8")
        v, _ = _xfold(xroot, 'System.getProperty("user.dir")',
                      allow_tf=True)
        assert v is REFUSE
        # the poison also kills TF static-finals derived from a
        # property read (Cfg.USERDIR)
        v2, _ = _xfold(xroot, "Cfg.USERDIR", allow_tf=True)
        assert v2 is REFUSE

    def test_definers_all_fold_still_refuses_taint(self):
        rd, sink, index = TestGateConsumers()._rd_setup(
            "        String v = x;\n", "v")
        assert not definers_all_fold(rd, sink, "v", index)
