"""Unit battery for the b42 taint-free union machinery.

Covers the three seams the corpus exercises end-to-end:

* returns-taint-free helper summary derivation (acceptances and every
  named refusal);
* the non-agreeing definer union in the point resolver — tier-on
  yields TAINT_FREE, tier-off keeps the historical refusal
  byte-for-byte;
* the same-line multi-write refusal in ``JavaConstIndex.rhs_at`` (the
  pre-existing collapse hazard the b42 value-position trap exposed:
  a one-liner ``if/else`` discriminant folded to its first arm and
  pruned the tainted switch arm).
"""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_java")

from core.analysis.java_taint_freedom import (  # noqa: E402
    derive_tf_helpers,
    make_tf_helper_resolver,
)


def _cls(body: str) -> str:
    return "public class T {\n" + body + "\n}\n"


class TestHelperSummaries:
    def test_flag_gated_all_literal_branches_qualifies(self):
        # The Juliet _21 shape: the field flag selects the branch but
        # every branch writes a literal — union taint-free, no
        # reasoning about the flag.
        src = _cls(
            "    private boolean flag = false;\n"
            "    private String src() {\n"
            "        String d;\n"
            "        if (flag) { d = null; } else { d = \"foo\"; }\n"
            "        return d;\n"
            "    }\n"
        )
        idx = derive_tf_helpers(src)
        assert idx.ok
        assert ("src", 0) in idx.taint_free

    def test_single_literal_return_qualifies(self):
        src = _cls("    private String v() { return \"x\"; }\n")
        assert ("v", 0) in derive_tf_helpers(src).taint_free

    def test_parameter_flow_refuses(self):
        src = _cls(
            "    private String pick(String p) {\n"
            "        if (p.isEmpty()) { return p; }\n"
            "        return \"x\";\n"
            "    }\n"
        )
        idx = derive_tf_helpers(src)
        assert ("pick", 1) not in idx.taint_free
        assert idx.refused.get("return-not-taint-free")

    def test_field_value_refuses(self):
        src = _cls(
            "    private String stash = \"d\";\n"
            "    private String src() {\n"
            "        String d;\n"
            "        if (stash.isEmpty()) { d = stash; }\n"
            "        else { d = \"foo\"; }\n"
            "        return d;\n"
            "    }\n"
        )
        assert ("src", 0) not in derive_tf_helpers(src).taint_free

    def test_unknown_call_refuses(self):
        src = _cls(
            "    private String src() {\n"
            "        String d = System.console().readLine();\n"
            "        return d;\n"
            "    }\n"
        )
        assert ("src", 0) not in derive_tf_helpers(src).taint_free

    def test_compound_write_refuses(self):
        src = _cls(
            "    private String src(String p) {\n"
            "        String d = \"foo\";\n"
            "        d += p;\n"
            "        return d;\n"
            "    }\n"
        )
        assert ("src", 1) not in derive_tf_helpers(src).taint_free

    def test_overload_ambiguity_refuses(self):
        src = _cls(
            "    private String v(int a) { return \"x\"; }\n"
            "    private String v(int a, int b) { return \"y\"; }\n"
            "    private String v(int a) { return \"z\"; }\n"
        )
        idx = derive_tf_helpers(src)
        assert ("v", 1) not in idx.taint_free
        # the unambiguous 2-arity overload still qualifies
        assert ("v", 2) in idx.taint_free

    def test_varargs_refuses(self):
        src = _cls(
            "    private String v(String... a) { return \"x\"; }\n"
        )
        assert not derive_tf_helpers(src).taint_free

    def test_void_helper_refuses(self):
        src = _cls("    private void v() { return; }\n")
        assert ("v", 0) not in derive_tf_helpers(src).taint_free

    def test_recursive_helper_refuses(self):
        src = _cls(
            "    private String v() {\n"
            "        String d = w();\n"
            "        return d;\n"
            "    }\n"
            "    private String w() { return v(); }\n"
        )
        idx = derive_tf_helpers(src)
        # v's body calls w() — an unknown call to the folder (no
        # helper-of-helper summaries in v1), so both refuse.
        assert ("v", 0) not in idx.taint_free
        assert ("w", 0) not in idx.taint_free


class TestHelperResolver:
    def test_resolver_none_when_no_helpers(self):
        src = _cls("    private String v(String p) { return p; }\n")
        assert make_tf_helper_resolver(src) is None

    def test_resolver_claims_bare_call_only(self):
        src = _cls(
            "    private String v() { return \"x\"; }\n"
        )
        res = make_tf_helper_resolver(src)
        assert res is not None
        from core.analysis.cfg_builder_java import _get_parser
        from core.analysis.const_fold_java import TAINT_FREE
        tree = _get_parser().parse(
            b"class U { void m(T t) { String a = v(); "
            b"String b = t.v(); } }"
        )
        calls = []
        stack = [tree.root_node]
        while stack:
            n = stack.pop()
            if n.type == "method_invocation":
                calls.append(n)
            stack.extend(n.children)
        got = {}
        for c in calls:
            got[c.text.decode()] = res(c, None, 0)
        assert got["v()"] is TAINT_FREE
        assert got["t.v()"] is None  # receiver: no claim


class TestDefinerUnion:
    SRC = (
        "public class T {\n"
        "    public void handle(String cond) {\n"
        "        String data;\n"
        "        if (cond.isEmpty()) {\n"
        "            data = null;\n"
        "        } else {\n"
        "            data = \"foo\";\n"
        "        }\n"
        "        use(data);\n"
        "    }\n"
        "    void use(String s) {}\n"
        "}\n"
    )

    def _rd_and_index(self):
        from core.analysis.cfg_builder_java import (
            build_java_intraproc_cfg,
        )
        from core.analysis.const_fold_java import JavaConstIndex
        from core.analysis.dataflow import reaching_defs
        g = build_java_intraproc_cfg(self.SRC, "handle")
        assert g is not None
        rd = reaching_defs(g)
        sink = [n for n in g.nodes() if getattr(n, "lineno", 0) == 9][0]
        idx = JavaConstIndex(self.SRC, (1, 12))
        return rd, sink, idx

    def test_union_tier_on_yields_taint_free_reason(self):
        from core.analysis.const_fold_java import all_definers_constant
        rd, sink, idx = self._rd_and_index()
        reason = all_definers_constant(rd, sink, "data", idx)
        assert reason is not None
        assert "non-agreeing taint-free union" in reason

    def test_union_tier_off_refuses(self):
        # The value-only entry point keeps the historical refusal:
        # a disagreeing merge must never produce a usable value.
        from core.analysis.const_fold_java import (
            REFUSE,
            fold_expr_at,
        )
        from core.analysis.cfg_builder_java import _get_parser
        rd, sink, idx = self._rd_and_index()
        tree = _get_parser().parse(b"class Q { void m() { use(data); } }")
        ident = None
        stack = [tree.root_node]
        while stack:
            n = stack.pop()
            if n.type == "identifier" and n.text == b"data":
                ident = n
            stack.extend(n.children)
        val = fold_expr_at(rd, sink, ident, idx,
                           allow_taint_free=False)
        assert val is REFUSE


class TestMultiWriteLineRefusal:
    def test_one_liner_if_else_discriminant_never_prunes(self):
        # The trap that caught a live false suppression: both writes
        # to the discriminant share one line, so the line-keyed RHS
        # lookup used to serve the first arm to BOTH definers and the
        # switch pruned its tainted default arm.
        src = (
            "public class T {\n"
            "    public void handle(String param) {\n"
            "        String s;\n"
            "        if (param.length() > 2) { s = \"a\"; } "
            "else { s = \"b\"; }\n"
            "        use(s);\n"
            "    }\n"
            "    void use(String x) {}\n"
            "}\n"
        )
        from core.analysis.const_fold_java import JavaConstIndex
        idx = JavaConstIndex(src, (1, 8))
        assert idx.rhs_at(4, "s") is None

    def test_single_write_line_still_serves(self):
        src = (
            "public class T {\n"
            "    public void handle() {\n"
            "        String s = \"a\";\n"
            "        use(s);\n"
            "    }\n"
            "    void use(String x) {}\n"
            "}\n"
        )
        from core.analysis.const_fold_java import JavaConstIndex
        idx = JavaConstIndex(src, (1, 7))
        assert idx.rhs_at(3, "s") is not None
