"""Zero-false-suppress precision harness for the sanitizer-cut gate.

The suppression doctrine (:mod:`core.analysis.reach_witness`, binary-
oracle precedent): a witness kind may hard-suppress a finding ONLY
after a labelled corpus shows zero false-suppress for it. This module
is the sanitizer-cut counterpart of
:mod:`core.analysis.binary_oracle_precision`: it runs the value-bound
gate (the full production path — ``resolve_finding`` →
``evaluate_finding``, inter-procedural bindings included) over a
labelled fixture corpus and reports whether any fixture labelled
``must_not_suppress`` received the ``suppress`` verdict.

The gate metric is **false suppressions** — a fixture that carries a
real (or unprovable) flaw yet gets verdict ``suppress``. The corpus is
deliberately adversarial: wrong-class sanitizers, sanitizers on N-1 of
N paths, sanitization after the sink, straight-line and loop rebinds,
wrong-variable cleaning, unrelated-constant sanitization, a
catalog-empty class, and an unsupported language. ``candidate_only`` /
``no_suppress`` / ``unresolved`` all PASS for a must-not-suppress
fixture — only ``suppress`` fails the gate.

``may_suppress`` fixtures measure utility (how many genuinely-safe
shapes the gate actually suppresses); a miss there is reported but is
NOT a gate failure — soundness first.

Until a run of this harness is clean across every covered sink class
AND its report is recorded alongside the flip, the
``sanitizer_dominated`` entry in :mod:`core.analysis.reach_witness`
stays ``earns_suppression=False`` and the live producer
(:func:`core.dataflow.smt_barrier._record_value_bound_audit`) writes
record-only evidence (``dropped: false``).

Run via ``libexec/raptor-sanitizer-cut-precision``.
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

LABEL_MUST_NOT_SUPPRESS = "must_not_suppress"
LABEL_MAY_SUPPRESS = "may_suppress"

_VERDICT_SUPPRESS = "suppress"


@dataclass(frozen=True)
class CutFixture:
    """One labelled corpus entry. ``shape`` names the adversarial (or
    safe) pattern the fixture exercises so the per-class report rows
    are self-describing. All sources are hand-built public CWE example
    patterns — no undisclosed vulnerabilities (repo corpus doctrine).
    """
    name: str
    sink_class: str
    cwe: str
    language: str
    shape: str
    label: str
    source: str
    source_line: int
    sink_line: int
    suffix: str = ".py"


@dataclass
class FixtureMeasurement:
    name: str
    sink_class: str
    shape: str
    label: str
    verdict: str

    @property
    def false_suppress(self) -> bool:
        return (self.label == LABEL_MUST_NOT_SUPPRESS
                and self.verdict == _VERDICT_SUPPRESS)

    @property
    def missed_suppress(self) -> bool:
        return (self.label == LABEL_MAY_SUPPRESS
                and self.verdict != _VERDICT_SUPPRESS)


@dataclass
class PrecisionReport:
    """Corpus-level result, binary_oracle_precision report style."""
    corpus_name: str
    n_fixtures: int
    measurements: List[FixtureMeasurement] = field(default_factory=list)
    verdict_counts: Dict[str, int] = field(default_factory=dict)
    false_suppressions: List[str] = field(default_factory=list)
    missed_suppressions: List[str] = field(default_factory=list)
    # cross_tab[sink_class][label][verdict] = count
    cross_tab: Dict[str, Dict[str, Dict[str, int]]] = field(
        default_factory=dict)
    n_must_not: int = 0
    # 3/n rule-of-three 95% upper bound on the false-suppress rate,
    # meaningful only when false_suppressions is empty.
    rule_of_three_95_ub: Optional[float] = None
    toolchain: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "corpus": self.corpus_name,
            "n_fixtures": self.n_fixtures,
            "n_must_not_suppress": self.n_must_not,
            "verdict_counts": self.verdict_counts,
            "false_suppressions": self.false_suppressions,
            "missed_suppressions": self.missed_suppressions,
            "cross_tab": self.cross_tab,
            "rule_of_three_95_upper_bound_false_suppress_rate":
                self.rule_of_three_95_ub,
            "toolchain": self.toolchain,
            "measurements": [
                {
                    "name": m.name,
                    "sink_class": m.sink_class,
                    "shape": m.shape,
                    "label": m.label,
                    "verdict": m.verdict,
                }
                for m in self.measurements
            ],
        }


def _fx(name, sink_class, cwe, shape, label, source, src_ln, sink_ln,
        language="python", suffix=".py") -> CutFixture:
    return CutFixture(
        name=name, sink_class=sink_class, cwe=cwe, language=language,
        shape=shape, label=label, source=source,
        source_line=src_ln, sink_line=sink_ln, suffix=suffix,
    )


def _class_fixtures(sink_class, cwe, sanitizer, wrong_sanitizer,
                    sink) -> List[CutFixture]:
    """The per-class fixture template: safe shapes + the adversarial
    battery, instantiated with the class's catalog sanitizer, a
    catalog sanitizer of a DIFFERENT class (the wrong-class case),
    and the class's sink call."""
    c = sink_class
    return [
        _fx(f"{c}_straight_line", c, cwe, "straight_line",
            LABEL_MAY_SUPPRESS,
            f"def handle(x):\n"
            f"    y = {sanitizer}(x)\n"
            f"    {sink}(y)\n", 1, 3),
        _fx(f"{c}_symmetric_branches", c, cwe, "symmetric_branches",
            LABEL_MAY_SUPPRESS,
            f"def handle(x, flag):\n"
            f"    if flag:\n"
            f"        y = {sanitizer}(x)\n"
            f"    else:\n"
            f"        y = {sanitizer}(x)\n"
            f"    {sink}(y)\n", 1, 6),
        _fx(f"{c}_partial_path", c, cwe, "sanitizer_on_n_minus_1_paths",
            LABEL_MUST_NOT_SUPPRESS,
            f"def handle(x, flag):\n"
            f"    if flag:\n"
            f"        y = {sanitizer}(x)\n"
            f"    else:\n"
            f"        y = x\n"
            f"    {sink}(y)\n", 1, 6),
        _fx(f"{c}_wrong_class", c, cwe, "wrong_class_sanitizer",
            LABEL_MUST_NOT_SUPPRESS,
            f"def handle(x):\n"
            f"    y = {wrong_sanitizer}(x)\n"
            f"    {sink}(y)\n", 1, 3),
        _fx(f"{c}_after_sink", c, cwe, "sanitizer_after_sink",
            LABEL_MUST_NOT_SUPPRESS,
            f"def handle(x):\n"
            f"    {sink}(x)\n"
            f"    y = {sanitizer}(x)\n", 1, 2),
        _fx(f"{c}_straight_rebind", c, cwe, "sanitized_then_rebound",
            LABEL_MUST_NOT_SUPPRESS,
            f"def handle(x):\n"
            f"    y = {sanitizer}(x)\n"
            f"    y = x\n"
            f"    {sink}(y)\n", 1, 4),
        _fx(f"{c}_loop_rebind", c, cwe, "sanitized_then_loop_rebound",
            LABEL_MUST_NOT_SUPPRESS,
            f"def handle(items, x):\n"
            f"    y = {sanitizer}(x)\n"
            f"    for i in items:\n"
            f"        y = i\n"
            f"    {sink}(y)\n", 1, 5),
        _fx(f"{c}_wrong_variable", c, cwe, "wrong_variable_sanitized",
            LABEL_MUST_NOT_SUPPRESS,
            f"def handle(user, other):\n"
            f"    safe = {sanitizer}(other)\n"
            f"    {sink}(user)\n", 1, 3),
        _fx(f"{c}_unrelated_constant", c, cwe, "sanitizes_constant_only",
            LABEL_MUST_NOT_SUPPRESS,
            f"def handle(x):\n"
            f"    y = {sanitizer}('const')\n"
            f"    {sink}(x)\n", 1, 3),
        _fx(f"{c}_no_exit_validator", c, cwe, "validator_without_exit",
            LABEL_MUST_NOT_SUPPRESS,
            f"def handle(x):\n"
            f"    if not x.isalnum():\n"
            f"        log('bad')\n"
            f"    {sink}(x)\n", 1, 4),
    ]


def _java_fixtures() -> List[CutFixture]:
    """The Java adversarial battery (b13 leg) — b11's shapes
    re-instantiated in Java plus the Java-specific hazards: the
    wrong-class URLEncoder case (a URL encoder before an HTML sink
    must never suppress), reference-aliasing escapes (array store,
    field store), the chained ESAPI singleton idiom, and the
    lambda-refusal case (the builder must refuse, not mis-model).
    """
    imp = "import org.owasp.encoder.Encode;\n"
    cls = "public class T {\n"
    end = "}\n"

    def meth(body: str, params: str = "String x, java.io.PrintWriter out",
             throws: str = "") -> str:
        return (f"{cls}    public void handle({params}){throws} {{\n"
                f"{body}    }}\n{end}")

    j = []
    j.append(_fx(
        "java_xss_straight_line", "xss", "CWE-79", "straight_line",
        LABEL_MAY_SUPPRESS,
        imp + meth("        String y = Encode.forHtml(x);\n"
                   "        out.println(y);\n"),
        3, 5, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_symmetric_branches", "xss", "CWE-79",
        "symmetric_branches", LABEL_MAY_SUPPRESS,
        imp + meth("        String y;\n"
                   "        if (x.length() > 3) { y = Encode.forHtml(x); }\n"
                   "        else { y = Encode.forHtmlContent(x); }\n"
                   "        out.println(y);\n",
                   params="String x, java.io.PrintWriter out"),
        3, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_partial_path", "xss", "CWE-79",
        "sanitizer_on_n_minus_1_paths", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String y;\n"
                   "        if (x.length() > 3) { y = Encode.forHtml(x); }\n"
                   "        else { y = x; }\n"
                   "        out.println(y);\n"),
        3, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_wrong_class_urlencoder", "xss", "CWE-79",
        "wrong_class_sanitizer", LABEL_MUST_NOT_SUPPRESS,
        "import java.net.URLEncoder;\n"
        + meth("        String y = URLEncoder.encode(x, \"UTF-8\");\n"
               "        out.println(y);\n",
               throws=" throws Exception"),
        3, 5, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_after_sink", "xss", "CWE-79", "sanitizer_after_sink",
        LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        out.println(x);\n"
                   "        String y = Encode.forHtml(x);\n"),
        3, 4, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_straight_rebind", "xss", "CWE-79",
        "sanitized_then_rebound", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String y = Encode.forHtml(x);\n"
                   "        y = x;\n"
                   "        out.println(y);\n"),
        3, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_loop_rebind", "xss", "CWE-79",
        "sanitized_then_loop_rebound", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String y = Encode.forHtml(x);\n"
                   "        for (String i : items) { y = i; }\n"
                   "        out.println(y);\n",
                   params="String x, String[] items, "
                          "java.io.PrintWriter out"),
        3, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_wrong_variable", "xss", "CWE-79",
        "wrong_variable_sanitized", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String safe = Encode.forHtml(other);\n"
                   "        out.println(user);\n",
                   params="String user, String other, "
                          "java.io.PrintWriter out"),
        3, 5, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_constant_only", "xss", "CWE-79",
        "sanitizes_constant_only", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String y = Encode.forHtml(\"const\");\n"
                   "        out.println(x);\n"),
        3, 5, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_no_exit_validator", "xss", "CWE-79",
        "validator_without_exit", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        if (x.contains(\"<\")) { "
                   "System.err.println(\"bad\"); }\n"
                   "        out.println(x);\n"),
        3, 5, language="java", suffix=".java"))
    j.append(_fx(
        # b19 note: the original body's array was LOCAL, fresh, and
        # never read — element tracking proves it irrelevant to the
        # sanitized scalar sink, so the old body became legitimately
        # suppressible (the b19 exemption). The alias line below makes
        # the array genuinely untracked, preserving this fixture's
        # guard role: an escaping array on the path must keep the
        # may_escape downgrade.
        "java_xss_array_store_escape", "xss", "CWE-79",
        "array_element_aliasing", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        String[] b = a;\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        b[0] = x;\n"
                   "        String y = Encode.forHtml(x);\n"
                   "        out.println(y);\n"),
        3, 9, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_esapi_chain", "xss", "CWE-79", "esapi_singleton_chain",
        LABEL_MAY_SUPPRESS,
        "import org.owasp.esapi.ESAPI;\n"
        + meth("        String y = ESAPI.encoder().encodeForHTML(x);\n"
               "        out.println(y);\n"),
        3, 5, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_instance_encoder_untyped", "xss", "CWE-79",
        "instance_call_no_type_inference", LABEL_MUST_NOT_SUPPRESS,
        # ``enc`` is untyped from the gate's perspective — could be
        # anything with an encodeForHTML method. Must not resolve to
        # the ESAPI catalog entry.
        meth("        String y = enc.encodeForHTML(x);\n"
             "        out.println(y);\n",
             params="String x, Object enc, java.io.PrintWriter out"),
        2, 4, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_lambda_refusal", "xss", "CWE-79",
        "lambda_forces_refusal", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        Runnable r = () -> out.println(x);\n"
                   "        String y = Encode.forHtml(x);\n"
                   "        out.println(y);\n"),
        3, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_try_catch_safe", "xss", "CWE-79", "try_catch_safe",
        LABEL_MAY_SUPPRESS,
        imp + meth("        try {\n"
                   "            String y = Encode.forHtml(x);\n"
                   "            out.println(y);\n"
                   "        } catch (Exception e) { "
                   "out.println(\"err\"); }\n"),
        3, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_sqli_catalog_empty", "sqli", "CWE-89",
        "catalog_empty_class", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String y = Encode.forHtml(x);\n"
                   "        stmt.execute(y);\n",
                   params="String x, java.sql.Statement stmt",
                   throws=" throws Exception"),
        3, 5, language="java", suffix=".java"))
    return j


def _java_wrapper_fixtures() -> List[CutFixture]:
    """b19 wrapper-summary battery. Adversarial shapes first — every
    way a helper can LOOK like a sanitizer without being one must
    refuse: a non-sanitizing body, a two-level wrapper (depth cap), a
    branchy body, an overridable instance method (dynamic dispatch),
    recursion, same-arity overloads, and a mixed clean+dirty parameter
    signature. Safe shapes: the direct wrapper and the
    local-chain body."""
    imp = "import org.owasp.encoder.Encode;\n"

    def cls(helpers: str, body: str,
            params: str = "String x, java.io.PrintWriter out") -> str:
        return ("public class T {\n"
                f"{helpers}"
                f"    public void handle({params}) {{\n"
                f"{body}    }}\n"
                "}\n")

    j = []
    j.append(_fx(
        "java_wrap_nonsanitizing", "xss", "CWE-79",
        "wrapper_without_sanitizer", LABEL_MUST_NOT_SUPPRESS,
        cls("    private static String clean(String s) {\n"
            "        return s.trim();\n"
            "    }\n",
            "        String y = clean(x);\n"
            "        out.println(y);\n"),
        5, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_wrap_two_level", "xss", "CWE-79",
        "wrapper_depth_two", LABEL_MUST_NOT_SUPPRESS,
        imp + cls(
            "    private static String inner(String s) "
            "{ return Encode.forHtml(s); }\n"
            "    private static String outer(String s) "
            "{ return inner(s); }\n",
            "        String y = outer(x);\n"
            "        out.println(y);\n"),
        5, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_wrap_branchy", "xss", "CWE-79",
        "wrapper_sanitizes_one_branch", LABEL_MUST_NOT_SUPPRESS,
        imp + cls(
            "    private static String h(String s) {\n"
            "        if (s.length() > 3) { return Encode.forHtml(s); }\n"
            "        return s;\n"
            "    }\n",
            "        String y = h(x);\n"
            "        out.println(y);\n"),
        7, 9, language="java", suffix=".java"))
    j.append(_fx(
        "java_wrap_overridable", "xss", "CWE-79",
        "wrapper_dynamic_dispatch", LABEL_MUST_NOT_SUPPRESS,
        imp + cls(
            "    public String h(String s) "
            "{ return Encode.forHtml(s); }\n",
            "        String y = h(x);\n"
            "        out.println(y);\n"),
        4, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_wrap_recursive", "xss", "CWE-79",
        "wrapper_recursion", LABEL_MUST_NOT_SUPPRESS,
        imp + cls(
            "    private static String h(String s) "
            "{ return h(Encode.forHtml(s)); }\n",
            "        String y = h(x);\n"
            "        out.println(y);\n"),
        4, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_wrap_overloaded", "xss", "CWE-79",
        "wrapper_overload_ambiguity", LABEL_MUST_NOT_SUPPRESS,
        imp + cls(
            "    private static String h(String s) "
            "{ return Encode.forHtml(s); }\n"
            "    private static String h(Object s) "
            "{ return s.toString(); }\n",
            "        String y = h(x);\n"
            "        out.println(y);\n"),
        5, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_wrap_mixed_params", "xss", "CWE-79",
        "wrapper_clean_and_dirty_params", LABEL_MUST_NOT_SUPPRESS,
        imp + cls(
            "    private static String h(String a, String b) {\n"
            "        return Encode.forHtml(a) + b;\n"
            "    }\n",
            "        String y = h(x, x);\n"
            "        out.println(y);\n"),
        6, 8, language="java", suffix=".java"))
    j.append(_fx(
        "java_wrap_direct", "xss", "CWE-79",
        "wrapper_direct_sanitizer", LABEL_MAY_SUPPRESS,
        imp + cls(
            "    private static String esc(String s) "
            "{ return Encode.forHtml(s); }\n",
            "        String y = esc(x);\n"
            "        out.println(y);\n"),
        4, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_wrap_local_chain", "xss", "CWE-79",
        "wrapper_local_chain", LABEL_MAY_SUPPRESS,
        imp + cls(
            "    private static String esc(String s) {\n"
            "        String t = Encode.forHtml(s);\n"
            "        return t;\n"
            "    }\n",
            "        String y = esc(x);\n"
            "        out.println(y);\n"),
        7, 9, language="java", suffix=".java"))
    return j


def _java_array_fixtures() -> List[CutFixture]:
    """b19 element-sensitivity battery. Adversarial shapes first —
    every way per-element reasoning can be broken must refuse: element
    rebind with taint, element mismatch trusted via base-name kills,
    reference aliasing (both directions), the array passed to a
    helper, a field array, a non-constant index poisoning the array,
    a compound element write, an enhanced-for element read, a tainted
    write below the sink, and a whole-array sink pass. Safe shapes:
    the direct element read, the one-scalar-hop copy, and the
    incidental-tracked-array exemption."""
    imp = "import org.owasp.encoder.Encode;\n"

    def meth(body: str,
             params: str = "String x, java.io.PrintWriter out") -> str:
        return ("public class T {\n"
                f"    public void handle({params}) {{\n"
                f"{body}    }}\n"
                "}\n")

    j = []
    j.append(_fx(
        "java_arr_element_rebind", "xss", "CWE-79",
        "element_rebound_with_taint", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        a[0] = x;\n"
                   "        out.println(a[0]);\n"),
        3, 7, language="java", suffix=".java"))
    j.append(_fx(
        # The base-name reaching-defs inversion: a[1]'s write kills
        # a[0]'s in the base-name lattice, so trusting RD here would
        # read "only the sanitizer reaches" while the sink consumes
        # the TAINTED element. Flow-insensitive exclusivity refuses.
        "java_arr_element_mismatch", "xss", "CWE-79",
        "element_mismatch_rd_inversion", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        a[1] = x;\n"
                   "        out.println(a[1]);\n"),
        3, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_arr_alias_out", "xss", "CWE-79",
        "array_alias_out", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        String[] b = a;\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        b[0] = x;\n"
                   "        out.println(a[0]);\n"),
        3, 8, language="java", suffix=".java"))
    j.append(_fx(
        "java_arr_helper_escape", "xss", "CWE-79",
        "array_passed_to_helper", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        fill(a, x);\n"
                   "        out.println(a[0]);\n"),
        3, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_arr_field_array", "xss", "CWE-79",
        "field_array_not_local", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        this.a[0] = Encode.forHtml(x);\n"
                   "        out.println(this.a[0]);\n"),
        3, 5, language="java", suffix=".java"))
    j.append(_fx(
        "java_arr_nonconst_index", "xss", "CWE-79",
        "nonconstant_index_poisons", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        a[i] = x;\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        out.println(a[0]);\n",
                   params="String x, int i, java.io.PrintWriter out"),
        3, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_arr_compound_write", "xss", "CWE-79",
        "compound_element_write", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        a[0] += x;\n"
                   "        out.println(a[0]);\n"),
        3, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_arr_enhanced_for_read", "xss", "CWE-79",
        "enhanced_for_element_read", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        a[1] = x;\n"
                   "        for (String s : a) { out.println(s); }\n"),
        3, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_arr_taint_below_sink", "xss", "CWE-79",
        "tainted_write_below_sink", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        out.println(a[0]);\n"
                   "        a[0] = x;\n"),
        3, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_arr_whole_array_sink", "xss", "CWE-79",
        "whole_array_sink_pass", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        a[1] = x;\n"
                   "        out.println(a);\n"),
        3, 7, language="java", suffix=".java"))
    j.append(_fx(
        # Exemption blocker: an UNTRACKED (field) array access on the
        # path must keep the may_escape downgrade even though the
        # scalar binding held.
        "java_arr_untracked_on_path", "xss", "CWE-79",
        "untracked_array_blocks_exemption", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String y = Encode.forHtml(x);\n"
                   "        this.cache[0] = y;\n"
                   "        out.println(y);\n"),
        3, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_arr_element_direct", "xss", "CWE-79",
        "element_direct_read", LABEL_MAY_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        out.println(a[0]);\n"),
        3, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_arr_scalar_hop", "xss", "CWE-79",
        "element_scalar_hop", LABEL_MAY_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        String bar = a[0];\n"
                   "        out.println(bar);\n"),
        3, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_arr_incidental_exempt", "xss", "CWE-79",
        "tracked_array_exemption", LABEL_MAY_SUPPRESS,
        imp + meth("        String y = Encode.forHtml(x);\n"
                   "        String[] a = new String[1];\n"
                   "        a[0] = y;\n"
                   "        out.println(y);\n"),
        3, 7, language="java", suffix=".java"))
    return j


def build_corpus() -> List[CutFixture]:
    """The labelled corpus: the adversarial battery instantiated per
    covered python sink class, plus interproc, catalog-empty-class,
    unsupported-language singletons, and the Java battery (b13 leg).

    Sanitizer names come from the catalog
    (:func:`core.dataflow.sanitizer_catalog.sanitizer_callables_for_cwe`)
    — a test pins that each per-class sanitizer used here is really in
    the catalog for its class and the wrong-class one is NOT.
    """
    fixtures: List[CutFixture] = []
    fixtures += _class_fixtures(
        "xss", "CWE-79", "html.escape", "shlex.quote", "render")
    fixtures += _class_fixtures(
        "cmdi", "CWE-78", "shlex.quote", "html.escape", "os.system")
    fixtures += _class_fixtures(
        "pathtrav", "CWE-22", "werkzeug.utils.secure_filename",
        "html.escape", "open")
    fixtures.append(_fx(
        "xss_helper_interproc", "xss", "CWE-79", "sanitizer_in_helper",
        LABEL_MAY_SUPPRESS,
        "def _clean(s):\n"
        "    return html.escape(s)\n"
        "def handle(x):\n"
        "    y = _clean(x)\n"
        "    render(y)\n", 3, 5))
    # Catalog-empty class: python has no sqli sanitizer entries, so
    # nothing may EVER suppress a CWE-89 python finding — including a
    # plausible-looking wrong-class escape.
    fixtures.append(_fx(
        "sqli_catalog_empty", "sqli", "CWE-89", "catalog_empty_class",
        LABEL_MUST_NOT_SUPPRESS,
        "def q(v):\n"
        "    v2 = html.escape(v)\n"
        "    cursor.execute(v2)\n", 1, 3))
    # C leg: the resolver's C intra-proc path (or, on builds without
    # it, an unresolved refusal) must never read an unsanitized
    # system(cmd) as suppressible.
    fixtures.append(_fx(
        "c_unsanitized_system", "cmdi", "CWE-78", "c_language",
        LABEL_MUST_NOT_SUPPRESS,
        "void run(char *cmd) {\n"
        "    system(cmd);\n"
        "}\n", 1, 2, language="c", suffix=".c"))
    fixtures += _java_fixtures()
    fixtures += _java_constant_fixtures()
    fixtures += _java_wrapper_fixtures()
    fixtures += _java_array_fixtures()
    return fixtures


def measure_fixture(fx: CutFixture, work_dir: Path) -> FixtureMeasurement:
    """Run the production gate path over one fixture."""
    from core.dataflow.sanitizer_cut_parity import value_bound_verdict_for

    path = work_dir / f"{fx.name}{fx.suffix}"
    path.write_text(fx.source, encoding="utf-8")
    verdict = value_bound_verdict_for({
        "cwe": fx.cwe,
        "file_path": str(path),
        "source_line": fx.source_line,
        "sink_line": fx.sink_line,
        "language": fx.language,
    })
    return FixtureMeasurement(
        name=fx.name, sink_class=fx.sink_class, shape=fx.shape,
        label=fx.label, verdict=verdict,
    )


def _toolchain() -> Dict[str, str]:
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
    }


def _java_constant_fixtures() -> List[CutFixture]:
    """Constant-definers battery: the dead-branch ternary trick may
    suppress; every variation that breaks the constancy proof — a
    live condition, the fold selecting the tainted branch, a compound
    writer, an incidental-constant sibling argument (the sink-arg
    inversion trap), and an array-element rebind — must not.
    """
    hdr = ("import javax.servlet.http.HttpServletRequest;\n"
           "public class T {\n"
           "    public void handle(HttpServletRequest request, "
           "java.io.PrintWriter out) {\n")
    end = "    }\n}\n"

    def body(*lines: str) -> str:
        return hdr + "".join(f"        {ln}\n" for ln in lines) + end

    j = []
    j.append(_fx(
        "java_const_dead_branch_ternary", "xss", "CWE-79",
        "constant_dead_branch", LABEL_MAY_SUPPRESS,
        body('String param = request.getParameter("q");',
             'int num = 106;',
             'String bar = (7 * 18) + num > 200 ? "safe" : param;',
             'out.println(bar);'),
        4, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_const_live_condition", "xss", "CWE-79",
        "constant_live_condition", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'int num = request.getIntHeader("n");',
             'String bar = (7 * 18) + num > 200 ? "safe" : param;',
             'out.println(bar);'),
        4, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_const_fold_selects_tainted", "xss", "CWE-79",
        "constant_false_ternary", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'int num = 106;',
             'String bar = (7 * 18) + num > 2000 ? "safe" : param;',
             'out.println(bar);'),
        4, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_const_compound_writer", "xss", "CWE-79",
        "constant_compound_writer", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String bar = "safe";',
             'bar += param;',
             'out.println(bar);'),
        4, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_const_sibling_arg_inversion", "xss", "CWE-79",
        "constant_sibling_inversion", LABEL_MUST_NOT_SUPPRESS,
        body('String zz = request.getParameter("q");',
             'String aa = "constant";',
             'out.printf(aa, zz);'),
        4, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_const_multiple_agreeing_defs", "xss", "CWE-79",
        "constant_agreeing_defs", LABEL_MAY_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String bar;',
             'if (param.length() > 3) { bar = "safe"; }',
             'else { bar = "safe"; }',
             'out.println(bar);'),
        4, 8, language="java", suffix=".java"))
    j.append(_fx(
        "java_const_disagreeing_defs", "xss", "CWE-79",
        "constant_disagreeing_defs", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String bar;',
             'if (param.length() > 3) { bar = "safe"; }',
             'else { bar = param; }',
             'out.println(bar);'),
        4, 8, language="java", suffix=".java"))
    return j


def run_corpus(fixtures: Optional[List[CutFixture]] = None,
               corpus_name: str = "adversarial-v1") -> PrecisionReport:
    fixtures = fixtures if fixtures is not None else build_corpus()
    report = PrecisionReport(
        corpus_name=corpus_name,
        n_fixtures=len(fixtures),
        toolchain=_toolchain(),
    )
    with tempfile.TemporaryDirectory(
            prefix="sanitizer-cut-precision-") as tmp:
        work = Path(tmp)
        for fx in fixtures:
            m = measure_fixture(fx, work)
            report.measurements.append(m)
            report.verdict_counts[m.verdict] = (
                report.verdict_counts.get(m.verdict, 0) + 1)
            cls = report.cross_tab.setdefault(m.sink_class, {})
            lbl = cls.setdefault(m.label, {})
            lbl[m.verdict] = lbl.get(m.verdict, 0) + 1
            if m.label == LABEL_MUST_NOT_SUPPRESS:
                report.n_must_not += 1
            if m.false_suppress:
                report.false_suppressions.append(m.name)
            if m.missed_suppress:
                report.missed_suppressions.append(m.name)
    if not report.false_suppressions and report.n_must_not:
        report.rule_of_three_95_ub = 3.0 / report.n_must_not
    return report


def _format_markdown(report: PrecisionReport) -> str:
    lines = [
        "# Sanitizer-cut precision report",
        "",
        f"- corpus: {report.corpus_name}",
        f"- fixtures: {report.n_fixtures} "
        f"({report.n_must_not} must-not-suppress)",
        f"- verdicts: {json.dumps(report.verdict_counts, sort_keys=True)}",
        "- toolchain: "
        + ", ".join(f"{k}={v}" for k, v in sorted(report.toolchain.items())),
        "",
    ]
    if report.false_suppressions:
        lines.append(
            f"## GATE FAILED — {len(report.false_suppressions)} "
            "false suppression(s)")
        for name in report.false_suppressions:
            lines.append(f"- {name}")
    else:
        lines.append("## Gate clean — zero false suppressions")
        if report.rule_of_three_95_ub is not None:
            lines.append(
                f"- rule-of-three 95% UB on the false-suppress rate: "
                f"{report.rule_of_three_95_ub:.3f} "
                f"(3/{report.n_must_not})")
        lines.append(
            "- NOTE: a clean run is necessary, not sufficient — flipping "
            "``sanitizer_dominated`` to earns_suppression is a reviewed "
            "change that must record this report.")
    lines.append("")
    if report.missed_suppressions:
        lines.append(
            f"## Missed suppressions (utility, not a gate failure): "
            f"{len(report.missed_suppressions)}")
        for name in report.missed_suppressions:
            lines.append(f"- {name}")
        lines.append("")
    lines.append("## Per-class cross-tab (label × verdict)")
    for cls in sorted(report.cross_tab):
        lines.append(f"### {cls}")
        for lbl in sorted(report.cross_tab[cls]):
            row = json.dumps(report.cross_tab[cls][lbl], sort_keys=True)
            lines.append(f"- {lbl}: {row}")
    lines.append("")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="raptor-sanitizer-cut-precision",
        description=(
            "Measure the sanitizer-cut value-bound gate against the "
            "labelled adversarial corpus. The gate metric is false "
            "suppressions: any must-not-suppress fixture receiving the "
            "suppress verdict fails the run (exit 1). A clean run is "
            "the precondition for the sanitizer_dominated witness ever "
            "earning hard-suppression."
        ),
    )
    p.add_argument("--out", type=Path, default=None,
                   help=("output dir (default: "
                         "out/sanitizer-cut-precision/runs/<ts>)"))
    args = p.parse_args(argv)

    report = run_corpus()

    out = args.out
    if out is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = Path("out") / "sanitizer-cut-precision" / "runs" / ts
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    md = _format_markdown(report)
    (out / "report.md").write_text(md, encoding="utf-8")
    sys.stdout.write(md)
    sys.stdout.write(f"\nreports written to {out}\n")
    return 1 if report.false_suppressions else 0


__all__ = [
    "LABEL_MAY_SUPPRESS",
    "LABEL_MUST_NOT_SUPPRESS",
    "CutFixture",
    "FixtureMeasurement",
    "PrecisionReport",
    "build_corpus",
    "measure_fixture",
    "run_corpus",
    "main",
]
