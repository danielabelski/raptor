"""Tolerance matcher: line drift, file-level, CWE family, paths."""

from __future__ import annotations

from core.recall.manifest import ExpectedFinding, Provenance, Tolerance
from core.recall.matcher import (
    clean_region_hits,
    match_findings,
    path_matches,
)

_PROV = Provenance(kind="benchmark", suite="s", case="c")


def _exp(**kw) -> ExpectedFinding:
    base = dict(id="e1", file="src/A.java", cwe="CWE-78",
                provenance=_PROV, line_start=100, line_end=104)
    base.update(kw)
    return ExpectedFinding(**base)


def _prod(**kw) -> dict:
    base = {"file": "/work/repo/src/A.java", "startLine": 102,
            "endLine": 102, "cwe_id": "CWE-78", "tool": "semgrep",
            "rule_id": "r1"}
    base.update(kw)
    return base


TOL = Tolerance(line_drift=5, cwe_family_match=True)
STRICT = Tolerance(line_drift=0, cwe_family_match=False)


class TestPathMatching:
    def test_absolute_produced_suffix_matches(self):
        assert path_matches("src/A.java", "/work/repo/src/A.java")

    def test_dotslash_normalised(self):
        assert path_matches("./src/A.java", "src/A.java")

    def test_different_file_rejected(self):
        assert not path_matches("src/A.java", "/work/repo/src/B.java")

    def test_empty_produced_rejected(self):
        assert not path_matches("src/A.java", None)


class TestLineDrift:
    def test_inside_window_matches(self):
        [r] = match_findings([_exp()], [_prod(startLine=108, endLine=108)],
                             TOL)
        assert r.matched  # 104 + 5 >= 108

    def test_outside_window_misses(self):
        [r] = match_findings([_exp()], [_prod(startLine=115, endLine=115)],
                             TOL)
        assert not r.matched

    def test_zero_drift_exact(self):
        [r] = match_findings([_exp()], [_prod(startLine=104)], STRICT)
        assert r.matched
        [r] = match_findings([_exp()], [_prod(startLine=105)], STRICT)
        assert not r.matched

    def test_file_level_matches_any_line(self):
        exp = _exp(line_start=None, line_end=None)
        [r] = match_findings([exp], [_prod(startLine=9999)], STRICT)
        assert r.matched

    def test_produced_without_line_only_matches_file_level(self):
        [r] = match_findings([_exp()], [_prod(startLine=None)], TOL)
        assert not r.matched
        exp = _exp(line_start=None, line_end=None)
        [r] = match_findings([exp], [_prod(startLine=None)], TOL)
        assert r.matched


class TestCweMatching:
    def test_exact_match(self):
        [r] = match_findings([_exp()], [_prod(cwe_id="CWE-78")], STRICT)
        assert not STRICT.cwe_family_match
        assert r.matched or _prod()["startLine"] != 104  # sanity
        [r] = match_findings([_exp(line_start=102, line_end=102)],
                             [_prod(cwe_id="CWE-78")], STRICT)
        assert r.matched

    def test_family_sibling_matches_when_enabled(self):
        # CWE-77 is a command-injection sibling of CWE-78
        [r] = match_findings([_exp()], [_prod(cwe_id="CWE-77")], TOL)
        assert r.matched

    def test_weak_cipher_family_bridges_326_327(self):
        # Producers tag DES/RC4 findings CWE-326 or CWE-327
        # interchangeably (measured live: the registry des-is-deprecated
        # rule is 326, the OWASP Benchmark labels the cases 327).
        exp = _exp(cwe="CWE-327")
        [r] = match_findings([exp], [_prod(cwe_id="CWE-326")], TOL)
        assert r.matched

    def test_family_sibling_rejected_when_disabled(self):
        exp = _exp(line_start=102, line_end=102)
        [r] = match_findings([exp], [_prod(cwe_id="CWE-77")], STRICT)
        assert not r.matched

    def test_bare_number_normalised(self):
        [r] = match_findings([_exp()], [_prod(cwe_id="78")], TOL)
        assert r.matched

    def test_cwe_less_finding_never_matches(self):
        [r] = match_findings([_exp()], [_prod(cwe_id=None)], TOL)
        assert not r.matched


class TestAttribution:
    def test_tools_deduped_and_sorted(self):
        prods = [_prod(tool="semgrep"), _prod(tool="codeql"),
                 _prod(tool="codeql", rule_id="r2")]
        [r] = match_findings([_exp()], prods, TOL)
        assert r.tools == ["codeql", "semgrep"]
        assert len(r.hits) == 3

    def test_one_finding_can_satisfy_two_expected(self):
        exps = [_exp(id="a"), _exp(id="b", line_start=None, line_end=None)]
        rs = match_findings(exps, [_prod()], TOL)
        assert all(r.matched for r in rs)


class TestCleanRegions:
    def test_only_hits_returned(self):
        clean = [_exp(id="clean-1", file="src/C.java",
                      line_start=None, line_end=None)]
        hits = clean_region_hits(clean, [_prod()], TOL)
        assert hits == []
        hits = clean_region_hits(
            clean, [_prod(file="/work/repo/src/C.java")], TOL)
        assert len(hits) == 1 and hits[0].matched
