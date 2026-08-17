"""Tests for core.audit.tool_coverage — vulnerability class coverage map."""

from __future__ import annotations

from core.audit.tool_coverage import _extract_cwes, is_class_covered


class TestExtractCwes:
    def test_explicit_cwe(self):
        assert _extract_cwes("CWE-79") == ["CWE-79"]

    def test_multiple_cwes(self):
        assert _extract_cwes("CWE-79, CWE-89") == ["CWE-79", "CWE-89"]

    def test_cwe_case_insensitive(self):
        assert _extract_cwes("cwe-78") == ["CWE-78"]

    def test_mechanism_keyword(self):
        cwes = _extract_cwes("", mechanism="buffer overflow")
        assert "CWE-120" in cwes

    def test_hypothesis_keyword(self):
        cwes = _extract_cwes("", hypothesis="sql injection via user input")
        assert "CWE-89" in cwes

    def test_combined_sources(self):
        cwes = _extract_cwes("CWE-78", mechanism="command injection")
        assert "CWE-78" in cwes
        assert len([c for c in cwes if c == "CWE-78"]) == 1  # deduped

    def test_no_match(self):
        assert _extract_cwes("", mechanism="logic error") == []

    def test_empty_inputs(self):
        assert _extract_cwes("") == []

    def test_mechanism_use_after_free_variants(self):
        assert "CWE-416" in _extract_cwes("", mechanism="use after free")
        assert "CWE-416" in _extract_cwes("", mechanism="use-after-free")

    def test_mechanism_codeql_injection(self):
        assert "CWE-94" in _extract_cwes("", mechanism="CodeQL injection via proposed_guard")

    def test_mechanism_race_condition_is_cwe_362(self):
        """Generic races are CWE-362 (lock races), not CWE-367 (TOCTOU).

        The prefilter's TOCTOU check only detects stat/access-then-open
        patterns; mapping generic races to CWE-367 marked every race
        hypothesis tool-covered via the always-on prefilter.
        """
        cwes = _extract_cwes("", mechanism="race condition on shared counter")
        assert "CWE-362" in cwes
        assert "CWE-367" not in cwes

    def test_mechanism_toctou_is_cwe_367(self):
        assert _extract_cwes("", mechanism="toctou between stat and open") == ["CWE-367"]


class TestIsClassCovered:
    ALL_TOOLS = {
        "joern": True, "codeql": True, "semgrep": True,
        "coccinelle": True, "smt": True,
    }
    NO_TOOLS = {
        "joern": False, "codeql": False, "semgrep": False,
        "coccinelle": False, "smt": False,
    }

    def test_covered_all_tools(self):
        assert is_class_covered("CWE-78", "", "", self.ALL_TOOLS) is True

    def test_covered_prefilter_only(self):
        """prefilter is always available — CWE-78 maps to it."""
        assert is_class_covered("CWE-78", "", "", self.NO_TOOLS) is True

    def test_uncovered_unknown_cwe(self):
        """Unknown CWE → not in map → conservative dark."""
        assert is_class_covered("CWE-99999", "", "", self.ALL_TOOLS) is False

    def test_uncovered_no_cwe_extracted(self):
        """No CWE extractable → conservative dark."""
        assert is_class_covered("", "logic error", "", self.ALL_TOOLS) is False

    def test_covered_via_mechanism(self):
        assert is_class_covered("", "sql injection", "", self.ALL_TOOLS) is True

    def test_covered_via_hypothesis(self):
        assert is_class_covered(
            "", "", "path traversal via user input", self.ALL_TOOLS,
        ) is True

    def test_not_covered_tool_unavailable(self):
        """CWE-476 only maps to codeql and coccinelle. Both unavailable."""
        tools = {"joern": True, "codeql": False, "semgrep": True,
                 "coccinelle": False}
        assert is_class_covered("CWE-476", "", "", tools) is False

    def test_covered_partial_tools(self):
        """CWE-89 maps to prefilter+semgrep+codeql+joern. semgrep alone."""
        tools = {"joern": False, "codeql": False, "semgrep": True,
                 "coccinelle": False}
        assert is_class_covered("CWE-89", "", "", tools) is True

    def test_empty_available_tools(self):
        """prefilter is always implicitly available."""
        assert is_class_covered("CWE-120", "", "", {}) is True

    def test_race_condition_not_covered(self):
        """Race conditions (CWE-367) only covered by prefilter (TOCTOU)."""
        assert is_class_covered("CWE-367", "", "", self.NO_TOOLS) is True

    def test_race_mechanism_dark_without_coccinelle(self):
        """Lock races (CWE-362) are coccinelle-only — dark when absent."""
        assert is_class_covered(
            "", "race condition on shared counter", "", self.NO_TOOLS,
        ) is False

    def test_race_mechanism_covered_with_coccinelle(self):
        assert is_class_covered(
            "", "race condition on shared counter", "",
            {"coccinelle": True},
        ) is True

    def test_ssrf_needs_semgrep_or_codeql(self):
        tools = {"joern": True, "codeql": False, "semgrep": False,
                 "coccinelle": True}
        assert is_class_covered("CWE-918", "", "", tools) is False


class TestGateResolutionIntegration:
    """Test the three-way resolution logic end to end."""

    def test_covered_class_resolves_clean(self):
        """SQL injection (covered by prefilter+semgrep) + no corroboration → clean."""
        covered = is_class_covered("CWE-89", "", "", {"semgrep": True})
        assert covered is True  # → would resolve to clean

    def test_uncovered_class_resolves_dark(self):
        """Logic error (no CWE mapping) + no corroboration → dark."""
        covered = is_class_covered("", "logic error", "", {"semgrep": True})
        assert covered is False  # → would resolve to dark

    def test_incomplete_map_conservative(self):
        """CWE not in map → False → dark. Fails safe."""
        covered = is_class_covered("CWE-1234", "", "", {"semgrep": True})
        assert covered is False
