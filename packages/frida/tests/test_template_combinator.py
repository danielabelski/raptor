"""Tests for the --template a+b combinator."""

from __future__ import annotations

from packages.frida.runner import load_script_source


class TestTemplateCombinator:
    def test_combined_templates_render_and_parse(self):
        source, origin = load_script_source(
            "seed-harvest+exec-and-load", None)
        assert origin == "template:seed-harvest+exec-and-load"
        # Both templates present, each in its own IIFE (they share
        # top-level names; raw concatenation is a SyntaxError).
        assert source.count(";(function () {") == 2
        assert "seed-harvest loaded" in source
        assert "exec-and-load loaded" in source
        # Slots rendered for both.
        assert "/*__INGEST_HOOKS__*/ []" not in source
        assert "/*__EXEC_HOOKS__*/ []" not in source

    def test_unknown_member_rejected(self):
        import pytest
        with pytest.raises(FileNotFoundError):
            load_script_source("seed-harvest+no-such-template", None)

    def test_single_name_unchanged(self):
        _source, origin = load_script_source("api-trace", None)
        assert origin == "template:api-trace"


class TestCombinatorValidation:
    def test_duplicate_member_rejected(self):
        import pytest
        with pytest.raises(ValueError, match="duplicate"):
            load_script_source("seed-harvest+seed-harvest", None)

    def test_empty_member_rejected(self):
        import pytest
        with pytest.raises(ValueError):
            load_script_source("seed-harvest+", None)
