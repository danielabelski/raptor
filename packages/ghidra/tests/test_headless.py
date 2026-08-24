"""Tests for the analyzeHeadless wrapper contracts."""


class TestCopyPreparedContract:
    def test_standalone_refuses_existing_destination(self, tmp_path):
        import pytest
        from packages.ghidra.headless import GhidraError, import_enrichments
        gpr = tmp_path / "p.gpr"
        gpr.write_text("x")
        dst = tmp_path / "out" / "p.gpr"
        dst.parent.mkdir()
        dst.write_text("pre-placed")
        with pytest.raises(GhidraError, match="already exists"):
            import_enrichments(gpr, tmp_path / "e.json", dst)

    def test_copy_prepared_requires_copy(self, tmp_path):
        import pytest
        from packages.ghidra.headless import GhidraError, import_enrichments
        gpr = tmp_path / "p.gpr"
        gpr.write_text("x")
        dst = tmp_path / "out" / "p.gpr"
        dst.parent.mkdir()
        with pytest.raises(GhidraError, match="no working copy"):
            import_enrichments(
                gpr, tmp_path / "e.json", dst, copy_prepared=True,
            )

    def test_name_mismatch_refused(self, tmp_path):
        import pytest
        from packages.ghidra.headless import GhidraError, import_enrichments
        gpr = tmp_path / "p.gpr"
        gpr.write_text("x")
        with pytest.raises(GhidraError, match="project name"):
            import_enrichments(
                gpr, tmp_path / "e.json", tmp_path / "renamed.gpr",
            )
