

class TestHostileRepCopy:
    """prepare_working_copy against attacker-shaped .rep trees."""

    def _project(self, tmp_path):
        proj = tmp_path / "proj"
        proj.mkdir()
        gpr = proj / "p.gpr"
        gpr.write_text("x")
        rep = proj / "p.rep"
        rep.mkdir()
        return gpr, rep

    def test_symlinks_skipped_not_dereferenced(self, tmp_path):
        from packages.ghidra.project_util import prepare_working_copy
        gpr, rep = self._project(tmp_path)
        secret = tmp_path / "secret"
        secret.write_text("SENSITIVE")
        (rep / "stolen").symlink_to(secret)
        (rep / "zero").symlink_to("/dev/zero")
        (rep / "loop").symlink_to(rep)
        (rep / "ok.txt").write_text("fine")
        work = tmp_path / "work"
        work.mkdir()
        prepare_working_copy(gpr, work)
        copied = sorted(p.name for p in (work / "p.rep").rglob("*"))
        assert copied == ["ok.txt"]

    def test_size_cap_enforced(self, tmp_path, monkeypatch):
        import pytest
        from packages.ghidra import project_util
        from packages.ghidra.project_util import prepare_working_copy
        gpr, rep = self._project(tmp_path)
        (rep / "big.bin").write_bytes(b"A" * 4096)
        monkeypatch.setattr(project_util, "MAX_REP_COPY_BYTES", 1024)
        work = tmp_path / "work"
        work.mkdir()
        with pytest.raises(ValueError, match="working-copy cap"):
            prepare_working_copy(gpr, work)

    def test_symlinked_gpr_rejected(self, tmp_path):
        import pytest
        from packages.ghidra.project_util import prepare_working_copy
        gpr, rep = self._project(tmp_path)
        link = tmp_path / "link.gpr"
        link.symlink_to(gpr)
        work = tmp_path / "work"
        work.mkdir()
        with pytest.raises(ValueError, match="symlink"):
            prepare_working_copy(link, work)
