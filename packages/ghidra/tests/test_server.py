"""Tests for the persistent sandboxed Ghidra server."""

import pytest

from packages.ghidra.detect import pyghidra_available


class TestServerGating:
    def test_requires_pyghidra(self, tmp_path, monkeypatch):
        import packages.ghidra.server as server_mod
        monkeypatch.setattr(
            server_mod, "pyghidra_available", lambda: False,
        )
        gpr = tmp_path / "p.gpr"
        gpr.write_text("")
        with pytest.raises(server_mod.GhidraServerError, match="pyghidra"):
            server_mod.GhidraServer(gpr)

    def test_persist_requires_start(self, tmp_path, monkeypatch):
        import packages.ghidra.server as server_mod
        monkeypatch.setattr(
            server_mod, "pyghidra_available", lambda: True,
        )
        gpr = tmp_path / "p.gpr"
        gpr.write_text("")
        srv = server_mod.GhidraServer(gpr)
        with pytest.raises(server_mod.GhidraServerError, match="not started"):
            srv.persist_enriched(tmp_path / "out")


class TestWorkerProtocol:
    """Worker protocol logic without a JVM (unknown op, bad JSON)."""

    def test_unknown_op_rejected(self):
        from packages.ghidra import server_worker
        session = server_worker._Session()
        with pytest.raises(RuntimeError, match="unknown op"):
            server_worker._handle(session, {"op": "frobnicate"})

    def test_ops_require_open_project(self):
        from packages.ghidra import server_worker
        session = server_worker._Session()
        with pytest.raises(RuntimeError, match="no project open"):
            server_worker._handle(
                session, {"op": "decompile", "function": "main"},
            )


@pytest.mark.integration
@pytest.mark.skipif(
    not pyghidra_available(), reason="pyghidra not installed",
)
class TestServerLive:
    """Full boot→open→decompile against a real project.

    Marked integration (deselected by default): builds a Ghidra
    project via analyzeHeadless (~15s JVM import) then exercises the
    sandboxed server end to end.
    """

    def test_boot_open_decompile_apply(self, tmp_path):
        import shutil as _shutil
        import subprocess
        headless = _shutil.which("analyzeHeadless")
        if headless is None:
            pytest.skip("analyzeHeadless not on PATH")
        proj_dir = tmp_path / "proj"
        proj_dir.mkdir()
        # Full analysis (no -noanalysis): function definitions are
        # what the decompile assertion needs, and /bin/true is tiny.
        r = subprocess.run(
            [headless, str(proj_dir), "probe",
             "-import", "/bin/true"],
            capture_output=True, text=True, timeout=300,
        )
        if r.returncode != 0:
            pytest.skip(f"project build failed: {r.stderr[-200:]}")

        from packages.ghidra.server import GhidraServer
        with GhidraServer(proj_dir / "probe.gpr") as srv:
            info = srv.open()
            assert info["programs"]
            programs = srv.list_programs()
            assert programs == info["programs"]
            code = srv.decompile("entry")
            assert "(" in code
            applied = srv.apply_enrichments({
                "comments": [{"function": "entry", "kind": "plate",
                              "text": "RAPTOR: live test"}],
                "bookmarks": [],
            })
            assert applied["comments"] == 1
            kept = srv.persist_enriched(tmp_path / "keep")
        assert kept.exists()
