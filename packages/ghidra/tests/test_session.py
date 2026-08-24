"""Tests for packages.ghidra.session — PyGhidra session layer.

Unit tests mock the JVM/PyGhidra layer. The live integration test
(test_live_import) requires Ghidra + PyGhidra and a real .gpr project.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.ghidra.session import GhidraSession, GhidraSessionError
from packages.ghidra.project_util import fix_owner, prepare_working_copy


MINIMAL_GPR = """\
<?xml version="1.0" encoding="UTF-8"?>
<FILE_INFO>
    <BASIC_INFO>
        <STATE NAME="OWNER" TYPE="string" VALUE="testuser" />
    </BASIC_INFO>
</FILE_INFO>
"""


@pytest.fixture
def gpr_project(tmp_path):
    """Create a minimal .gpr project structure."""
    gpr = tmp_path / "test.gpr"
    gpr.write_text(MINIMAL_GPR, encoding="utf-8")
    rep = tmp_path / "test.rep"
    rep.mkdir()
    (rep / "project.prp").write_text(MINIMAL_GPR, encoding="utf-8")
    idata = rep / "idata"
    idata.mkdir()
    (idata / "test_binary").mkdir()
    return gpr


class TestGhidraSessionInit:
    def test_no_program_before_open(self):
        session = GhidraSession()
        with pytest.raises(GhidraSessionError, match="no program open"):
            session.export()

    def test_decompile_before_open(self):
        session = GhidraSession()
        with pytest.raises(GhidraSessionError, match="no program open"):
            session.decompile_function("main")

    def test_close_is_idempotent(self):
        session = GhidraSession()
        session.close()
        session.close()

    def test_context_manager(self):
        with GhidraSession() as session:
            assert session is not None

    def test_func_index_cleared_on_close(self):
        session = GhidraSession()
        session._func_index = {"fake": object()}
        session.close()
        assert session._func_index is None


class TestWorkingCopy:
    def test_creates_copy(self, gpr_project, tmp_path):
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        work_gpr = prepare_working_copy(gpr_project, work_dir)

        assert work_gpr.exists()
        assert work_gpr.parent == work_dir
        assert (work_dir / "test.rep").is_dir()
        assert (work_dir / "test.rep" / "project.prp").is_file()

    def test_fixes_owner(self, gpr_project, tmp_path):
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        prepare_working_copy(gpr_project, work_dir)

        import getpass
        import xml.etree.ElementTree as ET

        prp = work_dir / "test.rep" / "project.prp"
        tree = ET.parse(prp)
        for state in tree.getroot().iter("STATE"):
            if state.get("NAME") == "OWNER":
                assert state.get("VALUE") == getpass.getuser()

    def test_removes_lock(self, gpr_project, tmp_path):
        lock = gpr_project.parent / "test.lock"
        lock.write_text("locked", encoding="utf-8")

        work_dir = tmp_path / "work"
        work_dir.mkdir()
        prepare_working_copy(gpr_project, work_dir)

        assert not (work_dir / "test.lock").exists()
        assert lock.exists()  # original untouched

    def test_empty_gpr_copied(self, tmp_path):
        """Ghidra 11.x empty .gpr files are copied correctly."""
        gpr = tmp_path / "empty.gpr"
        gpr.write_text("", encoding="utf-8")
        rep = tmp_path / "empty.rep"
        rep.mkdir()
        (rep / "project.prp").write_text(MINIMAL_GPR, encoding="utf-8")

        work_dir = tmp_path / "work"
        work_dir.mkdir()
        work_gpr = prepare_working_copy(gpr, work_dir)
        assert work_gpr.stat().st_size == 0
        assert (work_dir / "empty.rep" / "project.prp").is_file()


class TestFixOwner:
    def test_patches_different_user(self, tmp_path):
        prp = tmp_path / "project.prp"
        prp.write_text(
            '<?xml version="1.0"?>\n<FILE_INFO>\n'
            '  <STATE NAME="OWNER" TYPE="string" VALUE="otheruser" />\n'
            "</FILE_INFO>\n",
            encoding="utf-8",
        )
        assert fix_owner(prp) is True

        import getpass
        import xml.etree.ElementTree as ET

        tree = ET.parse(prp)
        for state in tree.getroot().iter("STATE"):
            if state.get("NAME") == "OWNER":
                assert state.get("VALUE") == getpass.getuser()

    def test_skips_same_user(self, tmp_path):
        import getpass

        prp = tmp_path / "project.prp"
        prp.write_text(
            '<?xml version="1.0"?>\n<FILE_INFO>\n'
            f'  <STATE NAME="OWNER" TYPE="string" VALUE="{getpass.getuser()}" />\n'
            "</FILE_INFO>\n",
            encoding="utf-8",
        )
        assert fix_owner(prp) is False

    def test_handles_missing_file(self, tmp_path):
        assert fix_owner(tmp_path / "nope.prp") is False

    def test_handles_malformed_xml(self, tmp_path):
        prp = tmp_path / "project.prp"
        prp.write_text("not xml {{{", encoding="utf-8")
        assert fix_owner(prp) is False


class TestListPrograms:
    def test_no_project(self):
        session = GhidraSession()
        assert session.list_programs() == []


class TestEnsureJvm:
    def test_calls_pyghidra_start(self):
        GhidraSession._jvm_started = False
        try:
            mock_pyghidra = MagicMock()
            mock_pyghidra.api.started.return_value = False
            with patch.dict("sys.modules", {"pyghidra": mock_pyghidra, "pyghidra.api": mock_pyghidra.api}), \
                 patch.dict("os.environ", {"GHIDRA_INSTALL_DIR": "/opt/ghidra"}):
                GhidraSession.ensure_jvm()
            mock_pyghidra.start.assert_called_once()
            assert GhidraSession._jvm_started is True
        finally:
            GhidraSession._jvm_started = False

    def test_skips_if_already_started(self):
        GhidraSession._jvm_started = True
        try:
            GhidraSession.ensure_jvm()  # should not raise
        finally:
            GhidraSession._jvm_started = False


class TestFindInstallDir:
    def test_derives_from_analyzeHeadless(self, tmp_path):
        support = tmp_path / "ghidra" / "support"
        support.mkdir(parents=True)
        headless = support / "analyzeHeadless"
        headless.write_text("#!/bin/sh\n", encoding="utf-8")
        headless.chmod(0o755)

        with patch("shutil.which", return_value=str(headless)):
            result = GhidraSession._find_install_dir()
        assert result == tmp_path / "ghidra"

    def test_returns_none_when_not_found(self):
        with patch("shutil.which", return_value=None):
            assert GhidraSession._find_install_dir() is None

    def test_returns_none_when_not_in_support(self, tmp_path):
        headless = tmp_path / "analyzeHeadless"
        headless.write_text("#!/bin/sh\n", encoding="utf-8")
        headless.chmod(0o755)

        with patch("shutil.which", return_value=str(headless)):
            assert GhidraSession._find_install_dir() is None

    def test_auto_detects_on_this_system(self):
        """Live test: verifies auto-detection works on this box."""
        import shutil as _shutil
        if not _shutil.which("analyzeHeadless"):
            pytest.skip("analyzeHeadless not on PATH")
        result = GhidraSession._find_install_dir()
        assert result is not None
        assert result.is_dir()


class TestDetectPyGhidra:
    def test_pyghidra_available(self):
        """Where the pyghidra module is installed, the probe reads
        True (CI and most hosts run headless-CLI-only: skip)."""
        import pytest
        pytest.importorskip("pyghidra")
        from packages.ghidra.detect import pyghidra_available
        assert pyghidra_available() is True

    def test_pyghidra_unavailable(self):
        from packages.ghidra.detect import pyghidra_available
        with patch("importlib.util.find_spec", return_value=None):
            assert pyghidra_available() is False
