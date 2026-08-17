"""Tests for core.run.tmp_reaper — stale temp-artifact sweep.

All tests point the reaper at a private tmp_path via a monkeypatched
``tempfile.gettempdir`` so nothing touches the real system temp dir.
"""

import os
import socket
import subprocess
import time
from pathlib import Path

import pytest

from core.run.tmp_reaper import reap_stale_logs, reap_stale_tmp

_OLD = time.time() - 25 * 3600  # past the 24h default age floor


@pytest.fixture
def tmp_root(tmp_path, monkeypatch):
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.delenv("RAPTOR_TMP_REAP_MAX_AGE_H", raising=False)
    return tmp_path


def _make_old_dir(root, name, contents=()):
    d = root / name
    d.mkdir()
    for fname in contents:
        (d / fname).write_text("x")
    os.utime(d, (_OLD, _OLD))
    return d


class TestDirReaping:

    def test_stale_prefixed_dirs_reaped(self, tmp_root):
        dirs = [
            _make_old_dir(tmp_root, "raptor-llm-raptor-cafe0001-abc123"),
            _make_old_dir(tmp_root, "raptor-cc-cwd-abc123"),
            _make_old_dir(tmp_root, "raptor-joern-ws-abc123"),
            _make_old_dir(tmp_root, "raptor-calibrate-abc123"),
            _make_old_dir(tmp_root, "raptor_auto_abc123"),
            _make_old_dir(tmp_root, "raptor_git_frk_abc1"),
            _make_old_dir(tmp_root, "raptor_decomp_abc123"),
        ]
        reaped = reap_stale_tmp()
        assert sorted(reaped) == sorted(dirs)
        for d in dirs:
            assert not d.exists()

    def test_fresh_dir_kept(self, tmp_root):
        d = tmp_root / "raptor-llm-raptor-cafe0002-fresh1"
        d.mkdir()
        assert reap_stale_tmp() == []
        assert d.is_dir()

    def test_foreign_prefix_kept(self, tmp_root):
        d = _make_old_dir(tmp_root, "someone-elses-dir")
        assert reap_stale_tmp() == []
        assert d.is_dir()

    def test_observe_keep_dirs_not_reaped(self, tmp_root):
        # --keep / --out observe dirs are operator-preserved on purpose.
        d = _make_old_dir(
            tmp_root, "raptor-observe-abc123", [".sandbox-observe.jsonl"],
        )
        assert reap_stale_tmp() == []
        assert d.is_dir()

    def test_symlink_squatting_on_prefix_kept(self, tmp_root):
        target = tmp_root / "victim"
        target.mkdir()
        (target / "data.txt").write_text("precious")
        link = tmp_root / "raptor-llm-raptor-cafe0003-planted"
        link.symlink_to(target)
        os.utime(link, (_OLD, _OLD), follow_symlinks=False)
        assert reap_stale_tmp() == []
        assert link.is_symlink()
        assert (target / "data.txt").read_text() == "precious"

    def test_dir_with_answering_socket_kept_then_reaped(self, monkeypatch):
        # Own short root instead of the tmp_root fixture: AF_UNIX paths
        # cap at ~108 chars and a nested pytest basetemp (custom TMPDIR)
        # blows past it. Same workaround as test_proxy_netns_enforcement.
        import shutil
        import tempfile
        short_root = tempfile.mkdtemp(prefix="rpt_", dir="/tmp")
        monkeypatch.setattr("tempfile.gettempdir", lambda: short_root)
        monkeypatch.delenv("RAPTOR_TMP_REAP_MAX_AGE_H", raising=False)
        try:
            d = _make_old_dir(Path(short_root),
                              "raptor-llm-raptor-cafe0004-livesk")
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                srv.bind(str(d / "llm.sock"))
                srv.listen(1)
                os.utime(d, (_OLD, _OLD))
                assert reap_stale_tmp() == []
                assert d.is_dir()
            finally:
                srv.close()
            # Listener gone → ECONNREFUSED → dead → reaped.
            assert reap_stale_tmp() == [d]
            assert not d.exists()
        finally:
            shutil.rmtree(short_root, ignore_errors=True)

    def test_dir_serving_as_live_cwd_kept(self, tmp_root):
        d = _make_old_dir(tmp_root, "raptor-cc-cwd-livecwd")
        proc = subprocess.Popen(
            ["sleep", "30"], cwd=str(d),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            os.utime(d, (_OLD, _OLD))
            assert reap_stale_tmp() == []
            assert d.is_dir()
        finally:
            proc.terminate()
            proc.wait()


class TestFileReaping:

    def test_stale_sweep_yaml_and_joern_script_reaped(self, tmp_root):
        files = []
        for name in ("audit_sweep_ab12cd34.yaml", "wrapped-script42.sc",
                     "raptor-audit-cfg-ab12cd34.json"):
            f = tmp_root / name
            f.write_text("rules: []\n")
            os.utime(f, (_OLD, _OLD))
            files.append(f)
        reaped = reap_stale_tmp()
        assert sorted(reaped) == sorted(files)

    def test_fresh_sweep_yaml_kept(self, tmp_root):
        f = tmp_root / "audit_sweep_ab12cd34.yaml"
        f.write_text("rules: []\n")
        assert reap_stale_tmp() == []
        assert f.is_file()

    def test_prefix_without_suffix_kept(self, tmp_root):
        f = tmp_root / "audit_sweep_notes.txt"
        f.write_text("keep me")
        os.utime(f, (_OLD, _OLD))
        assert reap_stale_tmp() == []
        assert f.is_file()


class TestConfigAndSafety:

    def test_env_zero_disables_sweep(self, tmp_root, monkeypatch):
        d = _make_old_dir(tmp_root, "raptor-llm-raptor-cafe0005-nosweep")
        monkeypatch.setenv("RAPTOR_TMP_REAP_MAX_AGE_H", "0")
        assert reap_stale_tmp() == []
        assert d.is_dir()

    def test_env_shrinks_age_floor(self, tmp_root, monkeypatch):
        d = tmp_root / "raptor-llm-raptor-cafe0006-young1"
        d.mkdir()
        two_h = time.time() - 2 * 3600
        os.utime(d, (two_h, two_h))
        assert reap_stale_tmp() == []
        monkeypatch.setenv("RAPTOR_TMP_REAP_MAX_AGE_H", "1")
        assert reap_stale_tmp() == [d]

    def test_non_numeric_env_falls_back_to_default(self, tmp_root,
                                                   monkeypatch):
        d = _make_old_dir(tmp_root, "raptor-llm-raptor-cafe0007-badenv")
        monkeypatch.setenv("RAPTOR_TMP_REAP_MAX_AGE_H", "soon")
        assert reap_stale_tmp() == [d]

    def test_never_raises(self, tmp_root, monkeypatch):
        _make_old_dir(tmp_root, "raptor-llm-raptor-cafe0008-boom")

        def _boom(*a, **kw):
            raise RuntimeError("listdir exploded")

        monkeypatch.setattr(os, "listdir", _boom)
        assert reap_stale_tmp() == []


class TestLogReaping:

    @pytest.fixture
    def log_dir(self, tmp_path, monkeypatch):
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "LOG_DIR", tmp_path)
        monkeypatch.delenv("RAPTOR_LOG_REAP_MAX_AGE_D", raising=False)
        return tmp_path

    @staticmethod
    def _log(root, name, age_s):
        f = root / name
        f.write_text("{}\n")
        t = time.time() - age_s
        os.utime(f, (t, t))
        return f

    def test_old_log_reaped_fresh_kept(self, log_dir):
        old = self._log(log_dir, "raptor_1_pid1_1.jsonl", 15 * 86400)
        fresh = self._log(log_dir, "raptor_2_pid2_2.jsonl", 86400)
        assert reap_stale_logs() == [old]
        assert not old.exists()
        assert fresh.is_file()

    def test_non_log_files_kept(self, log_dir):
        other = self._log(log_dir, "notes.txt", 30 * 86400)
        assert reap_stale_logs() == []
        assert other.is_file()

    def test_env_zero_disables(self, log_dir, monkeypatch):
        old = self._log(log_dir, "raptor_1_pid1_1.jsonl", 30 * 86400)
        monkeypatch.setenv("RAPTOR_LOG_REAP_MAX_AGE_D", "0")
        assert reap_stale_logs() == []
        assert old.is_file()

    def test_missing_log_dir_is_noop(self, tmp_path, monkeypatch):
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "LOG_DIR", tmp_path / "absent")
        assert reap_stale_logs() == []


class TestStartRunHook:

    def test_start_run_invokes_sweeps(self, tmp_path, monkeypatch):
        import core.run.tmp_reaper as reaper_mod
        from core.run.metadata import start_run

        calls = []
        monkeypatch.setattr(
            reaper_mod, "reap_stale_tmp", lambda: calls.append("tmp") or [],
        )
        monkeypatch.setattr(
            reaper_mod, "reap_stale_logs", lambda: calls.append("logs") or [],
        )
        start_run(tmp_path / "run", "scan")
        assert calls == ["tmp", "logs"]
