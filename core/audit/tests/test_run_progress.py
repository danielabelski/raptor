"""Tests for the orchestrator's run-progress checkpoint writer."""

from __future__ import annotations

import json
from types import SimpleNamespace

from core.audit.orchestrator import _update_run_progress


class TestUpdateRunProgress:
    def test_writes_progress_into_extra(self, tmp_path) -> None:
        meta_path = tmp_path / ".raptor-run.json"
        meta_path.write_text(
            json.dumps({"status": "running", "extra": {}}),
            encoding="utf-8",
        )
        _update_run_progress(tmp_path, SimpleNamespace(reviewed=7))
        updated = json.loads(meta_path.read_text(encoding="utf-8"))
        assert updated["extra"]["progress"] == {"completed": 7}
        assert updated["status"] == "running"

    def test_preserves_concurrently_set_terminal_status(
        self, tmp_path,
    ) -> None:
        """A lifecycle writer marking the run interrupted between
        checkpoints must not be clobbered back to running."""
        meta_path = tmp_path / ".raptor-run.json"
        meta_path.write_text(
            json.dumps({
                "status": "interrupted",
                "extra": {"interrupt_reason": "sigterm"},
            }),
            encoding="utf-8",
        )
        _update_run_progress(tmp_path, SimpleNamespace(reviewed=3))
        updated = json.loads(meta_path.read_text(encoding="utf-8"))
        assert updated["status"] == "interrupted"
        assert updated["extra"]["interrupt_reason"] == "sigterm"
        assert updated["extra"]["progress"] == {"completed": 3}

    def test_missing_metadata_is_noop(self, tmp_path) -> None:
        _update_run_progress(tmp_path, SimpleNamespace(reviewed=1))
        assert not (tmp_path / ".raptor-run.json").exists()

    def test_malformed_metadata_is_noop(self, tmp_path) -> None:
        meta_path = tmp_path / ".raptor-run.json"
        meta_path.write_text("[1, 2, 3]", encoding="utf-8")
        _update_run_progress(tmp_path, SimpleNamespace(reviewed=1))
        assert json.loads(meta_path.read_text(encoding="utf-8")) == [1, 2, 3]
