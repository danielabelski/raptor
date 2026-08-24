"""Graduation-dir resolution matrix (the engine-rules WRITE site).

Graduated rules load and execute as trusted scanner config, so WHERE
graduation writes is a privilege decision: pinned project → the
project store (target-gated), foreign target → the run's own
target-keyed standalone dir, pin-less legacy dirs → suppressed.
"""
from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.audit.rules_dirs import (
    graduation_dir,
    standalone_read_candidates,
    target_rules_key,
)
from core.json import save_json
from core.project.project import ProjectManager


class GraduationDirMatrixTest(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.target = self.root / "code"
        self.target.mkdir()
        self.projects_dir = self.root / "projects"
        self.mgr = ProjectManager(projects_dir=self.projects_dir)
        self.proj = self.mgr.create(
            "gradproj", str(self.target),
            output_dir=str(self.root / "out" / "gradproj"))
        for p in (
            patch("core.project.project.PROJECTS_DIR", self.projects_dir),
        ):
            p.start()
            self.addCleanup(p.stop)

    def _run(self, project, target=None, source="session") -> Path:
        d = Path(self.proj.output_dir) / "audit_1"
        d.mkdir(parents=True, exist_ok=True)
        meta = {"status": "completed", "project": project,
                "project_source": source}
        if target is not None:
            meta["target_path"] = str(target)
        save_json(d / ".raptor-run.json", meta)
        return d

    def test_pinned_matching_target_writes_the_project_store(self):
        d = self._run("gradproj", target=self.target)
        out = graduation_dir(d, self.target)
        self.assertEqual(out, Path(self.proj.output_dir) / "engine-rules")

    def test_pinned_foreign_target_redirects_to_target_keyed_dir(self):
        other = self.root / "other"
        other.mkdir()
        d = self._run("gradproj", target=self.target)
        with patch("core.config.RaptorConfig.get_out_dir",
                   return_value=self.root / "out"):
            out = graduation_dir(d, other)
        self.assertIsNotNone(out)
        self.assertNotIn("gradproj", str(out))
        self.assertIn(target_rules_key(other), str(out))

    def test_pin_null_standalone_writes_target_keyed_dir(self):
        d = self._run(None, target=self.target, source="none")
        with patch("core.config.RaptorConfig.get_out_dir",
                   return_value=self.root / "out"):
            out = graduation_dir(d, self.target)
        self.assertIsNotNone(out)
        self.assertIn(target_rules_key(self.target), str(out))

    def test_pinless_legacy_dir_is_suppressed(self):
        d = Path(self.proj.output_dir) / "audit_legacy"
        d.mkdir(parents=True)
        save_json(d / ".raptor-run.json", {"status": "completed"})
        self.assertIsNone(graduation_dir(d, self.target))

    def test_no_out_dir_is_suppressed(self):
        self.assertIsNone(graduation_dir(None, self.target))

    def test_read_candidates_are_target_keyed(self):
        with patch("core.config.RaptorConfig.get_out_dir",
                   return_value=self.root / "out"):
            cands = standalone_read_candidates(self.target)
        self.assertEqual(len(cands), 1)
        self.assertIn(target_rules_key(self.target), str(cands[0]))
        self.assertEqual(standalone_read_candidates(None), [])


if __name__ == "__main__":
    unittest.main()
