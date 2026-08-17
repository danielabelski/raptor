"""Detector-correctness tests for the dead-code/miswiring scan.

Two false-positive classes the daily scan produced:

- pytest xunit / unittest module lifecycle hooks (``setup_method``,
  ``setUpModule``, ...) are resolved by name by the test runner and
  never referenced in code — the dead-symbol pass flagged them dead.
- The reference text corpus only covered core/packages/plugins/
  libexec/engine, so symbols invoked from skill instructions
  (``.claude/skills/``), documentation (``docs/``), launcher shims
  (``bin/``), personas (``tiers/``) or CI scripts (``.github/``)
  counted as dead.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "check_miswiring.py"


def _load_detector():
    spec = importlib.util.spec_from_file_location("check_miswiring", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def detector():
    return _load_detector()


def _index(detector, root: Path):
    idx = detector.RepoIndex(root)
    idx.build()
    return idx


def _dead_names(detector, root: Path) -> set[str]:
    idx = _index(detector, root)
    findings, _sup = detector.find_dead(idx)
    return {f["name"] for f in findings}


XUNIT_HOOKS = [
    "setUpModule", "tearDownModule",
    "setup_module", "teardown_module",
    "setup_function", "teardown_function",
]
XUNIT_METHOD_HOOKS = [
    "setup_class", "teardown_class",
    "setup_method", "teardown_method",
]


class TestXunitLifecycleHooks:
    def test_module_level_hooks_not_flagged_dead(self, detector, tmp_path):
        pkg = tmp_path / "core" / "foo" / "tests"
        pkg.mkdir(parents=True)
        body = "\n\n".join(
            f"def {name}():\n    pass" for name in XUNIT_HOOKS
        )
        (pkg / "test_thing.py").write_text(body + "\n", encoding="utf-8")

        dead = _dead_names(detector, tmp_path)
        for name in XUNIT_HOOKS:
            assert name not in dead, (
                f"live pytest lifecycle hook {name} classified dead"
            )

    def test_class_level_hooks_not_flagged_dead(self, detector, tmp_path):
        pkg = tmp_path / "core" / "foo" / "tests"
        pkg.mkdir(parents=True)
        methods = "\n\n".join(
            f"    def {name}(self):\n        pass"
            for name in XUNIT_METHOD_HOOKS
        )
        (pkg / "test_thing.py").write_text(
            "class TestThing:\n" + methods + "\n", encoding="utf-8",
        )

        dead = _dead_names(detector, tmp_path)
        for name in XUNIT_METHOD_HOOKS:
            assert not any(name in d for d in dead), (
                f"live pytest lifecycle hook {name} classified dead"
            )

    def test_genuinely_dead_test_helper_still_flagged(self, detector, tmp_path):
        """The hook allowlist must not blind the scan to real dead code."""
        pkg = tmp_path / "core" / "foo" / "tests"
        pkg.mkdir(parents=True)
        (pkg / "test_thing.py").write_text(
            "def orphan_helper_nobody_calls():\n    pass\n",
            encoding="utf-8",
        )
        assert "orphan_helper_nobody_calls" in _dead_names(detector, tmp_path)


class TestTextCorpusRoots:
    def _repo_with_symbol(self, tmp_path) -> Path:
        pkg = tmp_path / "core" / "api"
        pkg.mkdir(parents=True)
        (pkg / "surface.py").write_text(
            "def skill_invoked_entry():\n    return 1\n", encoding="utf-8",
        )
        return tmp_path

    def test_symbol_without_any_reference_is_dead(self, detector, tmp_path):
        root = self._repo_with_symbol(tmp_path)
        assert "skill_invoked_entry" in _dead_names(detector, root)

    @pytest.mark.parametrize("rel", [
        "docs/architecture.md",
        ".claude/skills/exploit-dev/instructions.md",
        "tiers/personas/researcher.md",
        ".github/scripts/helper_notes.md",
    ])
    def test_reference_from_text_root_keeps_symbol_alive(
        self, detector, tmp_path, rel,
    ):
        root = self._repo_with_symbol(tmp_path)
        doc = root / rel
        doc.parent.mkdir(parents=True, exist_ok=True)
        doc.write_text(
            "Call `skill_invoked_entry()` to load the context.\n",
            encoding="utf-8",
        )
        assert "skill_invoked_entry" not in _dead_names(detector, root)

    def test_bin_shim_reference_keeps_symbol_alive(self, detector, tmp_path):
        root = self._repo_with_symbol(tmp_path)
        shim = root / "bin" / "raptor-helper.sh"
        shim.parent.mkdir(parents=True)
        shim.write_text(
            "python3 -c 'from core.api.surface import skill_invoked_entry'\n",
            encoding="utf-8",
        )
        assert "skill_invoked_entry" not in _dead_names(detector, root)

    def test_text_roots_never_join_python_index(self, detector, tmp_path):
        """A .py under .github is reference text, not indexed code —
        its own defs must not become dead-symbol candidates."""
        root = self._repo_with_symbol(tmp_path)
        ci = root / ".github" / "scripts" / "ci_tool.py"
        ci.parent.mkdir(parents=True)
        ci.write_text(
            "def ci_only_helper():\n    pass\n", encoding="utf-8",
        )
        idx = _index(detector, root)
        assert all(
            ".github" not in m.path.parts for m in idx.module_list
        )
        assert "ci_only_helper" not in _dead_names(detector, root)

    def test_worktrees_under_claude_are_skipped(self, detector, tmp_path):
        root = self._repo_with_symbol(tmp_path)
        wt = root / ".claude" / "worktrees" / "scratch" / "notes.md"
        wt.parent.mkdir(parents=True)
        wt.write_text("skill_invoked_entry\n", encoding="utf-8")
        assert "skill_invoked_entry" in _dead_names(detector, root)


class TestBaselineCorpusExclusion:
    """The baseline file names every baselined symbol; if it joined the
    reference corpus it would self-suppress exactly the findings it
    records, so baselined entries could never fire or go stale again."""

    def _repo_with_dead_symbol(self, tmp_path) -> Path:
        pkg = tmp_path / "core" / "api"
        pkg.mkdir(parents=True)
        (pkg / "surface.py").write_text(
            "def orphaned_entry_nobody_calls():\n    return 1\n",
            encoding="utf-8",
        )
        return tmp_path

    def test_baseline_file_does_not_self_suppress(self, detector, tmp_path):
        root = self._repo_with_dead_symbol(tmp_path)
        bl = root / ".github" / "scripts" / "miswiring_baseline.json"
        bl.parent.mkdir(parents=True)
        bl.write_text(
            '{"entries": {"dead:dead_function:core/api/surface.py:'
            'orphaned_entry_nobody_calls": {"note": "triaged"}}}\n',
            encoding="utf-8",
        )
        assert "orphaned_entry_nobody_calls" in _dead_names(detector, root)

    def test_other_github_text_still_joins_corpus(self, detector, tmp_path):
        """The exclusion is surgical: any other .github text file still
        keeps referenced symbols alive."""
        root = self._repo_with_dead_symbol(tmp_path)
        notes = root / ".github" / "scripts" / "notes.json"
        notes.parent.mkdir(parents=True)
        notes.write_text(
            '{"hint": "call orphaned_entry_nobody_calls on boot"}\n',
            encoding="utf-8",
        )
        assert "orphaned_entry_nobody_calls" not in _dead_names(
            detector, root,
        )

    def test_baseline_mention_does_not_count_as_artifact_reference(
        self, detector, tmp_path,
    ):
        """Artifact names inside the baseline's own keys must not feed
        the artifact occurrence scan."""
        pkg = tmp_path / "core" / "foo"
        pkg.mkdir(parents=True)
        (pkg / "writer.py").write_text(
            "import json\n"
            "\n"
            "\n"
            "def emit(out_dir, rows):\n"
            "    with open(out_dir / 'run-report.json', 'w') as f:\n"
            "        json.dump(rows, f)\n",
            encoding="utf-8",
        )
        bl = tmp_path / ".github" / "scripts" / "miswiring_baseline.json"
        bl.parent.mkdir(parents=True)
        bl.write_text(
            '{"entries": {"artifacts:write_only_artifact::run-report.json":'
            ' {"note": "reader lands later"}}}\n',
            encoding="utf-8",
        )
        idx = _index(detector, tmp_path)
        findings, _sup = detector.find_artifacts(idx)
        assert any(
            f["kind"] == "write_only_artifact"
            and f["name"] == "run-report.json"
            and all("miswiring_baseline" not in m for m in f["mentions"])
            for f in findings
        )


class TestAtomicWriteIdiom:
    def test_tempfile_rename_writer_is_not_orphan_reader(
        self, detector, tmp_path,
    ):
        """A tempfile-then-rename writer names the artifact only where
        the destination path is built (next to an is_file() guard);
        the +/-2-line window used to classify that as read-only and
        report the artifact as an orphan reader."""
        pkg = tmp_path / "core" / "foo"
        pkg.mkdir(parents=True)
        (pkg / "writer.py").write_text(
            "import json\n"
            "import os\n"
            "import tempfile\n"
            "from pathlib import Path\n"
            "\n"
            "\n"
            "def record(output_dir, rows):\n"
            "    path = output_dir / 'accumulated-rows.json'\n"
            "    existing = []\n"
            "    if path.is_file():\n"
            "        existing = json.loads(path.read_text())\n"
            "    existing.extend(rows)\n"
            "    fd, tmp = tempfile.mkstemp(dir=str(output_dir))\n"
            "    with os.fdopen(fd, 'w') as f:\n"
            "        json.dump(existing, f)\n"
            "    Path(tmp).rename(path)\n",
            encoding="utf-8",
        )
        (pkg / "reader.py").write_text(
            "import json\n"
            "\n"
            "\n"
            "def consume(out_dir):\n"
            "    p = out_dir / 'accumulated-rows.json'\n"
            "    if p.is_file():\n"
            "        return json.loads(p.read_text())\n"
            "    return []\n",
            encoding="utf-8",
        )
        idx = _index(detector, tmp_path)
        findings, _sup = detector.find_artifacts(idx)
        orphans = [
            f for f in findings
            if f["kind"] == "orphan_reader"
            and f["name"] == "accumulated-rows.json"
        ]
        assert not orphans, (
            "tempfile+rename writer misclassified; artifact reported "
            f"as orphan reader: {orphans}"
        )
