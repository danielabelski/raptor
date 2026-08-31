"""Builder input-hardening regressions.

Covers: single-file shebang targets, scope validation, walk-time
exclude honouring, FIFO-safe file collection, and the workflow
content predicate.

Hermetic: every build here runs on a tiny tempdir tree (sequential
path — no worker pools), no network, no external binaries.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from core.inventory.builder import (
    _collect_source_files,
    _is_github_workflow,
    build_inventory,
)


# ---------------------------------------------------------------------------
# Single-file targets
# ---------------------------------------------------------------------------


def test_single_file_shebang_script_target(tmp_path: Path) -> None:
    script = tmp_path / "deploy"
    script.write_text("#!/usr/bin/env python3\nprint(1)\n")
    inv = build_inventory(str(script), output_dir=str(tmp_path / "out"),
                          parallel=False)
    assert inv["total_files"] == 1


def test_single_file_unknown_extension_still_rejected(
    tmp_path: Path,
) -> None:
    f = tmp_path / "data.bin"
    f.write_text("not source")
    with pytest.raises(ValueError, match="no recognized source extension"):
        build_inventory(str(f), output_dir=str(tmp_path / "out"))


# ---------------------------------------------------------------------------
# Scope validation
# ---------------------------------------------------------------------------


class TestScopeValidation:
    @pytest.fixture()
    def target(self, tmp_path: Path) -> Path:
        t = tmp_path / "proj"
        (t / "src").mkdir(parents=True)
        (t / "src" / "m.py").write_text("def f():\n    pass\n")
        (t / "other.py").write_text("def g():\n    pass\n")
        return t

    def test_absolute_scope_outside_target_rejected(
        self, target: Path, tmp_path: Path,
    ) -> None:
        # pathlib joins DISCARD the lhs for absolute rhs — pre-fix the
        # inventory silently emptied instead of erroring.
        with pytest.raises(ValueError, match="escapes the target"):
            build_inventory(str(target),
                            output_dir=str(tmp_path / "out"),
                            scope=["/somewhere/src"])

    def test_root_scope_rejected(self, target: Path, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="escapes the target"):
            build_inventory(str(target),
                            output_dir=str(tmp_path / "out"), scope=["/"])

    def test_dotdot_scope_rejected(self, target: Path,
                                   tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="escapes the target"):
            build_inventory(str(target),
                            output_dir=str(tmp_path / "out"),
                            scope=["../escape"])

    def test_relative_scope_filters(self, target: Path,
                                    tmp_path: Path) -> None:
        inv = build_inventory(str(target),
                              output_dir=str(tmp_path / "out"),
                              scope=["src"], parallel=False)
        assert [f["path"] for f in inv["files"]] == ["src/m.py"]

    def test_absolute_scope_under_target_accepted(
        self, target: Path, tmp_path: Path,
    ) -> None:
        inv = build_inventory(str(target),
                              output_dir=str(tmp_path / "out"),
                              scope=[str(target / "src")], parallel=False)
        assert [f["path"] for f in inv["files"]] == ["src/m.py"]


# ---------------------------------------------------------------------------
# Walk-time exclude honouring
# ---------------------------------------------------------------------------


class TestWalkHonoursCallerExcludes:
    def test_empty_exclude_list_reincludes_default_dirs(
        self, tmp_path: Path,
    ) -> None:
        t = tmp_path / "proj"
        (t / "vendor").mkdir(parents=True)
        (t / "vendor" / "v.py").write_text("def v():\n    pass\n")
        (t / "main.py").write_text("def m():\n    pass\n")
        inv = build_inventory(str(t), output_dir=str(tmp_path / "o1"),
                              exclude_patterns=[], parallel=False)
        assert "vendor/v.py" in [f["path"] for f in inv["files"]]
        # Artifact truthfulness: the applied list is the recorded list.
        assert inv["excluded_patterns"] == []

    def test_default_excludes_still_prune(self, tmp_path: Path) -> None:
        t = tmp_path / "proj"
        (t / "vendor").mkdir(parents=True)
        (t / "vendor" / "v.py").write_text("def v():\n    pass\n")
        (t / "main.py").write_text("def m():\n    pass\n")
        inv = build_inventory(str(t), output_dir=str(tmp_path / "o2"),
                              parallel=False)
        assert "vendor/v.py" not in [f["path"] for f in inv["files"]]


# ---------------------------------------------------------------------------
# FIFO-safe collection
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX-only FIFO test")
def test_collection_ignores_fifos(tmp_path: Path) -> None:
    """The extensionless-shebang probe opens directory entries in the
    MAIN process; a plain open() of a reader-less FIFO blocks forever
    and wedged the whole inventory build."""
    (tmp_path / "a.py").write_text("def f():\n    pass\n")
    os.mkfifo(tmp_path / "apipe")
    files, _pruned = _collect_source_files(tmp_path, {".py"})
    assert [f.name for f in files] == ["a.py"]


# ---------------------------------------------------------------------------
# Workflow predicate parity with the yaml extractor
# ---------------------------------------------------------------------------


def test_jobs_block_without_trigger_key_is_workflow_shaped() -> None:
    # The extractor emits job items for any top-level jobs: block; the
    # builder gate must not additionally require a trigger key (Azure
    # Pipelines yaml, or a roundtripped workflow whose on: became
    # true:, was excluded as unreviewable).
    azure = "trigger:\n- main\njobs:\n  build:\n    steps: []\n"
    assert _is_github_workflow("ci/pipeline.yml", azure)
    assert not _is_github_workflow("cfg/app.yml", "server:\n  port: 80\n")
    # Scalar jobs value — the extractor yields nothing for it either.
    assert not _is_github_workflow("config.yml", "jobs: none\n")
