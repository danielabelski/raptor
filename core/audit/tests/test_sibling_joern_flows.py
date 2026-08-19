"""Staleness gate for the sibling joern-flow import."""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.joern_backend import import_sibling_joern_flows


def _mk_run(
    project: Path,
    name: str,
    *,
    flows: dict | None = None,
    content_hash: str | None = None,
    target: str | None = None,
) -> Path:
    run = project / name
    run.mkdir(parents=True)
    manifest: dict = {"status": "completed"}
    if content_hash is not None:
        manifest["content_hash"] = content_hash
    if target is not None:
        manifest["target_path"] = target
    (run / ".raptor-run.json").write_text(
        json.dumps(manifest), encoding="utf-8",
    )
    if flows is not None:
        (run / "joern-flows.json").write_text(
            json.dumps(flows), encoding="utf-8",
        )
    return run


class TestSiblingStalenessGate:
    def test_matching_hash_imports(self, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        out_dir = _mk_run(project, "current", content_hash="aaaa1111")
        _mk_run(
            project, "older",
            flows={"a.c:f": [{"sink": "system"}]},
            content_hash="aaaa1111",
        )
        imported = import_sibling_joern_flows(out_dir)
        assert imported == {"a.c:f": [{"sink": "system"}]}

    def test_mismatched_hash_skipped(self, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        out_dir = _mk_run(project, "current", content_hash="aaaa1111")
        _mk_run(
            project, "older",
            flows={"a.c:f": [{"sink": "system"}]},
            content_hash="bbbb2222",
        )
        assert import_sibling_joern_flows(out_dir) is None

    def test_legacy_sibling_without_hash_imports(
        self, tmp_path: Path,
    ) -> None:
        project = tmp_path / "proj"
        out_dir = _mk_run(project, "current", content_hash="aaaa1111")
        _mk_run(project, "older", flows={"a.c:f": [{"sink": "system"}]})
        imported = import_sibling_joern_flows(out_dir)
        assert imported == {"a.c:f": [{"sink": "system"}]}

    def test_unknown_current_hash_imports(self, tmp_path: Path) -> None:
        """When the current run's hash is unavailable (no manifest hash,
        no target tree) the gate cannot decide — import as before."""
        project = tmp_path / "proj"
        out_dir = _mk_run(project, "current")
        _mk_run(
            project, "older",
            flows={"a.c:f": [{"sink": "system"}]},
            content_hash="bbbb2222",
        )
        imported = import_sibling_joern_flows(out_dir)
        assert imported == {"a.c:f": [{"sink": "system"}]}

    def test_mixed_siblings_only_fresh_imported(
        self, tmp_path: Path,
    ) -> None:
        project = tmp_path / "proj"
        out_dir = _mk_run(project, "current", content_hash="aaaa1111")
        _mk_run(
            project, "fresh",
            flows={"a.c:f": [{"sink": "system"}]},
            content_hash="aaaa1111",
        )
        _mk_run(
            project, "stale",
            flows={"b.c:g": [{"sink": "exec"}]},
            content_hash="cccc3333",
        )
        imported = import_sibling_joern_flows(out_dir)
        assert imported == {"a.c:f": [{"sink": "system"}]}
