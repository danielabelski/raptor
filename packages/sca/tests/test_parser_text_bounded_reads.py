"""Oversize-file bounds for the SCA text/TOML/YAML/XML target parsers.

Companion to ``test_supply_chain_bounded_reads.py`` (same shape, same
red-before-fix construction): every parser here reads a text-format
manifest from the scanned — attacker-controlled — repository. The
reads go through ``packages.sca.parsers._safe_read.read_bounded``
(``follow_symlinks=False``), which stat-gates size BEFORE the read
and refuses symlinked paths.

Each oversize fixture is a sparse file truncated past the 50 MB cap,
and each test asserts the gate's refusal warning — a whole-file read
that merely fails to parse cannot satisfy it, which is what makes
these red before the migration and green after.
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import pytest

from packages.sca.parsers._safe_read import _MAX_PARSER_BYTES

_SAFE_READ_LOGGER = "packages.sca.parsers._safe_read"
_REFUSAL = "refusing to read"


def _sparse_oversize(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        os.truncate(fh.fileno(), _MAX_PARSER_BYTES + 1)
    return path


@contextmanager
def _expect_refusal(caplog: pytest.LogCaptureFixture) -> Iterator[None]:
    """Assert the size/symlink gate refused the read — the degraded
    result must come from the bound, not from a failed parse of a
    fully-buffered file."""
    with caplog.at_level(logging.WARNING, logger=_SAFE_READ_LOGGER):
        yield
    assert _REFUSAL in caplog.text or "refusing symlinked" in caplog.text


class TestPnpmWorkspaceCatalogBound:
    """pnpm-workspace.yaml → yaml.safe_load was the last unbounded,
    symlink-following read-then-parse of a target manifest in the
    package."""

    def _get(self, root: Path):
        from packages.sca.parsers import _pnpm_catalog
        _pnpm_catalog._clear_cache()
        return _pnpm_catalog.get_catalogs(root)

    def test_oversize_workspace_yaml_no_catalogs(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        _sparse_oversize(tmp_path / "pnpm-workspace.yaml")
        with _expect_refusal(caplog):
            assert self._get(tmp_path) == {}

    def test_symlinked_workspace_yaml_refused(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        real = outside / "pnpm-workspace.yaml"
        real.write_text("catalog:\n  react: ^18.2.0\n", encoding="utf-8")
        ws = tmp_path / "repo"
        ws.mkdir()
        (ws / "pnpm-workspace.yaml").symlink_to(real)
        with _expect_refusal(caplog):
            assert self._get(ws) == {}

    def test_small_workspace_yaml_still_parses(self, tmp_path: Path) -> None:
        pytest.importorskip("yaml")
        (tmp_path / "pnpm-workspace.yaml").write_text(
            "catalog:\n  react: ^18.2.0\ncatalogs:\n  react17:\n"
            "    react: ^17.0.0\n",
            encoding="utf-8",
        )
        catalogs = self._get(tmp_path)
        assert catalogs[""]["react"] == "^18.2.0"
        assert catalogs["react17"]["react"] == "^17.0.0"
