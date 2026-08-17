"""Drift guard for the core.paths adoption sweep.

The wave that created ``core.paths`` consolidated 13+ hand-rolled
``file://`` strippers (three of them corrupting substring-``replace``
variants) and the ``_relative_path`` helper family. This test pins the
swept call sites to the substrate the same way
``packages/llm_analysis/tests/test_preflight_cost_gate.py`` pins the
cost gate: the module must import the shared helper, and the hand-
rolled spelling must not reappear.

Deliberately NOT swept (do not add them here):

* ``core/sarif/`` — keeps its own percent-decoding normalisation by
  design (the only layer that ``unquote``\\ s; see core/paths
  docstring).
* ``core/audit/sweep.py`` — owned by the concurrent dedup-wave1
  series at sweep time.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Modules that must delegate file:// stripping to core.paths.
_STRIP_ADOPTERS = [
    "core/dataflow/cvefix_bridge.py",
    "packages/semgrep/nosemgrep.py",
    "packages/exploitability_validation/orchestrator.py",
    "packages/llm_analysis/dataflow_validation.py",
    "packages/llm_analysis/agent.py",
    "packages/llm_analysis/patch_gate.py",
]

# Hand-rolled spellings that must not reappear in adopters. The
# substring-``replace`` variant is the one that corrupted mid-string
# ``file://``; the others are the benign-but-drifting leading strips.
_FORBIDDEN = [
    re.compile(r"""\.replace\(\s*['"]file://['"]"""),
    re.compile(r"""\.removeprefix\(\s*['"]file://['"]"""),
    re.compile(r"""startswith\(\s*['"]file://['"]"""),
]


@pytest.mark.parametrize("rel_path", _STRIP_ADOPTERS)
def test_module_imports_substrate(rel_path):
    src = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    assert "strip_file_uri" in src, (
        f"{rel_path} no longer references core.paths.strip_file_uri — "
        "a hand-rolled file:// stripper may have crept back in"
    )
    assert re.search(
        r"from core\.paths import .*\bstrip_file_uri\b", src
    ), f"{rel_path} must import strip_file_uri from core.paths"


@pytest.mark.parametrize("rel_path", _STRIP_ADOPTERS)
def test_no_hand_rolled_stripper(rel_path):
    src = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    for pattern in _FORBIDDEN:
        assert not pattern.search(src), (
            f"{rel_path} re-grew a hand-rolled file:// stripper "
            f"({pattern.pattern}); use core.paths.strip_file_uri"
        )
