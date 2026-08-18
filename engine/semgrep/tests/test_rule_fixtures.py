"""Fixture gate for the in-repo semgrep rules added by the taint-rules wave.

Every rule file under test ships a positive fixture (must fire) and a
negative fixture (must stay silent), mirroring the engine/negative_controls
discipline for synthesized rules. The real semgrep binary adjudicates —
skipped when it is not installed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

_RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
_FIXTURES = Path(__file__).resolve().parent / "fixtures"

# rule file → (positive fixtures that must fire, negative fixtures that
# must not). Fixture names double as the language matrix.
_CASES = {
    "sinks/ssrf-wrappers.yaml": (
        ["ssrf_wrappers_pos.java", "ssrf_wrappers_pos.js", "ssrf_wrappers_pos.py"],
        ["ssrf_wrappers_neg.java", "ssrf_wrappers_neg.js", "ssrf_wrappers_neg.py"],
    ),
    "deserialisation/unsafe-java-xml-yaml.yaml": (
        ["deser_java_pos.java"],
        ["deser_java_neg.java"],
    ),
    "deserialisation/unsafe-python-jsonpickle.yaml": (
        ["deser_python_pos.py"],
        ["deser_python_neg.py"],
    ),
    "web/prototype-pollution-implementation.yaml": (
        ["protopoll_impl_pos.js"],
        ["protopoll_impl_neg.js"],
    ),
}

pytestmark = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep binary not installed"
)


def _run_semgrep(rule_file: Path, targets: list[Path]) -> dict:
    proc = subprocess.run(
        [
            "semgrep",
            "scan",
            "--config",
            str(rule_file),
            "--quiet",
            "--metrics",
            "off",
            "--json",
            *[str(t) for t in targets],
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert proc.returncode == 0, f"semgrep failed on {rule_file}: {proc.stderr[:500]}"
    return json.loads(proc.stdout)


@pytest.mark.parametrize("rule_rel", sorted(_CASES))
def test_rule_file_is_valid(rule_rel: str):
    rule_file = _RULES_DIR / rule_rel
    assert rule_file.is_file(), rule_file
    proc = subprocess.run(
        ["semgrep", "scan", "--validate", "--config", str(rule_file),
         "--metrics", "off"],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert proc.returncode == 0, f"--validate failed: {proc.stderr[:500]}"


@pytest.mark.parametrize("rule_rel", sorted(_CASES))
def test_positive_fixtures_fire(rule_rel: str):
    positives, _ = _CASES[rule_rel]
    rule_file = _RULES_DIR / rule_rel
    for fixture in positives:
        target = _FIXTURES / fixture
        assert target.is_file(), target
        results = _run_semgrep(rule_file, [target])["results"]
        assert results, f"{rule_rel} produced no findings on {fixture}"


@pytest.mark.parametrize("rule_rel", sorted(_CASES))
def test_negative_fixtures_stay_silent(rule_rel: str):
    _, negatives = _CASES[rule_rel]
    rule_file = _RULES_DIR / rule_rel
    for fixture in negatives:
        target = _FIXTURES / fixture
        assert target.is_file(), target
        results = _run_semgrep(rule_file, [target])["results"]
        hits = [(r["check_id"], r["start"]["line"]) for r in results]
        assert not hits, f"{rule_rel} fired on clean fixture {fixture}: {hits}"


def test_every_rule_has_cwe_metadata():
    """New rules must carry CWE metadata for the coverage machinery."""
    yaml = pytest.importorskip("yaml")
    for rule_rel in _CASES:
        doc = yaml.safe_load((_RULES_DIR / rule_rel).read_text())
        for rule in doc["rules"]:
            cwes = rule.get("metadata", {}).get("cwe", [])
            assert cwes, f"{rule['id']} has no cwe metadata"
