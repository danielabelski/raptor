"""Juliet held-out manifest generator: spans, refusals, pin, doctrine."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from core.recall.juliet_manifest import (
    JULIET_PINNED_SHA,
    JulietManifestError,
    generate_manifest,
    split_bad_good_spans,
)
from core.recall.manifest import parse_manifest

_GOOD_FILE = """\
public class CWE89_SQL_Injection__test_01 {
    public void bad(HttpServletRequest request) throws Throwable {
        String data = request.getParameter("id");
        stmt.execute(q + data);
    }

    private void badHelper(String data) throws Throwable {
        sink(data);
    }

    public void good() throws Throwable {
        goodG2B();
    }

    private void goodG2B() throws Throwable {
        String data = "constant";
        stmt.execute(q + data);
    }
}
"""

_UNORDERED = """\
public class X {
    public void good() throws Throwable { }
    public void bad(HttpServletRequest r) throws Throwable { }
}
"""


class TestSplit:
    def test_spans_cover_bad_then_good(self):
        spans = split_bad_good_spans(_GOOD_FILE)
        assert spans is not None
        (bad_start, bad_end), (good_start, good_end) = spans
        lines = _GOOD_FILE.splitlines()
        assert "void bad(" in lines[bad_start - 1]
        assert "void good(" in lines[good_start - 1]
        assert bad_end == good_start - 1
        assert good_end == len(lines)
        # the bad helper sits inside the bad span
        helper_line = next(i for i, ln in enumerate(lines, 1)
                           if "badHelper" in ln)
        assert bad_start <= helper_line <= bad_end

    def test_ordering_violation_refused(self):
        assert split_bad_good_spans(_UNORDERED) is None

    def test_missing_methods_refused(self):
        assert split_bad_good_spans("class X { }") is None
        assert split_bad_good_spans(
            "public void bad() throws Throwable { }") is None


def _make_clone(tmp_path: Path) -> Path:
    clone = tmp_path / "juliet"
    d = clone / "src/testcases/CWE89_SQL_Injection/s01"
    d.mkdir(parents=True)
    (d / "CWE89_SQL_Injection__test_01.java").write_text(
        _GOOD_FILE, encoding="utf-8")
    # multi-file variant must be skipped and counted
    (d / "CWE89_SQL_Injection__test_54a.java").write_text(
        _GOOD_FILE, encoding="utf-8")
    # unsplittable support class must be skipped and counted
    (d / "Helper.java").write_text("class Helper { }", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(clone)], check=True)
    subprocess.run(["git", "-C", str(clone), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(clone), "-c", "user.email=t@example.org",
         "-c", "user.name=t", "commit", "-qm", "fixture"], check=True)
    return clone


class TestGenerate:
    def test_wrong_sha_refused(self, tmp_path):
        clone = _make_clone(tmp_path)
        with pytest.raises(JulietManifestError, match="pinned"):
            generate_manifest(clone)

    def test_manifest_shape_with_pin_bypassed(self, tmp_path,
                                              monkeypatch):
        clone = _make_clone(tmp_path)
        head = subprocess.run(
            ["git", "-C", str(clone), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True).stdout.strip()
        monkeypatch.setattr("core.recall.juliet_manifest."
                            "JULIET_PINNED_SHA", head)
        manifest = generate_manifest(clone)
        assert len(manifest["expected"]) == 1
        assert len(manifest["clean_regions"]) == 1
        exp = manifest["expected"][0]
        assert exp["cwe"] == "CWE-89"
        assert exp["line_start"] == 2
        assert exp["provenance"]["kind"] == "benchmark"
        clean = manifest["clean_regions"][0]
        assert clean["id"].endswith("__good")
        assert clean["line_start"] == exp["line_end"] + 1
        notes = manifest["notes"]
        assert notes["skipped_multi_file_variants"] == 1
        assert notes["skipped_no_bad_good_split"] == 1
        assert "never used to tune" in notes["holdout_doctrine"]
        # a generated manifest must validate against the schema
        # (target sha differs from the fixture pin; patch it back to a
        # valid hex sha for parsing)
        manifest["target"]["pinned_sha"] = head
        parsed = parse_manifest(json.loads(json.dumps(manifest)))
        assert parsed.name == "juliet-java-holdout"
        assert parsed.tolerance.cwe_family_match is True

    def test_missing_clone_refused(self, tmp_path):
        with pytest.raises(JulietManifestError, match="acquire"):
            generate_manifest(tmp_path / "nope")


def test_pinned_sha_is_full_hex():
    assert len(JULIET_PINNED_SHA) == 40
    int(JULIET_PINNED_SHA, 16)
