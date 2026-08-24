"""File-class context on graded findings.

A fuzz-harness overflow or a bug in a vendored dependency must not
export indistinguishable from a first-party production finding. The
export threads the orchestrator's prep-time vendored/generated verdicts
(``core.audit.vendored_detector``) plus a test-tree path classification
into a ``file_class`` field — present only for non-first-party code.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core.audit.findings_export import (
    build_graded_finding,
    classify_file_class,
    export_findings,
)
from core.audit.vendored_detector import VendorVerdict


@dataclass
class FakeOutcome:
    file: str = "src/auth.c"
    function: str = "check_pw"
    line: int = 42
    status: str = "finding"
    hypothesis: str = "buffer overflow"
    evidence_tool: str = ""
    cost_usd: float = 0.01
    model: str = "test-model"
    review_result: dict[str, Any] | None = None


def _vendored(kind="vendored", signal="path", detail="vendored path"):
    return VendorVerdict(kind=kind, signal=signal, detail=detail)


class TestClassifyFileClass:
    def test_vendored_verdict(self):
        verdicts = {"deps/zlib/inflate.c": _vendored()}
        assert classify_file_class(
            "deps/zlib/inflate.c", verdicts) == "vendored"

    def test_generated_verdict(self):
        verdicts = {"proto/api_pb2.py": _vendored(kind="generated",
                                                  signal="extension",
                                                  detail="protoc output")}
        assert classify_file_class("proto/api_pb2.py", verdicts) == "generated"

    def test_dict_shaped_verdict_tolerated(self):
        # Verdicts that round-tripped through JSON arrive as dicts.
        verdicts = {"vendor/lib.c": {"kind": "vendored"}}
        assert classify_file_class("vendor/lib.c", verdicts) == "vendored"

    def test_tests_directory(self):
        assert classify_file_class("tests/fuzz_harness.c", None) == "test"

    def test_regress_tree(self):
        # OpenSSH-style regress/ tree — not covered by the shared
        # fixture path patterns.
        assert classify_file_class("regress/misc/fuzz-harness/ssh-sk-null.cc",
                                   None) == "test"

    def test_regress_filename_is_not_a_tree(self):
        # Directory segments only — a production file named regress.c
        # is first-party.
        assert classify_file_class("src/regress.c", None) == ""

    def test_fixture_filename_conventions(self):
        assert classify_file_class("pkg/conftest.py", None) == "test"
        assert classify_file_class("pkg/parser_test.go", None) == "test"

    def test_first_party(self):
        assert classify_file_class("src/auth.c", None) == ""
        assert classify_file_class("src/auth.c", {}) == ""

    def test_empty_path(self):
        assert classify_file_class("", {"": _vendored()}) == ""

    def test_vendor_verdict_wins_over_test_path(self):
        # A vendored dependency's own test tree: provenance
        # (vendored) is the more specific classification.
        verdicts = {"third_party/lib/tests/t.c": _vendored()}
        assert classify_file_class(
            "third_party/lib/tests/t.c", verdicts) == "vendored"


class TestGradedFindingFileClass:
    def test_file_class_present_when_passed(self):
        finding = build_graded_finding(FakeOutcome(), file_class="vendored")
        assert finding["file_class"] == "vendored"

    def test_file_class_absent_for_first_party(self):
        finding = build_graded_finding(FakeOutcome())
        assert "file_class" not in finding


class TestExportFindingsFileClass:
    def test_export_threads_vendor_verdicts(self):
        outcomes = [
            FakeOutcome(file="vendor/zlib/inflate.c", function="inflate"),
            FakeOutcome(file="regress/fuzz/harness.c", function="fuzz_one"),
            FakeOutcome(file="src/auth.c", function="check_pw"),
        ]
        verdicts = {"vendor/zlib/inflate.c": _vendored()}
        export = export_findings(outcomes, vendor_verdicts=verdicts)
        by_file = {f["file"]: f for f in export["findings"]}
        assert by_file["vendor/zlib/inflate.c"]["file_class"] == "vendored"
        assert by_file["regress/fuzz/harness.c"]["file_class"] == "test"
        assert "file_class" not in by_file["src/auth.c"]

    def test_export_without_verdicts_still_classifies_test_trees(self):
        # SIGTERM-salvage export path passes no verdicts — test-tree
        # classification is path-derived and still applies.
        outcomes = [FakeOutcome(file="tests/fixtures/overflow.c")]
        export = export_findings(outcomes)
        assert export["findings"][0]["file_class"] == "test"

    def test_dark_finding_carries_file_class(self):
        outcomes = [FakeOutcome(file="regress/t.c", status="dark")]
        export = export_findings(outcomes)
        f = export["findings"][0]
        assert f["file_class"] == "test"
        assert f["needs_validation"] is True
