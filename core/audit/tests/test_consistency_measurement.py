"""Ground-truth corpus seed for the consistency dimensions (§4.4).

Per-dimension precision is tracked run-over-run through the existing
``measurement.py`` machinery: a target ships ``ground-truth.json``,
the run's findings land in ``findings.json``, ``evaluate_run`` scores
them. These fixtures are the corpus entries for the phase-1
dimensions — the failopen phase-3 discipline (promotion rights for
any detection-grade variant expand only behind a measured precision
report) starts from here.
"""

from __future__ import annotations

import json

from core.audit.consistency_prepass import run_consistency_prepass
from core.audit.measurement import evaluate_run, load_ground_truth


def _callers(checked: int, deviant: bool) -> str:
    parts = []
    for i in range(checked):
        parts.append(
            f"int caller_{i}(void) {{\n"
            f"    if (do_auth() != 0)\n"
            f"        return -1;\n"
            f"    return 0;\n}}\n"
        )
    if deviant:
        parts.append(
            "int caller_dev(void) {\n    do_auth();\n    return 0;\n}\n"
        )
    else:
        parts.append(
            "int caller_dev(void) {\n"
            "    if (do_auth() != 0)\n        return -1;\n"
            "    return 0;\n}\n"
        )
    return "\n".join(parts)


_WUR = "__attribute__((warn_unused_result)) int do_auth(void);\n"

_GROUND_TRUTH = [{
    "id": "GT-CONSISTENCY-1",
    "file": "callers.c",
    "function": "caller_dev",
    "line": 0,
    "vuln_type": "CWE-252",
    "description": "return of do_auth() discarded; 9/10 sites check",
    "depth": "L1",
}]


def _run(tmp_path, *, deviant: bool):
    target = tmp_path / "target"
    target.mkdir()
    (target / "callers.c").write_text(_callers(9, deviant))
    (target / "api.h").write_text(_WUR)
    (target / "ground-truth.json").write_text(json.dumps(_GROUND_TRUTH))

    out = tmp_path / "out"
    out.mkdir()
    prepass = run_consistency_prepass(
        {"callers.c": (target / "callers.c").read_text()},
        target_path=target,
        out_dir=out,
    )
    (out / "findings.json").write_text(json.dumps([
        {
            "file": f["file"],
            "function": f["function"],
            "status": f["status"],
            "evidence_chain": [{"source": "mechanical:tree_sitter"}],
        }
        for f in prepass["findings"]
    ]))
    truth = load_ground_truth(target)
    return evaluate_run(out, truth), prepass


class TestReturnCheckGroundTruth:
    def test_deviant_fixture_scores_true_positive(self, tmp_path):
        result, prepass = _run(tmp_path, deviant=True)
        assert prepass["findings"], "prepass produced no finding"
        assert len(result.true_positives) == 1
        assert result.true_positives[0].id == "GT-CONSISTENCY-1"
        assert result.false_positives == []
        assert result.detection_rate == 1.0
        assert result.precision == 1.0

    def test_conforming_twin_scores_no_false_positive(self, tmp_path):
        result, prepass = _run(tmp_path, deviant=False)
        assert prepass["findings"] == []
        assert result.false_positives == []
        assert len(result.false_negatives) == 1


class TestCleanupGroundTruth:
    def test_cleanup_dimension_scores_true_positive(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        parts = []
        for i in range(3):
            parts.append(
                f"int user_{i}(void) {{\n"
                f"    res_t *r{i} = grab_lock();\n"
                f"    use(r{i});\n"
                f"    drop_lock(r{i});\n"
                f"    return 0;\n}}\n"
            )
        parts.append(
            "int leaker(void) {\n"
            "    res_t *r = grab_lock();\n"
            "    use(r);\n"
            "    return 0;\n}\n"
        )
        (target / "users.c").write_text("\n".join(parts))
        (target / "ground-truth.json").write_text(json.dumps([{
            "id": "GT-CLEANUP-1",
            "file": "users.c",
            "function": "leaker",
            "vuln_type": "CWE-667",
            "depth": "L1",
        }]))
        out = tmp_path / "out"
        out.mkdir()
        prepass = run_consistency_prepass(
            {"users.c": (target / "users.c").read_text()},
            target_path=target,
            out_dir=out,
            domain_model={"paired_operations": [{
                "acquire": "grab_lock",
                "release": "drop_lock",
                "kind": "mutex",
            }]},
        )
        cleanup = [
            f for f in prepass["findings"]
            if f["dimension"] == "cleanup"
        ]
        assert cleanup and cleanup[0]["function"] == "leaker"
        (out / "findings.json").write_text(json.dumps([
            {
                "file": f["file"],
                "function": f["function"],
                "status": f["status"],
            }
            for f in cleanup
        ]))
        result = evaluate_run(out, load_ground_truth(target))
        assert len(result.true_positives) == 1
        assert result.false_positives == []
