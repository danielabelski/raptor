"""Re-measurement of elapsed-only stress-sweep failures.

Elapsed is one sample of a network-dominated process; only a
reproducing slowdown should block the sweep. Count drifts are
deterministic and must never be re-measured away.
"""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.calibration import stress as stress_mod
from packages.sca.calibration.project_samples import ProjectSample
from packages.sca.calibration.stress import (
    StressResult,
    compare_to_baseline,
    confirm_elapsed_regressions,
)


def _baseline(tmp_path: Path, projects: dict) -> Path:
    p = tmp_path / "baseline.json"
    p.write_text(json.dumps({"_source": {}, "projects": projects}))
    return p


def _sample(name: str = "proj") -> ProjectSample:
    return ProjectSample(
        name=name, ecosystem="PyPI",
        repo_url="https://example.invalid/x.git",
        git_ref="v1", license_spdx="MIT",
    )


def _result(name: str = "proj", elapsed: float = 100.0,
            vulns: int = 10, deps: int = 50,
            error: str | None = None) -> StressResult:
    return StressResult(
        project=name, ecosystem="PyPI", elapsed_seconds=elapsed,
        deps_analysed=deps, vuln_findings=vulns,
        eco_breakdown={"PyPI": vulns}, error=error,
    )


_BASE_ENTRY = {
    "ecosystem": "PyPI", "deps_analysed": 50, "vuln_findings": 10,
    "eco_breakdown": {"PyPI": 10}, "elapsed_seconds_p50": 18.0,
}


def test_transient_elapsed_fail_clears_on_fast_remeasure(
    tmp_path: Path, monkeypatch,
) -> None:
    baseline = _baseline(tmp_path, {"proj": _BASE_ENTRY})
    monkeypatch.setattr(
        stress_mod, "_scan_one",
        lambda sample, out_root, *, git_clone_timeout:
            _result(elapsed=20.0),
    )
    confirmed = confirm_elapsed_regressions(
        [_result(elapsed=100.0)], [_sample()], baseline,
        out_root=tmp_path,
    )
    assert confirmed[0].elapsed_seconds == 20.0
    diffs = compare_to_baseline(confirmed, baseline)
    assert diffs[0].severity == "ok"


def test_reproducing_slowdown_still_fails(
    tmp_path: Path, monkeypatch,
) -> None:
    baseline = _baseline(tmp_path, {"proj": _BASE_ENTRY})
    monkeypatch.setattr(
        stress_mod, "_scan_one",
        lambda sample, out_root, *, git_clone_timeout:
            _result(elapsed=95.0),
    )
    confirmed = confirm_elapsed_regressions(
        [_result(elapsed=100.0)], [_sample()], baseline,
        out_root=tmp_path,
    )
    # min(100, 95) still >= 5x of 18.0 — a real regression survives.
    assert confirmed[0].elapsed_seconds == 95.0
    diffs = compare_to_baseline(confirmed, baseline)
    assert diffs[0].severity == "fail"


def test_count_fails_are_never_remeasured(
    tmp_path: Path, monkeypatch,
) -> None:
    baseline = _baseline(tmp_path, {"proj": _BASE_ENTRY})

    def _boom(*a, **k):
        raise AssertionError("count-driven fail must not re-scan")

    monkeypatch.setattr(stress_mod, "_scan_one", _boom)
    # vuln_findings 10 -> 2 is a count fail (and elapsed is fine).
    confirmed = confirm_elapsed_regressions(
        [_result(elapsed=19.0, vulns=2)], [_sample()], baseline,
        out_root=tmp_path,
    )
    assert confirmed[0].vuln_findings == 2


def test_mixed_count_and_elapsed_fail_not_remeasured(
    tmp_path: Path, monkeypatch,
) -> None:
    """When counts already fail, a fast second timing sample must not
    launder the run — the count failure stands either way."""
    baseline = _baseline(tmp_path, {"proj": _BASE_ENTRY})

    def _boom(*a, **k):
        raise AssertionError("must not re-scan")

    monkeypatch.setattr(stress_mod, "_scan_one", _boom)
    confirmed = confirm_elapsed_regressions(
        [_result(elapsed=100.0, vulns=2)], [_sample()], baseline,
        out_root=tmp_path,
    )
    diffs = compare_to_baseline(confirmed, baseline)
    assert diffs[0].severity == "fail"


def test_errored_remeasure_keeps_original_sample(
    tmp_path: Path, monkeypatch,
) -> None:
    baseline = _baseline(tmp_path, {"proj": _BASE_ENTRY})
    monkeypatch.setattr(
        stress_mod, "_scan_one",
        lambda sample, out_root, *, git_clone_timeout:
            _result(elapsed=1.0, error="clone blew up"),
    )
    confirmed = confirm_elapsed_regressions(
        [_result(elapsed=100.0)], [_sample()], baseline,
        out_root=tmp_path,
    )
    assert confirmed[0].elapsed_seconds == 100.0
    assert confirmed[0].error is None


def test_remeasure_cap_bounds_extra_scans(
    tmp_path: Path, monkeypatch,
) -> None:
    projects = {
        f"p{i}": dict(_BASE_ENTRY) for i in range(5)
    }
    baseline = _baseline(tmp_path, projects)
    calls: list[str] = []

    def _fake_scan(sample, out_root, *, git_clone_timeout):
        calls.append(sample.name)
        return _result(name=sample.name, elapsed=20.0)

    monkeypatch.setattr(stress_mod, "_scan_one", _fake_scan)
    results = [_result(name=f"p{i}", elapsed=100.0) for i in range(5)]
    samples = [_sample(f"p{i}") for i in range(5)]
    confirm_elapsed_regressions(
        results, samples, baseline, out_root=tmp_path,
        max_remeasures=3,
    )
    assert len(calls) == 3


def test_scan_error_results_pass_through(
    tmp_path: Path, monkeypatch,
) -> None:
    baseline = _baseline(tmp_path, {"proj": _BASE_ENTRY})

    def _boom(*a, **k):
        raise AssertionError("errored scans are not timing fails")

    monkeypatch.setattr(stress_mod, "_scan_one", _boom)
    confirmed = confirm_elapsed_regressions(
        [_result(error="scan timed out")], [_sample()], baseline,
        out_root=tmp_path,
    )
    assert confirmed[0].error == "scan timed out"


def test_elapsed_only_warn_also_remeasured(
    tmp_path: Path, monkeypatch,
) -> None:
    """Warn-level elapsed noise (3-5x) is the same single-sample
    roulette as fail-level — a fast second sample clears it from the
    report."""
    baseline = _baseline(tmp_path, {"proj": _BASE_ENTRY})
    monkeypatch.setattr(
        stress_mod, "_scan_one",
        lambda sample, out_root, *, git_clone_timeout:
            _result(elapsed=20.0),
    )
    # 60s vs baseline 18s = 3.3x → warn band.
    confirmed = confirm_elapsed_regressions(
        [_result(elapsed=60.0)], [_sample()], baseline,
        out_root=tmp_path,
    )
    assert confirmed[0].elapsed_seconds == 20.0
    diffs = compare_to_baseline(confirmed, baseline)
    assert diffs[0].severity == "ok"


def test_count_warn_with_fast_elapsed_not_remeasured(
    tmp_path: Path, monkeypatch,
) -> None:
    """A pure count warn must not trigger a re-scan — only the
    elapsed dimension is noisy."""
    baseline = _baseline(tmp_path, {"proj": _BASE_ENTRY})

    def _boom(*a, **k):
        raise AssertionError("count-driven warn must not re-scan")

    monkeypatch.setattr(stress_mod, "_scan_one", _boom)
    # vulns 10 -> 13 (+30%) = count warn; elapsed fine.
    confirmed = confirm_elapsed_regressions(
        [_result(elapsed=19.0, vulns=13)], [_sample()], baseline,
        out_root=tmp_path,
    )
    assert confirmed[0].vuln_findings == 13


def test_fails_take_remeasure_budget_before_warns(
    tmp_path: Path, monkeypatch,
) -> None:
    """Warn-level elapsed noise earlier in the sweep order must not
    starve a genuine elapsed-only FAIL out of the shared budget —
    that would turn throttle noise back into a blocking rc=2."""
    projects = {f"p{i}": dict(_BASE_ENTRY) for i in range(4)}
    baseline = _baseline(tmp_path, projects)
    remeasured: list[str] = []

    def _fake_scan(sample, out_root, *, git_clone_timeout):
        remeasured.append(sample.name)
        return _result(name=sample.name, elapsed=20.0)

    monkeypatch.setattr(stress_mod, "_scan_one", _fake_scan)
    results = [
        _result(name="p0", elapsed=60.0),    # warn (3.3x)
        _result(name="p1", elapsed=60.0),    # warn
        _result(name="p2", elapsed=60.0),    # warn
        _result(name="p3", elapsed=200.0),   # FAIL (11x), last in order
    ]
    samples = [_sample(f"p{i}") for i in range(4)]
    confirmed = confirm_elapsed_regressions(
        results, samples, baseline, out_root=tmp_path,
        max_remeasures=3,
    )
    # The fail was re-measured (first), and the sweep exits clean.
    assert "p3" in remeasured
    assert len(remeasured) == 3
    diffs = compare_to_baseline(confirmed, baseline)
    assert all(d.severity != "fail" for d in diffs)
