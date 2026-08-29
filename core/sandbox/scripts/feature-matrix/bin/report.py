#!/usr/bin/env python3
"""Aggregate a results/<timestamp>/ run dir into the lane matrix.

Reads per-lane probe.json + junit-*.xml + pytest-*.rc + meta.json,
compares each probed shape against the lane's intended shape
(lanes/lanes.py), prints the matrix, and writes matrix.md + matrix.json
+ failures.txt into the run dir.

Exit status: 0 only if every lane ran, no test failures/errors, and no
lane's probe diverged from its intended feature shape. The matrix keys
on PROBED capabilities — a lane whose probe diverged is flagged
SHAPE-DIVERGED loudly, because its test results then describe a
different feature combination than the lane name claims.
"""

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "profiles"))
from lanes import LANE_ORDER, LANES  # noqa: E402


def parse_junits(lane_dir: Path) -> dict:
    from typing import Any
    agg: dict[str, Any] = {"tests": 0, "failures": 0, "errors": 0,
                           "skipped": 0, "failed_tests": [],
                           "junit_found": False}
    for junit in sorted(lane_dir.glob("junit-*.xml")):
        agg["junit_found"] = True
        try:
            root = ET.parse(junit).getroot()
        except ET.ParseError:
            agg["failed_tests"].append(f"<unparseable {junit.name}>")
            agg["errors"] += 1
            continue
        suites = root.iter("testsuite")
        for s in suites:
            agg["tests"] += int(s.get("tests", 0))
            agg["failures"] += int(s.get("failures", 0))
            agg["errors"] += int(s.get("errors", 0))
            agg["skipped"] += int(s.get("skipped", 0))
        for case in root.iter("testcase"):
            if case.find("failure") is not None or case.find("error") is not None:
                agg["failed_tests"].append(
                    f"{case.get('classname', '?')}::{case.get('name', '?')}")
    return agg


def shape_check(lane: str, probed: dict | None) -> tuple[str, list]:
    expect = LANES[lane]["expect"]
    if probed is None:
        return "NO-PROBE", ["probe.json missing/unreadable"]
    if expect is None:
        return "recorded", []
    assert isinstance(expect, dict)
    diverged = [f"{k}: intended {v!r}, probed {probed.get(k)!r}"
                for k, v in expect.items() if probed.get(k) != v]
    return ("SHAPE-DIVERGED", diverged) if diverged else ("as-intended", [])


def fmt_shape(probed: dict | None, abi=None) -> str:
    if probed is None:
        return "?"
    ll = probed.get("landlock", "?")
    if ll == "present":
        ll = f"abi{abi}"
    return (f"LL={ll} UNS={probed.get('userns', '?')} "
            f"MNT={probed.get('mount_in_userns', '?')} "
            f"PROC={probed.get('proc_mount_in_userns', '?')} "
            f"PIVOT={probed.get('pivot_root_in_userns', '?')} "
            f"SEC={probed.get('seccomp', '?')}")


def main() -> None:
    run_dir = Path(sys.argv[1]).resolve()
    rows = []
    exit_bad = False
    stray = []

    for image_dir in sorted(p for p in run_dir.iterdir() if p.is_dir()):
        image = image_dir.name
        if image in ("profiles",):
            continue
        # A lane dir the report does not know is itself a harness
        # error: results exist that the matrix would silently drop.
        stray += [f"{image}/{d.name}" for d in image_dir.iterdir()
                  if d.is_dir() and d.name not in LANE_ORDER]
        for lane in LANE_ORDER:
            lane_dir = image_dir / lane
            if not lane_dir.is_dir():
                continue
            probe = None
            probe_full = None
            try:
                probe_full = json.loads((lane_dir / "probe.json").read_text())
                probe = probe_full.get("shape")
            except (OSError, json.JSONDecodeError):
                pass
            meta = {}
            try:
                meta = json.loads((lane_dir / "meta.json").read_text())
            except (OSError, json.JSONDecodeError):
                pass
            tests = parse_junits(lane_dir)
            verdict, divergences = shape_check(lane, probe)

            harness_err = None
            if meta.get("rc") not in (0, None):
                harness_err = f"container rc={meta.get('rc')}"
            elif not tests["junit_found"]:
                harness_err = "no junit produced"
            elif tests["tests"] == 0:
                # An empty collection reports "0 failures" for a tier
                # that never ran — gate it like any other harness error.
                harness_err = "junit contains zero tests"

            bad = bool(divergences or verdict == "NO-PROBE"
                       or tests["failures"] or tests["errors"]
                       or harness_err)
            exit_bad |= bad

            rows.append({
                "image": image, "lane": lane,
                "landlock_abi": (probe_full or {}).get("landlock", {}).get("abi"),
                "probed_shape": probe, "shape_verdict": verdict,
                "divergences": divergences, "harness_error": harness_err,
                "duration_s": meta.get("duration_s"),
                **{k: tests[k] for k in
                   ("tests", "failures", "errors", "skipped", "failed_tests")},
            })

    # ---- render ---------------------------------------------------------
    hdr = (f"{'image':<6} {'lane':<12} {'probed features':<56} "
           f"{'shape':<15} {'pass':>5} {'fail':>5} {'err':>4} {'skip':>5}")
    lines = [hdr, "-" * len(hdr)]
    for r in rows:
        passed = r["tests"] - r["failures"] - r["errors"] - r["skipped"]
        lines.append(
            f"{r['image']:<6} {r['lane']:<12} "
            f"{fmt_shape(r['probed_shape'], r['landlock_abi']):<56} "
            f"{r['shape_verdict']:<15} "
            f"{passed:>5} {r['failures']:>5} {r['errors']:>4} {r['skipped']:>5}"
            + (f"  !! {r['harness_error']}" if r["harness_error"] else ""))
    table = "\n".join(lines)
    print(table)

    fail_lines = []
    for r in rows:
        for d in r["divergences"]:
            fail_lines.append(f"[{r['image']}/{r['lane']}] DIVERGENCE {d}")
        for t in r["failed_tests"]:
            fail_lines.append(f"[{r['image']}/{r['lane']}] FAIL {t}")
        if r["harness_error"]:
            fail_lines.append(
                f"[{r['image']}/{r['lane']}] HARNESS {r['harness_error']}")
    if fail_lines:
        print("\nFailures / divergences:")
        print("\n".join(fail_lines))

    if not rows:
        print("HARNESS ERROR: no lane results found under "
              f"{run_dir} — nothing was tested")
        sys.exit(1)
    if stray:
        print("HARNESS ERROR: unknown lane result dirs (results the "
              "matrix would silently drop): " + ", ".join(stray))
        exit_bad = True

    (run_dir / "matrix.json").write_text(json.dumps(rows, indent=1) + "\n")
    (run_dir / "failures.txt").write_text("\n".join(fail_lines) + "\n")
    md = ["# sandbox-matrix run " + run_dir.name, "", "```", table, "```", ""]
    if fail_lines:
        md += ["## Failures / divergences", "", "```"] + fail_lines + ["```", ""]
    (run_dir / "matrix.md").write_text("\n".join(md))
    print(f"\nwrote {run_dir}/matrix.json matrix.md failures.txt")
    sys.exit(1 if exit_bad else 0)


if __name__ == "__main__":
    main()
