"""CLI for the recall-measurement harness (raptor-recall-measure)."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from core.recall.manifest import PROFILES, ManifestError, load_manifest
from core.recall.matcher import clean_region_hits, match_findings
from core.recall.owasp_manifest import main as owasp_manifest_main
from core.recall.runner import (
    RunnerError,
    collect_findings,
    run_pipeline,
    verify_pinned_clone,
)
from core.recall.score import (
    collect_toolchain,
    compare_reports,
    render_markdown,
    score,
)

logger = logging.getLogger(__name__)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _default_out() -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return Path("out/recall-measure/runs") / ts


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        manifest = load_manifest(args.manifest)
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.profile:
        if args.profile not in PROFILES:
            print(f"error: unknown profile {args.profile!r} "
                  f"(choose from {sorted(PROFILES)})", file=sys.stderr)
            return 2
        manifest.profile = args.profile
    if PROFILES[manifest.profile]["uses_llm"] and not args.allow_llm:
        print(
            f"error: profile {manifest.profile!r} runs LLM analysis on "
            "every finding — pass --allow-llm to accept the cost, or "
            "use scan / scan-codeql for a free baseline",
            file=sys.stderr)
        return 2

    out_dir = args.out or _default_out()
    out_dir.mkdir(parents=True, exist_ok=True)
    repo_root = _repo_root()
    pipeline_dir = (args.pipeline_dir.resolve()
                    if args.pipeline_dir else repo_root)
    if not (pipeline_dir / "raptor.py").is_file():
        print(f"error: --pipeline-dir {pipeline_dir} does not contain "
              "raptor.py", file=sys.stderr)
        return 2

    try:
        # Manifest-relative paths resolve against the HARNESS tree; the
        # pipeline dir only selects which detector build runs, so two
        # builds can be measured against one manifest.
        target = verify_pinned_clone(manifest, repo_root)
        pipeline_out = run_pipeline(
            manifest, target, pipeline_dir, out_dir / "pipeline.log",
            timeout_s=args.timeout)
        produced = collect_findings(pipeline_out, source_root=target)
    except RunnerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    matches = match_findings(manifest.expected, produced,
                             manifest.tolerance)
    clean_hits = clean_region_hits(manifest.clean_regions, produced,
                                   manifest.tolerance)
    report = score(manifest, matches, clean_hits,
                   toolchain=collect_toolchain(),
                   run_output_dir=str(pipeline_out))

    json_path = out_dir / "report.json"
    json_path.write_text(json.dumps(report.to_dict(), indent=2) + "\n",
                         encoding="utf-8")
    md = render_markdown(report)
    (out_dir / "report.md").write_text(md, encoding="utf-8")
    print(md)
    print(f"report: {json_path}")
    return 0


def _cmd_compare(args: argparse.Namespace) -> int:
    try:
        base = json.loads(args.base.read_text(encoding="utf-8"))
        new = json.loads(args.new.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read report: {exc}", file=sys.stderr)
        return 2
    delta = compare_reports(base, new)
    print(json.dumps(delta, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO,
                        format="[%(levelname)s] %(message)s")
    p = argparse.ArgumentParser(
        prog="raptor-recall-measure",
        description=("End-to-end detector-recall measurement: run a "
                     "detection profile against a ground-truth target "
                     "and score found/expected per CWE. Reports are "
                     "recall-ground-truth class — never feed them to "
                     "FP-suppression or scorecard learning stores."),
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    run_p = sub.add_parser("run", help="run a manifest and score recall")
    run_p.add_argument("--manifest", type=Path, required=True)
    run_p.add_argument("--out", type=Path, default=None,
                       help="report dir (default: "
                            "out/recall-measure/runs/<ts>)")
    run_p.add_argument("--profile", default=None,
                       help="override the manifest's detection profile")
    run_p.add_argument("--allow-llm", action="store_true",
                       help="required for LLM-tier profiles (agentic)")
    run_p.add_argument("--pipeline-dir", type=Path, default=None,
                       help="RAPTOR checkout whose raptor.py runs the "
                            "profile (default: this tree) — lets two "
                            "detector builds be measured against one "
                            "manifest for before/after deltas")
    run_p.add_argument("--timeout", type=int, default=4 * 3600,
                       help="pipeline timeout in seconds")
    run_p.set_defaults(func=_cmd_run)

    cmp_p = sub.add_parser("compare",
                           help="delta two report JSONs (older first)")
    cmp_p.add_argument("base", type=Path)
    cmp_p.add_argument("new", type=Path)
    cmp_p.set_defaults(func=_cmd_compare)

    ow_p = sub.add_parser(
        "owasp-manifest",
        help="generate the OWASP Benchmark recall manifest from the "
             "pinned clone")
    ow_p.set_defaults(func=None)

    args, rest = p.parse_known_args(argv)
    if args.cmd == "owasp-manifest":
        return owasp_manifest_main(rest)
    if rest:
        p.error(f"unrecognized arguments: {' '.join(rest)}")
    return args.func(args)
