"""Generate a HELD-OUT recall manifest from the Juliet Java suite.

HOLDOUT DOCTRINE (the binary-oracle discipline, applied to recall):
detection mechanisms are tuned against the OWASP Benchmark corpus
ONLY. Juliet results are generalization checks — run once per round,
reported at first contact, and never used to tune probes, rules,
gates, or thresholds. A mechanism that only moves the OWASP numbers
has been overfit; the Juliet delta is the evidence either way.

Ground truth comes from Juliet's own structure: every single-file
test case declares its ``bad*`` methods first and its ``good*``
methods after (verified empirically on the pinned mirror — the
generator refuses files that violate the ordering rather than
mislabelling them). The bad-method span becomes one ``expected``
entry; the good-method span becomes one ``clean_region``. Multi-file
variants (``_54a.java``-style flows spanning classes) are excluded
from this first manifest and counted, not silently dropped.

The suite is NOT bundled: the generator reads an operator-acquired
clone of the public find-sec-bugs mirror of the NIST suite, pinned by
sha (labels are sha-bound like every recall corpus).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

from core.recall.manifest import SCHEMA_VERSION

#: Public mirror of the NIST Juliet Java suite (v1.2 content).
JULIET_REPO_URL = "https://github.com/find-sec-bugs/juliet-test-suite"
JULIET_PINNED_SHA = "b2c6df3733e2176fe7097e4784895c6891632b4c"
JULIET_DEFAULT_CLONE = "out/recall-corpus/juliet-java"
_TESTCASES = "src/testcases"

#: Juliet CWE directories comparable to the OWASP Benchmark classes.
#: Labels keep Juliet's own CWE numbers; the matcher's family
#: tolerance bridges 23/36 -> 22 and 80/83 -> 79. CWE81 is excluded:
#: it has no family bridge, so misses there would measure taxonomy,
#: not detection. The mirror ships no CWE330/CWE501 Java cases.
COMPARABLE_DIRS: dict[str, int] = {
    "CWE78_OS_Command_Injection": 78,
    "CWE89_SQL_Injection": 89,
    "CWE90_LDAP_Injection": 90,
    "CWE23_Relative_Path_Traversal": 23,
    "CWE36_Absolute_Path_Traversal": 36,
    "CWE80_XSS": 80,
    "CWE83_XSS_Attribute": 83,
    "CWE327_Use_Broken_Crypto": 327,
    "CWE328_Reversible_One_Way_Hash": 328,
}

_MULTI_FILE_RE = re.compile(r"_\d+[a-z]\.java$")
_DECL_RE = re.compile(
    r"^\s*(?:public|private|protected)\s+[\w<>\[\]., ]*?"
    r"\s(bad\w*|good\w*)\s*\(")

_ACQUIRE_HINT = (
    f"git clone {JULIET_REPO_URL} <clone-dir> && "
    f"git -C <clone-dir> checkout {JULIET_PINNED_SHA}"
)


class JulietManifestError(RuntimeError):
    pass


def _verify_clone(clone_dir: Path) -> None:
    if not (clone_dir / _TESTCASES).is_dir():
        raise JulietManifestError(
            f"Juliet clone not found or incomplete at {clone_dir} — "
            f"acquire with: {_ACQUIRE_HINT}")
    try:
        proc = subprocess.run(
            ["git", "-C", str(clone_dir), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        head = proc.stdout.strip().lower()
    except (OSError, subprocess.SubprocessError) as exc:
        raise JulietManifestError(
            f"cannot sha-verify {clone_dir}: {exc}") from exc
    if proc.returncode != 0 or not head:
        raise JulietManifestError(
            f"cannot sha-verify {clone_dir}: {proc.stderr.strip()}")
    if head != JULIET_PINNED_SHA:
        raise JulietManifestError(
            f"{clone_dir} is at {head[:12]}, labels are pinned to "
            f"{JULIET_PINNED_SHA[:12]} — {_ACQUIRE_HINT}")


def split_bad_good_spans(
        text: str) -> tuple[tuple[int, int], tuple[int, int]] | None:
    """Return ((bad_start, bad_end), (good_start, good_end)) or None.

    Line numbers are 1-based. None means the file has no usable
    bad/good split (no bad method, no good method, or an ordering
    violation — a good method before the last bad method — which
    would make span labels lie).
    """
    decls: list[tuple[int, str]] = []
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        m = _DECL_RE.match(line)
        if m:
            decls.append((i, m.group(1)))
    bad = [i for i, name in decls if name.startswith("bad")]
    good = [i for i, name in decls if name.startswith("good")]
    if not bad or not good:
        return None
    if max(bad) > min(good):
        return None  # ordering violation — refuse, never mislabel
    return (min(bad), min(good) - 1), (min(good), len(lines))


def _entry(case_id: str, rel_file: str, cwe: int,
           span: tuple[int, int]) -> dict:
    return {
        "id": case_id,
        "file": rel_file,
        "line_start": span[0],
        "line_end": span[1],
        "cwe": f"CWE-{cwe}",
        "provenance": {
            "kind": "benchmark",
            "suite": "juliet-java-fsb-mirror",
            "case": case_id,
        },
    }


def generate_manifest(clone_dir: Path, *, cwes: list[int] | None = None,
                      limit: int | None = None) -> dict:
    """Build the held-out manifest dict from the verified clone.

    ``cwes`` filters to specific Juliet CWE numbers; ``limit`` caps
    expected entries per CWE (deterministic: sorted by path).
    """
    _verify_clone(clone_dir)
    expected: list[dict] = []
    clean: list[dict] = []
    skipped_multi = 0
    skipped_unsplit = 0
    per_cwe_count: dict[int, int] = {}

    for dirname, cwe in sorted(COMPARABLE_DIRS.items()):
        if cwes and cwe not in cwes:
            continue
        cwe_dir = clone_dir / _TESTCASES / dirname
        if not cwe_dir.is_dir():
            continue
        for path in sorted(cwe_dir.rglob("*.java")):
            if _MULTI_FILE_RE.search(path.name):
                skipped_multi += 1
                continue
            spans = split_bad_good_spans(
                path.read_text(encoding="utf-8", errors="replace"))
            if spans is None:
                skipped_unsplit += 1
                continue
            if limit is not None:
                n = per_cwe_count.get(cwe, 0)
                if n >= limit:
                    continue
                per_cwe_count[cwe] = n + 1
            bad_span, good_span = spans
            rel = str(path.relative_to(clone_dir))
            case_id = path.stem
            expected.append(_entry(case_id, rel, cwe, bad_span))
            clean.append(
                _entry(f"{case_id}__good", rel, cwe, good_span))

    if not expected:
        raise JulietManifestError(
            "no expected entries survived the filters")

    return {
        "schema_version": SCHEMA_VERSION,
        "name": "juliet-java-holdout",
        "target": {
            "repo_url": JULIET_REPO_URL,
            "pinned_sha": JULIET_PINNED_SHA,
            "local_path": str(clone_dir),
        },
        "language": "java",
        # scan-codeql is the recall-bearing profile: measured 84.3% vs
        # 29.7% for semgrep-only on this corpus (threat-model=local
        # covers Juliet's console/env/file/properties sources).
        "profile": "scan-codeql",
        "tolerance": {"line_drift": 0, "cwe_family_match": True},
        "expected": expected,
        "clean_regions": clean,
        # Coverage honesty: what the generator dropped, and why this
        # corpus exists.
        "notes": {
            "holdout_doctrine": (
                "Generalization check ONLY: mechanisms are tuned on "
                "the OWASP corpus; Juliet runs are reported at first "
                "contact and never used to tune."),
            "skipped_multi_file_variants": skipped_multi,
            "skipped_no_bad_good_split": skipped_unsplit,
        },
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="raptor-recall-measure juliet-manifest",
        description=__doc__.splitlines()[0],
    )
    p.add_argument("--clone-dir", type=Path,
                   default=Path(JULIET_DEFAULT_CLONE))
    p.add_argument("--out", type=Path, required=True,
                   help="manifest JSON output path")
    p.add_argument("--cwe", action="append", type=int, default=[],
                   help="restrict to Juliet CWE number (repeatable)")
    p.add_argument("--limit", type=int, default=None,
                   help="cap expected entries per CWE (sorted, "
                        "deterministic)")
    args = p.parse_args(argv)

    try:
        manifest = generate_manifest(
            args.clone_dir, cwes=args.cwe or None, limit=args.limit)
    except JulietManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, indent=2) + "\n",
                        encoding="utf-8")
    notes = manifest["notes"]
    print(f"manifest: {args.out} "
          f"({len(manifest['expected'])} expected, "
          f"{len(manifest['clean_regions'])} clean regions; skipped "
          f"{notes['skipped_multi_file_variants']} multi-file + "
          f"{notes['skipped_no_bad_good_split']} unsplittable)")
    return 0
