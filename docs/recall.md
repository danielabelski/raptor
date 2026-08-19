# Detector recall measurement

Every other calibration surface in RAPTOR measures precision or
suppression-soundness: SCA validation scores risk *ranking*, the
negative controls are must-not-fire fixtures, the binary-oracle
corpora gate suppression, and `core/dataflow/corpus_metrics.py`
measures *validator* recall over findings a producer already emitted.
None of them can see a bug the pipeline never surfaced.

`libexec/raptor-recall-measure` (substrate: `core/recall/`) measures
exactly that: run a detection profile end to end against a target with
known, publicly-provenanced bugs, and score found/expected — detector
recall, per CWE, with the miss list as the actionable output.

## Usage

```
# One-time: generate the OWASP Benchmark manifest from the pinned
# clone (acquisition instructions: core/dataflow/corpus/SOURCES.md)
libexec/raptor-recall-measure owasp-manifest \
    --out out/recall-measure/owasp-manifest.json

# Measure (scan + CodeQL; no LLM cost)
libexec/raptor-recall-measure run \
    --manifest out/recall-measure/owasp-manifest.json

# Compare two runs (e.g. before/after a detection change)
libexec/raptor-recall-measure compare old/report.json new/report.json
```

`run` executes the manifest's profile through the operator surface
(`python3 raptor.py scan|agentic --repo <target>`), locates artifacts
via the `OUTPUT_DIR=` sentinel, parses every produced SARIF, and
matches against ground truth. Profiles: `scan`, `scan-codeql` (both
LLM-free), `agentic` (LLM-tier — requires `--allow-llm` because every
finding costs tokens).

## Ground truth manifests

JSON, schema in `core/recall/manifest.py`. Each expected finding
carries file (repo-relative), optional line range (`line_start: null`
= file-level, the benchmark norm), CWE, and **public provenance** —
a benchmark suite id or a CVE id plus fix commit. Manifests without
public provenance are refused (no undisclosed vulnerabilities in
corpora). Targets are pinned to an exact sha; the runner refuses any
other tree, since labels are sha-bound.

Match tolerance: configurable line-drift window (findings rarely land
on the labelled line exactly) and CWE-family matching via
`packages/checker_synthesis/cwe_families.py` (producers legitimately
disagree about e.g. CWE-77 vs CWE-78). Benchmark FP cases (same
pattern, sanitizer applied) become `clean_regions`: findings there
feed a secondary FP counter, never recall.

## Report

`report.json` + `report.md` in the run dir: overall and per-CWE
recall, tool attribution (which backend co-found each expected
finding), the missed-findings list, the clean-region FP count, and a
toolchain version block (mirroring the binary-oracle precision
harness) so the number is reproducible. `compare` produces per-CWE
deltas plus `newly_found` / `newly_missed` id lists.

## Segregation — read this before wiring anything to the output

Recall labels are **false-negative ground truth**. Feeding them into
the FP-suppression stores, cross-run verdict reuse, or the model
scorecard corrupts both calibrations (the
`cvefix_corpus_generator.py` warning, generalised). Every report is
stamped `label_class: recall-ground-truth`; consumers must refuse to
ingest that class into learning stores. `core/recall/` itself never
imports those stores — pinned by test
(`core/recall/tests/test_score.py::TestSegregationGuard`).

## FN census (`census --fn`)

The mirror of the FP census: ranks the MISSED expected findings by
the construct most likely to have broken the taint chain (probes
derived empirically from the missed cases) and splits them by
tool-coverage reason — rules fired for the CWE elsewhere in the run
(a chain break) versus no finding for the CWE class at all (a
coverage hole). Output: `fn-census.{json,md}`.

## Held-out corpus: Juliet Java (`juliet-manifest`)

Generalization checks only — the binary-oracle holdout discipline
applied to recall. Detection mechanisms are tuned against the OWASP
corpus; after each round, the Juliet manifest is run once and
reported AT FIRST CONTACT. Its numbers are never used to tune probes,
rules, gates, or thresholds — a mechanism that only moves the OWASP
numbers has been overfit, and the Juliet delta is the evidence either
way.

Ground truth comes from Juliet's structure: single-file cases declare
`bad*` methods before `good*` methods (files violating the ordering
are refused, not mislabelled); the bad span is one expected entry,
the good span one clean region. Multi-file flow variants are excluded
from the v1 manifest and counted in the manifest's `notes`. The suite
is not bundled — the generator reads an operator-acquired clone of
the public find-sec-bugs mirror of the NIST suite, sha-pinned like
every recall corpus.
