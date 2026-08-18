# /audit calibration corpus

Ground-truth labels for calibrating the /audit pipeline. Each
`.label.json` under `labels/<bug_class>/` pins one function in an
upstream repo (repo key + ref + file + line range) and records the
expected verdict, the expected *mechanism* that should produce it, and
optional per-mode expectations. Labels reference real-world
repositories at pinned refs. Source code is never committed — it is
fetched at pinned refs into `out/audit-corpus-fixtures/<repo_key>`.

Labels are not distributed with this tree; they are supplied locally
under `labels/<bug_class>/`.

## Running

```
python3 -m core.audit.corpus.run_corpus --dry-run          # verify labels + sources
python3 -m core.audit.corpus.run_corpus --fetch --dry-run  # bootstrap missing clones first
python3 -m core.audit.corpus.run_corpus --out out/corpus-run --output results.json
python3 -m core.audit.corpus.corpus_metrics results.json --check-gate
```

`sources.json` is the URL registry (repo key → primary URL, mirrors,
post-clone symlinks, notes). `--fetch` creates missing clones from it —
shallow, at the pinned ref, with mirror fallback. It lives next to the
labels and follows this shape:

```json
{
  "repos": {
    "demo-repo": {
      "url": "https://example.org/demo/demo-repo.git",
      "mirror_urls": ["https://mirror.example.org/demo-repo.git"],
      "ref_kind": "tag",
      "notes": "primary host has outage windows; mirror carries tags"
    },
    "src-rooted-repo": {
      "url": "https://example.org/demo/src-rooted-repo.git",
      "ref_kind": "sha",
      "symlinks": {"lib": "src/lib"}
    }
  }
}
```

`symlinks` maps a label-visible path prefix to its real location in
the clone, for repos whose labelled paths live under a subtree such as
`src/`.

## Scoring

Three layers, all emitted by the run summary and recomputable offline
with `corpus_metrics`:

1. **Verdict** — confusion matrix per bug class. `actual == "error"`
   is its own cell: excluded from P/R denominators, listed per label,
   and gated (`--max-error-fraction`, default 10%).
2. **Mechanism attribution** — labels carry `expected_mechanism`; the
   runner joins run receipts (refutation-gate audit-log records,
   evidence tools, journal `evidence_tools`, mechanical detectors)
   back to each label. Right verdict + right mechanism = `attributed`.
   Right verdict from the *wrong* mechanism = `MISATTRIBUTED` — the
   dangerous quiet cell, reported loudly and gated. No receipt at all
   = `unattributed` (reported, not gated — honest degradation for
   receipt-less mechanisms and results predating attribution).
3. **Mode expectations** — `expected_mode_results` per label, checked
   wherever a mode actually ran (single-mode runs via the row's
   `mode`; ensemble runs via `security_actual` / `bug_first_actual`).
   Unexercised modes are never guessed.

## Fix-and-rerun loop (--label + --splice)

A run that errors on a few labels does not need a full (expensive)
re-run. The loop:

```
# 1. See what errored — the metrics CLI lists errored labels
python3 -m core.audit.corpus.corpus_metrics results.json

# 2. Fix the cause, then re-run ONLY those labels, splicing the fresh
#    rows into the previous full results
python3 -m core.audit.corpus.run_corpus \
    --label 'src/net/session.c:session_recv' \
    --label 'src/store/log.c:record_from_disk' \
    --splice results.json --output results-v2.json

# 3. Recompute metrics over the merged set; diff against the old run
python3 -m core.audit.corpus.corpus_metrics results-v2.json --check-gate
python3 -m core.audit.corpus.corpus_metrics results-v2.json --diff results.json
```

Splice semantics: rows for the re-run labels replace their old rows;
every other row is kept verbatim, including its attribution
annotations. The merged file's `meta` records `spliced_from` and
`new_count`. A missing `--splice` file fails fast (exit 2) before any
cost is spent.

## Run history (compare, trend, stability)

Every corpus run appends one run-header record plus one per-label
record to an append-only JSONL store once results.json is finalized
(gate-fail exits included; `--probe` runs only with `--record-probe`).
The store defaults to `~/.local/share/raptor/corpus-history.jsonl`,
overridable via `RAPTOR_CORPUS_HISTORY` — tests must point it at a
temporary path. A write failure warns and never fails the run.

The run header carries the run id, timestamp, the pipeline tree sha
(`git rev-parse HEAD^{tree}` of the checkout the runner executed
from), config (mode / triage / prefilter / model / scope / splice), a
hash of the label set (sorted `function_id:span_sha`), recomputed
gate outcomes, totals, and cost. Label records carry expected/actual
status, match, the attribution cell, observed mechanisms,
error_reason, cost, and duration.

**Reporting-only, by design**: nothing in the audit/corpus pipeline
reads this store to alter behavior — the read side is exclusively the
history CLI:

```
python3 -m core.audit.corpus.history runs
# The fix-impact report: verdict flips grouped by flip type,
# attribution-cell changes, cost deltas
python3 -m core.audit.corpus.history compare v4 v5
python3 -m core.audit.corpus.history trend --label 'src/net/session.c:session_recv'
# Nondeterminism measure: verdict variance across runs sharing the
# same pipeline tree + config
python3 -m core.audit.corpus.history stability
# Back-import results.json from runs predating the store (marked
# imported=true; tolerates the older result shapes)
python3 -m core.audit.corpus.history import out/corpus-full-v2/results.json
```

Run tokens accept any unique substring of a run id (`v4` matches
`corpus-full-v4`). Corrupt store lines are skipped with a warning —
one bad line never kills reads over the rest of the store.

## Rule verification (mechanical, no LLM)

`rule_eval` runs the deterministic rule inventories — the shipped
semgrep category dirs under `engine/semgrep/rules/`, the shipped
`engine/coccinelle/rules/*.cocci` set, (opt-in) the custom CodeQL
queries, and the project's *graduated* synthesized rules (the
`RuleLibrary.graduate` promotions under `<project>/engine-rules/`) —
over the pinned sources and scores the hits against the labels. It answers a different question from `run_corpus`: not "does
the /audit pipeline reach the right verdict" but "what do our custom
rules alone see".

```
python3 -m core.audit.corpus.rule_eval --dry-run     # inventory + coverage gaps, zero cost
python3 -m core.audit.corpus.rule_eval --fetch --out out/rule-eval
python3 -m core.audit.corpus.rule_eval --engine codeql --out out/rule-eval-ql
```

Rules are discovered the same way the production scanners enumerate
them (never a parallel hardcoded list). A hit joins a label when it
lands in the pinned file within `line_start - slop .. line_end + slop`
(`--slop`, default 2). A rule *targets* a label when the label pins it
via the optional `expected_rule_hits` field, or by CWE intersection
(label `cwe`, else the bug class's CWE family) plus language
compatibility. Scoring is per rule (TP / FP / miss / untargeted hit)
and per class, with every per-rule row tagged by provenance
(`shipped` vs `graduated`) and the summary separating the two
populations — measuring synthesized-rule quality against corpus
ground truth is the point. `--provenance {all,shipped,graduated}`
(default `all`) restricts the run to one population;
`--engine-rules-dir` names the graduated base explicitly when no
active project provides it. The actionable output for rule authoring
is the **RULE-COVERAGE GAP** list — `finding` labels no evaluated
rule even targets.

Per-invocation wall time is recorded in `rule-eval-results.json`
under `rule_timings` (coccinelle per rule, semgrep per category dir,
codeql per query-suite pass) and the summary surfaces the slowest
invocations; `--spatch-timeout` (default 300, the production cocci
stage's bound) tightens the per-rule spatch bound when large
excerpts push rules to it — a timed-out rule is an engine error for
that rule, never a run failure.

The label linter's schema mode cross-checks every `expected_rule_hits`
pin against this same discovered inventory (shipped + graduated), so
a pin naming a renamed or removed rule fails lint instead of silently
degrading to a coverage gap.

CodeQL is gated behind `--engine codeql` because it needs a database
extraction pass: buildless C/C++ extraction runs over the excerpt tree
(partial by nature — missing headers are tolerated, results measure
the rules under those conditions); Java custom queries need a traced
build of the pinned repo, which excerpt trees cannot provide, and
languages without shipped custom queries are skipped outright. A
failed extraction is reported as a skip with the CLI error — never
faked.

Skips are never failures: missing fixtures, absent engines
(`semgrep` / `spatch` / `codeql` not installed), and per-repo
infeasibility all land in the skip taxonomy, mirroring `run_corpus`.

## Adding a label

1. Write the `.label.json` under `labels/<bug_class>/` (see
   `label.py` for the schema; `function_id` must be unique
   corpus-wide — duplicates fail loading).
2. If the repo is new, add it to `sources.json`.
3. `python3 -m core.audit.corpus.run_corpus --dry-run` — per-label
   source status is printed inline; a file found under a known prefix
   (e.g. `src/`) suggests the corrected path.

## Content-addressed pins (`source.span_sha`)

A pin may carry `span_sha`: the span hash (SHA-256[:12] over the raw
lines of `line_start..line_end` joined by `\n` — the shared
`core.staleness` convention that /annotate also uses) of the pinned
range at the pinned ref. It makes label drift *detectable*: when the
upstream file changes shape the hash stops matching, instead of the
runner silently reviewing whatever now occupies those line numbers —
and an intact span that merely moved can be relocated by hash.

Older labels without `span_sha` still load. Backfill it with the
corpus linter once a pin verifies against the pinned tree
(`python3 -m core.audit.corpus.lint --mode pins --stamp`); the linter
never stamps a pin that fails verification.
