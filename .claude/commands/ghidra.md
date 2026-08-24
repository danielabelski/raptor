---
description: Ghidra RE bridge — import, diff, decompile, export findings
dispatch: libexec/raptor-ghidra <subcommand> [args]
---

# /ghidra - Ghidra RE Bridge

Import, query, and diff Ghidra `.gpr` projects, and export RAPTOR
findings back into them. The sandboxed `analyzeHeadless` subprocess is
the default engine (the JVM parses attacker-controlled project data);
in-process pyghidra engages only when headless is absent, or with
`RAPTOR_GHIDRA_IN_PROCESS=1` (operator trust assertion — no sandbox).
Raw binaries degrade to r2, then objdump.

## Subcommands

```
/ghidra import <project.gpr | binary> [--out <dir>] [--enrich] [--decompile-all]
/ghidra diff <old.gpr> <new.gpr> [--out <dir>] [--label-old <v1>] [--label-new <v2>] [--json]
/ghidra decompile <project.gpr> <function_name_or_addr> [--timeout <s>]
/ghidra list <project.gpr>
/ghidra export <out-dir> --to <project.gpr> [--target <path>]
```

### import

One-shot import of a Ghidra project into RAPTOR's REDatabase format.
Exports functions, xrefs, types, comments, segments, imports, exports,
strings, and bookmarks to `re-database.json`.

Engine fallback: with pyghidra installed the import runs in-process;
otherwise a sandboxed `analyzeHeadless` (from `PATH`) does the export.
Passing a **raw binary** instead of a `.gpr` — or running without any
Ghidra install — falls back to the r2 importer, then objdump (reduced
fidelity: no decompilation or types; noted in the database metadata).

- `--enrich` — also run r2 analysis on the binary and merge results
- `--decompile-all` — decompile every function (slow on large binaries)
- `--program <name>` — specific program in a multi-binary project

### diff

Cross-version comparison of two Ghidra projects. Matches functions by
name and reports added/removed/changed functions, comment deltas, and
import changes. Human output ends with the priority review targets
(added/changed functions, auto-named excluded); `--json` emits the full
`version-diff.json` document instead.

- `--label-old` / `--label-new` — human labels for the versions

### decompile

Decompile a single function on demand. Accepts a function name or hex
address. Order: cached decompilation from a prior `--decompile-all`
import (no JVM), then in-process pyghidra when installed, then objdump
disassembly from a cached `re-database.json` (degraded).

### list

List programs (imported binaries) inside a Ghidra project.

### export

Write RAPTOR findings from an output directory into the Ghidra project
as comments and bookmarks (operator reviews them in Ghidra). `--to` is
required. All sources (agentic results, audit journal, annotations)
are gathered into ONE apply pass; counts printed are submissions —
names that don't resolve in the binary are skipped during apply.
Ghidra project comments travel the other way only as review-prompt
context — never into `/annotate` (annotations are human-written only).

## Deferred: attach / detach / status

Persistent project binding (auto-sync after each pipeline run) follows
the projects-schema rework; those subcommands currently exit 2 with a
pointer to the explicit-path workflow above. Use `import`/`export`
with explicit `.gpr` paths in the meantime.
