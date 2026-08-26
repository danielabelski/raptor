---
description: Ghidra RE bridge — attach, import, diff, decompile, export findings
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
/ghidra attach <project.gpr> [--enrich] [--decompile-all]
/ghidra detach [<project.gpr>]
/ghidra status
/ghidra import <project.gpr | binary> [--out <dir>] [--enrich] [--decompile-all]
/ghidra diff <old.gpr> <new.gpr> [--out <dir>] [--label-old <v1>] [--label-new <v2>] [--json]
/ghidra decompile <project.gpr> <function_name_or_addr> [--timeout <s>]
/ghidra list <project.gpr>
/ghidra export <out-dir> [--to <project.gpr>] [--target <path>]
```

### attach / detach / status

Persistent binding to the active RAPTOR project. `attach` registers
the `.gpr` on the project (`ghidra_projects`, also managed via
`/project ghidra add|remove|list|clear`), imports it, and caches the
database under
`<project output>/ghidra-attach/<name>-<hash>/re-database.json` (the
hash disambiguates same-named attachments, e.g. two firmware
versions; run management skips the `ghidra-attach` directory by name,
and it must NOT be dot-prefixed — Ghidra refuses project paths
containing hidden directories). The import runs under the sandbox
when `analyzeHeadless` is on `PATH`; with only pyghidra installed it
falls back in-process (logged — an operator trust call, same as
`RAPTOR_GHIDRA_IN_PROCESS=1`). Analysis runs (/agentic) then inject
the CACHED types and xrefs into review prompts automatically —
decompilation blocks appear only when the attach ran with
`--decompile-all` (a plain attach caches metadata without
decompilation, and a plain RE-attach discards previously cached
decompilation — the CLI warns). Cache-only by design: the
attacker-controlled bundle is parsed at attach time, never unprompted
at run start. Note the two engines differ in extraction fidelity
(comment/type counts can shift when an attachment is re-imported by
the other engine). `export` without `--to` syncs findings into every
attached project. `detach` with no argument releases all attachments;
`status` lists attachments and their cache state. `--wait` on
attach/detach blocks on a busy project lock instead of failing fast.
The binding is operator-initiated only — nothing harvests `.gpr`
files from the scanned repo, and cached databases are read
exclusively from RAPTOR-owned output locations.

### import

One-shot import of a Ghidra project into RAPTOR's REDatabase format.
Exports functions, xrefs, types, comments, segments, imports, exports,
strings, and bookmarks to `re-database.json`.

Engine fallback: a sandboxed `analyzeHeadless` (from `PATH`) is the
default; with only pyghidra installed the import runs in-process.
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
import (no JVM), then the sandboxed persistent decompile server, then
in-process pyghidra (only when in-process is the preferred engine),
then objdump disassembly from a cached `re-database.json` (degraded).

### list

List programs (imported binaries) inside a Ghidra project.

### export

Write RAPTOR findings from an output directory into the Ghidra project
as comments and bookmarks (operator reviews them in Ghidra). Without
`--to`, exports to every ATTACHED project; with `--to`, to that .gpr
explicitly. All sources (agentic results, audit journal, annotations)
are gathered into ONE apply pass; counts printed are submissions —
names that don't resolve in the binary are skipped during apply.
Ghidra project comments travel the other way only as review-prompt
context — never into `/annotate` (annotations are human-written only).
