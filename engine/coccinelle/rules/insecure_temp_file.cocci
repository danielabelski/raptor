// insecure_temp_file.cocci — Detect race-prone temporary-file creation.
//
// Two shapes, both CWE-377 (Insecure Temporary File):
//
// 1. Name-generation APIs: mktemp/tmpnam/tmpnam_r/tempnam only
//    produce a pathname — between name generation and the open() an
//    attacker who can write the temp directory creates or symlinks
//    the path, redirecting the victim's create/write (classic /tmp
//    symlink attack). glibc marks all four with link-time warnings;
//    any call is the bug, so this group flags the call itself.
//
// 2. mkstemp-then-reopen-by-path: mkstemp and friends are the safe
//    replacement because the fd they return is race-free — but
//    re-opening the filled-in template BY PATH afterwards discards
//    that guarantee and reintroduces the same window shape 1 avoids.
//    Use the returned fd (fdopen/dup) instead.
//
// Known limitations:
// - Group 2 is intra-procedural: a template reopened by a callee is
//   not seen (Coccinelle cannot trace the path across functions).
// - Group 1 does not attempt to prove the generated name is used —
//   a dead mktemp() call is still flagged (correct: the API itself
//   is the defect, and glibc warns on any use).
//
// CWE-377: Insecure Temporary File
// @role: verification

// ---------------------------------------------------------------
// Group 1: race-prone temp-name generation APIs
// ---------------------------------------------------------------

@name_gen@
position p;
@@

(
* mktemp@p(...)
|
* tmpnam@p(...)
|
* tmpnam_r@p(...)
|
* tempnam@p(...)
)

@script:python@
p << name_gen.p;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "insecure_temp_file",
          "message": "Race-prone temp-name API — the pathname can be "
                     "hijacked between generation and open (CWE-377). "
                     "Use mkstemp and keep the returned fd."}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// ---------------------------------------------------------------
// Group 2: mkstemp template reopened by path
// ---------------------------------------------------------------

@mkstemp_reopen@
expression FD, T, T2;
position p1, p2;
@@

(
  FD = mkstemp@p1(T)
|
  FD = mkostemp@p1(T, ...)
|
  FD = mkstemps@p1(T, ...)
|
  FD = mkostemps@p1(T, ...)
)
  ... when != T = T2
(
* open(T, ...)@p2
|
* fopen(T, ...)@p2
)

@script:python@
p1 << mkstemp_reopen.p1;
p2 << mkstemp_reopen.p2;
T << mkstemp_reopen.T;
@@

import json, sys
for _p1, _p2 in zip(p1, p2):
    _m = {"file": _p2.file, "line": int(_p2.line), "col": int(_p2.column),
          "line_end": int(_p2.line_end), "col_end": int(_p2.column_end),
          "rule": "insecure_temp_file",
          "message": "Template '%s' from mkstemp at line %s reopened "
                     "by path — the by-name reopen races like mktemp "
                     "(CWE-377). Use the returned fd (fdopen/dup)."
                     % (T, _p1.line)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
