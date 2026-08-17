"""Compiler-channel spot-checks for constant-shaped study questions.

The grep/extractor spot-check (``core.concepts.spot_check``) decides
questions whose constant carries a textual literal.  Computed
constants (``#define X (A + 4*B)``), enum auto-values, and
``sizeof``/``alignof``/``offsetof`` claims are textually undecidable —
for C/C++ targets this module resolves them by compile-probe: a
throwaway translation unit includes the defining file and asserts the
claimed value with ``_Static_assert`` (C) / ``static_assert`` (C++).
Compile success/failure IS the mechanical verdict — no diagnostic
text is ever parsed to decide.

Three-step probe protocol (each step sandboxed, per-step timeout):

1. **baseline** — the TU with no assertion.  Failure means the file
   does not compile standalone (missing config.h, needs build flags):
   the probe is *unavailable*, never a verdict.
2. **tautology** — ``assert((EXPR) == (EXPR))``.  Failure means the
   expression is not a compile-time constant here (undeclared,
   non-ICE): *unavailable*.
3. **claim** — ``assert((EXPR) == (VALUE))``.  With steps 1-2 green,
   success verifies the claim and failure can only be the assertion
   itself: *contradicted*.

This makes "assert failed" vs "unrelated compile error" a structural
distinction, not a locale/version-dependent diagnostic-text parse.
Verdicts carry a MECHANICAL-tier receipt: probe source hash, compiler
+ version, and a diagnostic snippet (recorded for humans only).

Untrusted-repo discipline: question text is LLM output and file paths
come from the scanned repo — the probe expression is allowlist-
sanitised before entering the TU, paths are embedded via ``#include``
of an absolute path written by us (never shell-interpolated), and
every compile runs through ``core.sandbox.context.run`` with network
blocked.  No sandbox → no probe (unavailable), mirroring the
compiler-sweep constraint.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Limits — consistent with the compiler-sweep harness's probe class.
_PROBE_COMPILE_TIMEOUT_S = 30
_DEFAULT_PROBE_CAP = 16
_MAX_EXPR_LEN = 120
_MAX_DIAG_SNIPPET = 400

_C_SUFFIXES = frozenset((".c", ".h"))
_CPP_SUFFIXES = frozenset((".cc", ".cpp", ".cxx", ".hpp", ".hxx", ".hh"))

_ASSERT_MARKER = "RAPTOR_STUDY_PROBE"


# ---------------------------------------------------------------------------
# Toolchain probe (cached; RAPTOR-chosen input, plain subprocess is the
# right trust level — the sandbox is reserved for compiles that read
# repo content)
# ---------------------------------------------------------------------------

_TOOLCHAIN_LOCK = threading.Lock()
_TOOLCHAIN_CACHE: dict[str, tuple[str, str] | None] = {}


def _safe_env() -> dict | None:
    try:
        from core.config import RaptorConfig
        return RaptorConfig.get_safe_env()
    except ImportError:
        return None


def _reset_toolchain_cache() -> None:
    """Test hook."""
    with _TOOLCHAIN_LOCK:
        _TOOLCHAIN_CACHE.clear()


def _find_toolchain(lang: str) -> tuple[str, str] | None:
    """``(compiler_path, version_line)`` for *lang* ("c"/"c++"), or
    None when no working compiler is on PATH."""
    with _TOOLCHAIN_LOCK:
        if lang in _TOOLCHAIN_CACHE:
            return _TOOLCHAIN_CACHE[lang]
    result: tuple[str, str] | None = None
    candidates = (
        ("gcc", "g++"), ("clang", "clang++"), ("cc", "c++"),
    )
    for c_name, cpp_name in candidates:
        name = c_name if lang == "c" else cpp_name
        path = shutil.which(name)
        if not path:
            continue
        try:
            ok = subprocess.run(
                [path, "-fsyntax-only", "-x", lang, os.devnull],
                capture_output=True, text=True, check=False,
                timeout=_PROBE_COMPILE_TIMEOUT_S, env=_safe_env(),
            )
            if ok.returncode != 0:
                continue
            ver = subprocess.run(
                [path, "--version"],
                capture_output=True, text=True, check=False,
                timeout=_PROBE_COMPILE_TIMEOUT_S, env=_safe_env(),
            )
            version = (ver.stdout or "").splitlines()[0].strip() if (
                ver.stdout
            ) else ""
            result = (path, version)
            break
        except (OSError, subprocess.SubprocessError):
            continue
    with _TOOLCHAIN_LOCK:
        _TOOLCHAIN_CACHE[lang] = result
    return result


# ---------------------------------------------------------------------------
# Question parsing + expression sanitisation
# ---------------------------------------------------------------------------

_VALUE = r"([-+]?0[xX][0-9a-fA-F]+|[-+]?\d+)"

# sizeof(struct foo) / alignof(x) / offsetof(struct s, m) claims
_BUILTIN_EXPR_RE = re.compile(
    r"((?:sizeof|_Alignof|alignof|offsetof)\s*\(\s*[^()]{1,80}\))\s*"
    r"(?:is|==|equals?|equal to|set to)?\s*"
    rf"[`'\"]?{_VALUE}[`'\"]?",
    re.IGNORECASE,
)

# plain identifier claim: "Is STATE_DONE 3?" / "MAX_BUF == 4096"
_IDENT_EXPR_RE = re.compile(
    r"[`'\"]?([A-Za-z_]\w*)[`'\"]?\s*"
    r"(?:is|==|equals?|equal to|set to|defined as)?\s*"
    rf"[`'\"]?{_VALUE}[`'\"]?",
)

# Allowlist for text that may enter the probe TU.  Anything outside
# this (quotes, semicolons, braces, preprocessor, comments, backslash)
# rejects the question — never sanitise-and-continue.
_EXPR_ALLOWED_RE = re.compile(r"^[A-Za-z0-9_ \t(),.*+/\-<>&|^~\[\]]+$")
_EXPR_FORBIDDEN = ("__asm", "//", "/*", "..")


def _expr_safe(expr: str) -> bool:
    if not expr or len(expr) > _MAX_EXPR_LEN:
        return False
    if not _EXPR_ALLOWED_RE.match(expr):
        return False
    lowered = expr.lower()
    return all(tok not in lowered for tok in _EXPR_FORBIDDEN)


def parse_probe_claim(question: str) -> tuple[str, str] | None:
    """Extract ``(expression, claimed_value)`` from a constant claim.

    Returns None when the question does not assert a numeric value
    against an expression, or when the expression fails the allowlist.
    """
    if not question:
        return None
    m = _BUILTIN_EXPR_RE.search(question)
    if m is None:
        m = _IDENT_EXPR_RE.search(question)
    if m is None:
        return None
    expr, value = m.group(1).strip(), m.group(2)
    if not _expr_safe(expr):
        return None
    return expr, value


# ---------------------------------------------------------------------------
# Probe TU generation
# ---------------------------------------------------------------------------

def _assert_stmt(expr: str, rhs: str, lang: str) -> str:
    kw = "_Static_assert" if lang == "c" else "static_assert"
    return f'{kw}(({expr}) == ({rhs}), "{_ASSERT_MARKER}");'


def generate_probe_source(
    include_path: Path,
    expr: str | None,
    claimed_value: str | None,
    lang: str,
) -> str:
    """The throwaway TU: include the defining file, optionally assert.

    ``expr is None`` → baseline TU (include only).
    ``claimed_value is None`` → tautology TU (expr == expr).
    """
    lines = [
        f"/* {_ASSERT_MARKER}: generated probe — never persisted */",
        f'#include "{include_path}"',
    ]
    if expr is not None and lang == "c":
        lines.append("#include <stddef.h>")  # offsetof
    if expr is not None:
        if claimed_value is None:
            lines.append(_assert_stmt(expr, expr, lang))
        else:
            lines.append(_assert_stmt(expr, claimed_value, lang))
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Probe execution
# ---------------------------------------------------------------------------

@dataclass
class ProbeBudget:
    """Per-run probe cap (shared across batches by the consumer)."""

    remaining: int = _DEFAULT_PROBE_CAP

    def take(self) -> bool:
        if self.remaining <= 0:
            return False
        self.remaining -= 1
        return True


@dataclass
class CompileProbeResult:
    """Outcome of one compile-probe question."""

    #: verified | contradicted | unavailable
    status: str
    expression: str = ""
    claimed_value: str = ""
    reason: str = ""
    answer: str = ""
    compiler: str = ""
    compiler_version: str = ""
    probe_sha256: str = ""
    diagnostic_snippet: str = ""
    include_file: str = ""
    notes: list[str] = field(default_factory=list)


def _compile_tu(
    source_text: str,
    workdir: Path,
    compiler: str,
    lang: str,
    include_dirs: list[str],
    source_root: Path,
) -> tuple[bool, str] | None:
    """Sandbox-compile one TU.  Returns ``(ok, diagnostics)`` or None
    when the sandboxed invocation itself failed (timeout/OS error)."""
    try:
        from core.sandbox.context import run as sandbox_run
    except ImportError:
        return None

    suffix = ".c" if lang == "c" else ".cpp"
    tu_path = workdir / f"probe{suffix}"
    tu_path.write_text(source_text, encoding="utf-8")

    cmd = [compiler, "-fsyntax-only", "-x", lang]
    for d in include_dirs:
        cmd.extend(["-I", d])
    cmd.append(str(tu_path))

    try:
        proc = sandbox_run(
            cmd,
            block_network=True,
            target=str(source_root),
            output=str(workdir),
            cwd=str(workdir),
            capture_output=True,
            text=True,
            timeout=_PROBE_COMPILE_TIMEOUT_S,
            caller_label="study-compile-probe",
        )
    except subprocess.TimeoutExpired:
        return None
    except (subprocess.SubprocessError, OSError, ValueError, TypeError):
        return None
    diag = (proc.stderr or "")[:_MAX_DIAG_SNIPPET]
    return (proc.returncode == 0, diag)


def compile_probe_question(
    question: str,
    study_items: list[dict],
    source_root: Path,
    *,
    budget: ProbeBudget | None = None,
) -> CompileProbeResult | None:
    """Resolve a textually undecidable constant claim by compile-probe.

    Returns None when the question is not compile-probe shaped (no
    numeric claim, no C/C++ corpus item to include).  Otherwise a
    :class:`CompileProbeResult` whose status is ``verified`` /
    ``contradicted`` (mechanical verdicts) or ``unavailable`` (with
    the reason — the caller keeps the question's prior state).
    """
    claim = parse_probe_claim(question)
    if claim is None:
        return None
    expr, value = claim

    # The defining file: the corpus item whose name appears in the
    # expression (identifier claims) or in the question (builtin
    # claims reference a type/member defined somewhere in the corpus).
    probe_item = None
    expr_tokens = set(re.findall(r"[A-Za-z_]\w*", expr))
    q_tokens = set(re.findall(r"[A-Za-z_]\w*", question))
    for it in study_items:
        if not isinstance(it, dict):
            continue
        suffix = Path(it.get("file") or "").suffix.lower()
        if suffix not in _C_SUFFIXES | _CPP_SUFFIXES:
            continue
        name = it.get("name") or ""
        if name in expr_tokens or name in q_tokens:
            probe_item = it
            break
    if probe_item is None:
        return None  # not a C/C++ question — textual resolver's turf

    lang = (
        "c"
        if Path(probe_item["file"]).suffix.lower() in _C_SUFFIXES
        else "c++"
    )

    def _unavailable(reason: str) -> CompileProbeResult:
        return CompileProbeResult(
            status="unavailable", expression=expr, claimed_value=value,
            reason=reason, include_file=probe_item.get("file") or "",
        )

    if budget is not None and not budget.take():
        return _unavailable("per-run probe cap reached")

    toolchain = _find_toolchain(lang)
    if toolchain is None:
        return _unavailable(f"no working {lang} compiler on PATH")
    compiler, version = toolchain

    include_path = (Path(source_root) / probe_item["file"]).resolve()
    try:
        include_path.relative_to(Path(source_root).resolve())
    except ValueError:
        return _unavailable("defining file escapes the source root")
    if not include_path.is_file():
        return _unavailable("defining file not found under source root")

    try:
        from core.audit.compiler_sweep import _derive_include_dirs
        include_dirs = _derive_include_dirs(
            Path(source_root), include_path.parent,
        )
    except Exception:  # noqa: BLE001 - fall back to the minimal set
        include_dirs = [str(source_root), str(include_path.parent)]

    claim_src = generate_probe_source(include_path, expr, value, lang)
    probe_sha = hashlib.sha256(claim_src.encode()).hexdigest()[:16]

    with tempfile.TemporaryDirectory(
        prefix="raptor_study_probe_",
    ) as td:
        workdir = Path(td)

        # Step 1: baseline — the file must compile standalone.
        baseline = _compile_tu(
            generate_probe_source(include_path, None, None, lang),
            workdir, compiler, lang, include_dirs, Path(source_root),
        )
        if baseline is None:
            return _unavailable(
                "sandboxed compile invocation failed (sandbox missing, "
                "timeout, or OS error)",
            )
        ok, diag = baseline
        if not ok:
            detail = diag.splitlines()[0][:160] if diag else ""
            return _unavailable(
                "defining file does not compile standalone"
                + (f": {detail}" if detail else ""),
            )

        # Step 2: tautology — the expression must be a compile-time
        # constant here.  (EXPR == EXPR) only fails when EXPR itself
        # is ill-formed or non-constant.
        tautology = _compile_tu(
            generate_probe_source(include_path, expr, None, lang),
            workdir, compiler, lang, include_dirs, Path(source_root),
        )
        if tautology is None:
            return _unavailable("sandboxed compile invocation failed")
        ok, diag = tautology
        if not ok:
            return _unavailable(
                "expression is not a compile-time constant here: "
                + (diag.splitlines()[0][:160] if diag else expr),
            )

        # Step 3: the claim.  Steps 1-2 green means failure here can
        # only be the assertion — compile result IS the verdict.
        claim_run = _compile_tu(
            claim_src, workdir, compiler, lang, include_dirs,
            Path(source_root),
        )
        if claim_run is None:
            return _unavailable("sandboxed compile invocation failed")
        ok, diag = claim_run

    status = "verified" if ok else "contradicted"
    rel = probe_item.get("file") or ""
    if ok:
        answer = (
            f"compile-probe: ({expr}) == {value} holds "
            f"[{compiler} static assertion accepted]"
        )
    else:
        answer = (
            f"compile-probe: ({expr}) == {value} DOES NOT hold "
            f"[{compiler} static assertion failed]"
        )
    return CompileProbeResult(
        status=status,
        expression=expr,
        claimed_value=value,
        answer=answer,
        compiler=compiler,
        compiler_version=version,
        probe_sha256=probe_sha,
        diagnostic_snippet="" if ok else diag[:_MAX_DIAG_SNIPPET],
        include_file=rel,
    )


def probe_receipt(result: CompileProbeResult, line: int | None = None):
    """MECHANICAL-tier receipt for a decided compile probe.

    ``sha256`` pins the probe source; ``note`` carries the compiler +
    version and (for contradictions) the diagnostic snippet — recorded
    for humans, never parsed for decisions.
    """
    from core.concepts.receipts import TIER_MECHANICAL, Receipt

    note = f"compile-probe: {result.compiler} ({result.compiler_version})"
    if result.diagnostic_snippet:
        note += f"; diag: {result.diagnostic_snippet[:200]}"
    return Receipt(
        file=result.include_file,
        line=line,
        quote=_assert_stmt(
            result.expression, result.claimed_value, "c",
        ),
        verified=True,
        sha256=result.probe_sha256,
        tier=TIER_MECHANICAL,
        note=note,
    )
