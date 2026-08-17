"""Shared skill-dispatch runner for lifecycle-managed ``claude -p`` passes.

Both /agentic's enrichment passes (``core/orchestration/agentic_passes``)
and /audit's post-audit validation handoff (``core/audit/validate``)
dispatch a Claude Code subprocess with a skill loaded, wrapped in the
same run-lifecycle bookkeeping. The audit copy was written second and
had already drifted behind the agentic one (head-truncation instead of
signal-sorted truncation, no ``OSError`` launch handling, and — the
security-relevant one — no cc-trust ``block_cc_dispatch`` gate). This
module is the single implementation of the MECHANICS:

- the gate chain: cc-trust block → rule-of-two → claude on PATH →
  caller preflight;
- lifecycle start/complete/fail via ``libexec/raptor-run-lifecycle``
  (with ``get_safe_env()`` so an untrusted target's ambient env never
  reaches the helpers);
- the sandboxed ``run_untrusted_networked`` dispatch with
  ``TimeoutExpired``/``OSError`` handling and the
  KeyboardInterrupt-aware "settled" pattern so an interrupted run dir
  never lingers in "running" state;
- signal-sorted truncation for over-cap finding selections.

Everything POLICY-shaped stays caller-side: which findings qualify,
what the prompt says, and what happens with the artefacts afterwards
(checklist enrichment, audit's auto-feedback hook).
"""

from __future__ import annotations

import logging
import math
import shutil
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from core.llm.cc_proxy_hosts import (
    proxy_hosts_for_cc_dispatch as _proxy_hosts_for_cc_dispatch,
)
from core.llm.cc_proxy_hosts import (
    readable_paths_for_cc_dispatch as _readable_paths_for_cc_dispatch,
)
from core.sandbox import run_untrusted_networked

logger = logging.getLogger(__name__)

# core/orchestration/skill_dispatch.py -> repo root (parents[2])
_RAPTOR_DIR = Path(__file__).resolve().parents[2]
_LIFECYCLE = _RAPTOR_DIR / "libexec" / "raptor-run-lifecycle"
_BUILD_CHECKLIST = _RAPTOR_DIR / "libexec" / "raptor-build-checklist"

# Sanity cap: even a pathological report shouldn't push more than this
# through a single post-pass subprocess. Above the cap callers truncate
# (signal-sorted — see truncate_findings_by_signal) and log a warning.
MAX_VALIDATE_FINDINGS = 50

_LIFECYCLE_TIMEOUT_S = 30   # lifecycle helpers are mechanical; should be instant
_CHECKLIST_TIMEOUT_S = 300  # build_checklist parses every source file


@dataclass
class SkillDispatchResult:
    """Outcome of :func:`run_skill_dispatch`.

    ``run_dir`` is set as soon as the lifecycle started, including on
    failure paths, so callers can surface the partially-populated run
    directory to the operator.
    """
    ran: bool
    skipped_reason: str | None = None
    run_dir: Path | None = None
    duration_s: float = 0.0


class StageError(Exception):
    """Raised by a caller's ``stage`` callback to abort the dispatch
    with a specific reason (the lifecycle is marked failed with it)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# ---------------------------------------------------------------------------
# Lifecycle helpers — wrap libexec/raptor-run-lifecycle and raptor-build-checklist.
# ---------------------------------------------------------------------------


def start_lifecycle(command: str, target: Path) -> Path | None:
    """Start a new lifecycle-managed run dir.

    Returns the OUTPUT_DIR path on success, or None if the helper failed
    or its output couldn't be parsed.

    The helpers run with `RaptorConfig.get_safe_env()` (strict allowlist)
    rather than the inherited environment. When the pipeline runs against
    an untrusted target — operator points RAPTOR at a freshly cloned OSS
    repo — the parent env may carry attacker-relevant vars (LD_PRELOAD,
    PYTHONSTARTUP, BASH_ENV from a poisoned dotfile, GIT_CONFIG_GLOBAL
    pointing at a malicious config). Inheriting them into the lifecycle
    subprocesses (which themselves invoke raptor-managed bash + python)
    widens the trust boundary unnecessarily. The helpers don't depend on
    operator env beyond PATH/HOME/USER, which get_safe_env preserves.
    """
    from core.config import RaptorConfig
    safe_env = RaptorConfig.get_safe_env()
    try:
        proc = subprocess.run(
            [str(_LIFECYCLE), "start", command, "--target", str(target)],
            capture_output=True, text=True, timeout=_LIFECYCLE_TIMEOUT_S,
            env=safe_env, check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning("lifecycle start %s failed: %s", command, e)
        return None
    if proc.returncode != 0:
        logger.warning("lifecycle start %s returned %d: %s",
                       command, proc.returncode, (proc.stderr or "")[:300])
        return None
    for line in reversed(proc.stdout.splitlines()):
        line = line.strip()
        if line.startswith("OUTPUT_DIR="):
            return Path(line[len("OUTPUT_DIR="):]).resolve()
    logger.warning("lifecycle start %s did not emit OUTPUT_DIR=", command)
    return None


def complete_lifecycle(output_dir: Path) -> None:
    """Mark a lifecycle run as completed. Best-effort; swallows errors.

    See `start_lifecycle` for the env=safe_env rationale.
    """
    from core.config import RaptorConfig
    safe_env = RaptorConfig.get_safe_env()
    try:
        proc = subprocess.run(
            [str(_LIFECYCLE), "complete", str(output_dir)],
            capture_output=True, text=True, timeout=_LIFECYCLE_TIMEOUT_S,
            env=safe_env, check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning("lifecycle complete failed: %s", e)
        return
    if proc.returncode != 0:
        logger.warning("lifecycle complete returned %d: %s",
                       proc.returncode, (proc.stderr or "")[:300])


def fail_lifecycle(output_dir: Path | None, message: str) -> None:
    """Mark a lifecycle run as failed. Best-effort; swallows errors.

    See `start_lifecycle` for the env=safe_env rationale.
    """
    if output_dir is None:
        return
    from core.config import RaptorConfig
    safe_env = RaptorConfig.get_safe_env()
    try:
        proc = subprocess.run(
            [str(_LIFECYCLE), "fail", str(output_dir), message],
            capture_output=True, text=True, timeout=_LIFECYCLE_TIMEOUT_S,
            env=safe_env, check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning("lifecycle fail failed: %s", e)
        return
    if proc.returncode != 0:
        logger.warning("lifecycle fail returned %d: %s",
                       proc.returncode, (proc.stderr or "")[:300])


def build_checklist(target: Path, output_dir: Path) -> bool:
    """Run libexec/raptor-build-checklist. Returns True on success.

    See `start_lifecycle` for the env=safe_env rationale.
    """
    from core.config import RaptorConfig
    safe_env = RaptorConfig.get_safe_env()
    try:
        proc = subprocess.run(
            [str(_BUILD_CHECKLIST), str(target), str(output_dir)],
            capture_output=True, text=True, timeout=_CHECKLIST_TIMEOUT_S,
            env=safe_env, check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning("build_checklist failed: %s", e)
        return False
    if proc.returncode != 0:
        logger.warning("build_checklist returned %d: %s",
                       proc.returncode, (proc.stderr or "")[:300])
        return False
    return True


# ---------------------------------------------------------------------------
# Signal-sorted truncation.
# ---------------------------------------------------------------------------


def _safe_score(f: dict) -> float:
    """Coerce ``exploitability_score`` for sorting.

    The schema says exploitability_score is a number, but malformed LLM
    output (e.g. "high" instead of 0.9) shouldn't crash sort
    mid-truncation. Coerce non-numeric to 0. Also guard against NaN/Inf
    — Python sort with NaN keys produces undefined order because NaN
    compares False to everything; we'd get non-deterministic truncation.
    """
    raw = f.get("exploitability_score")
    try:
        v = float(raw) if raw is not None else 0.0
    except (TypeError, ValueError):
        return 0.0
    if math.isnan(v) or math.isinf(v):
        return 0.0
    return v


def _signal_key(f: dict) -> tuple:
    return (
        0 if f.get("is_exploitable") is True else 1,  # exploitable first
        -_safe_score(f),                                # score descending
    )


def truncate_findings_by_signal(
    findings: list,
    cap: int = MAX_VALIDATE_FINDINGS,
    *,
    log_label: str = "post-pass",
) -> list:
    """Cap *findings* at *cap*, dropping the weakest qualifiers.

    Sorts by signal strength so truncation drops the weakest, not
    whoever happened to be last in report order. Priority:

    1. ``is_exploitable=True`` wins over confidence-only
    2. higher ``exploitability_score`` wins (when present)
    3. ties broken by input order (Python sort is stable)

    Entries missing both signal fields all tie, so a caller whose
    findings carry neither (e.g. audit emissions) keeps its input
    order for the survivors — never worse than head-truncation, and
    strictly better as soon as any entry carries a signal field.
    Returns the input list unchanged when it's within the cap.
    """
    if len(findings) <= cap:
        return findings
    ranked = sorted(findings, key=_signal_key)
    logger.warning(
        "%s: %d findings selected; truncating to %d "
        "(keeping highest-signal: is_exploitable then exploitability_score)",
        log_label, len(findings), cap,
    )
    return ranked[:cap]


# ---------------------------------------------------------------------------
# The generic gated dispatch runner.
# ---------------------------------------------------------------------------


def run_skill_dispatch(
    *,
    command: str,
    target: Path,
    tools: str,
    budget_usd: str,
    timeout_s: int,
    caller_label: str,
    log_label: str,
    build_prompt: Callable[[Path], str],
    block_cc_dispatch: bool = False,
    claude_bin: str | None = None,
    context_dirs: Sequence[Path] = (),
    preflight: Callable[[], str | None] | None = None,
    stage: Callable[[Path], None] | None = None,
    validate_outputs: Callable[[Path], str | None] | None = None,
) -> SkillDispatchResult:
    """Run one lifecycle-managed, sandboxed ``claude -p`` skill pass.

    Gate chain (first hit wins, mirrors the /agentic post-pass order):

    1. ``block_cc_dispatch`` — cc-trust verdict for the target repo
       (compute via ``core.security.cc_trust.check_repo_claude_trust``);
    2. rule-of-two: human terminal or effective sandbox (per
       ``require_human_or_sandbox_for_agentic_pass(command)``);
    3. ``claude`` binary on PATH (or explicit ``claude_bin``);
    4. caller ``preflight()`` — cheap caller-side checks (report
       exists, selection non-empty); return a skip reason or None.

    Then: lifecycle start → ``stage(run_dir)`` (write selection files /
    pointers into the run dir; raise :class:`StageError` to abort with
    a reason) → ``build_prompt(run_dir)`` → sandboxed dispatch →
    ``validate_outputs(run_dir)`` (return an error string to fail the
    run) → lifecycle complete.

    ``context_dirs`` are prior-phase artefact dirs the CC child must
    read (e.g. the parent pipeline's out_dir): they are appended to the
    sandbox ``add_dirs`` and ``readable_paths``. ``target`` and the run
    dir are always included.

    May raise: unexpected exceptions propagate AFTER the lifecycle is
    marked failed — callers keep their own never-raise wrapper so the
    base pipeline survives (both existing callers already do).
    KeyboardInterrupt / SystemExit also mark the lifecycle failed
    ("interrupted") before propagating.
    """
    if block_cc_dispatch:
        return SkillDispatchResult(
            ran=False,
            skipped_reason="cc_trust blocked dispatch (untrusted target)")

    from core.security.rule_of_two import (
        NonInteractiveError,
        require_human_or_sandbox_for_agentic_pass,
    )
    try:
        require_human_or_sandbox_for_agentic_pass(command)
    except NonInteractiveError as e:
        return SkillDispatchResult(ran=False, skipped_reason=str(e))

    claude_bin = claude_bin or shutil.which("claude")
    if not claude_bin:
        return SkillDispatchResult(ran=False, skipped_reason="claude not on PATH")

    if preflight is not None:
        reason = preflight()
        if reason is not None:
            return SkillDispatchResult(ran=False, skipped_reason=reason)

    target = Path(target).resolve()
    context_dirs = [Path(d).resolve() for d in context_dirs]

    t0 = time.monotonic()

    run_dir = start_lifecycle(command, target)
    if run_dir is None:
        return SkillDispatchResult(ran=False,
                                   skipped_reason="lifecycle start failed",
                                   duration_s=time.monotonic() - t0)

    # Track whether the run reached a definitive end-state. If we exit
    # via KeyboardInterrupt or another BaseException (which Exception
    # doesn't catch), the finally clause still marks the lifecycle
    # failed so the run dir doesn't linger in "running" state forever.
    lifecycle_settled = False
    try:
        if stage is not None:
            try:
                stage(run_dir)
            except StageError as e:
                # Mark settled BEFORE the call so that if fail_lifecycle
                # itself raises, the `finally` block's "interrupted"
                # fallback doesn't overwrite the real failure reason.
                # Same pattern at every other fail_lifecycle call site
                # in this function.
                lifecycle_settled = True
                fail_lifecycle(run_dir, e.reason)
                return SkillDispatchResult(
                    ran=False, skipped_reason=e.reason, run_dir=run_dir,
                    duration_s=time.monotonic() - t0)

        prompt = build_prompt(run_dir)

        from core.llm.cc_adapter import (
            CCDispatchConfig,
            build_cc_command,
            cc_subprocess_env,
        )
        dispatch_config = CCDispatchConfig(
            claude_bin=claude_bin,
            tools=tools,
            add_dirs=(str(_RAPTOR_DIR), str(target),
                      *(str(d) for d in context_dirs), str(run_dir)),
            budget_usd=budget_usd,
            timeout_s=timeout_s,
            capture_json_envelope=False,
        )
        try:
            # Sandboxed Claude Code dispatch with restrict_reads=True.
            # See cc_dispatch.py for rationale; this site adds
            # str(_RAPTOR_DIR) on top of the calibrated/default
            # readable_paths so the LLM-directed Bash tool can invoke
            # libexec helpers (which live under RAPTOR_DIR), plus the
            # caller's context_dirs holding prior phases' artefacts.
            # target + run_dir are auto-allowlisted via the
            # target=/output= positional args; $HOME secrets stay
            # denied.
            # env: backend overlay (CLAUDE_CODE_*/ANTHROPIC_*/AWS_*) so
            # a Bedrock/Vertex-backed CLI child can authenticate; the
            # sandbox's proxy env still overrides HTTPS_PROXY.
            proc = run_untrusted_networked(
                build_cc_command(dispatch_config),
                input=prompt, text=True,
                timeout=timeout_s,
                target=str(target), output=str(run_dir),
                env=cc_subprocess_env(),
                # Trust-marker propagation: this child is RAPTOR's own
                # claude binary running a skill pass on the same
                # operator-approved run (gated above by cc-trust +
                # rule-of-two). Its job is to drive libexec/ helpers
                # (raptor-validation-helper, raptor-run-lifecycle)
                # whose preamble refuses callers without CLAUDECODE /
                # _RAPTOR_TRUSTED — the default marker strip left the
                # validate post-pass child looking untrusted (rc=1,
                # A4). A parent that holds no marker propagates
                # nothing: an untrusted parent stays refused.
                keep_trust_markers=True,
                readable_paths=(
                    [str(_RAPTOR_DIR)]
                    + [str(d) for d in context_dirs]
                    + _readable_paths_for_cc_dispatch(claude_bin)
                ),
                proxy_hosts=_proxy_hosts_for_cc_dispatch(claude_bin),
                caller_label=caller_label,
            )
        except subprocess.TimeoutExpired:
            lifecycle_settled = True
            fail_lifecycle(run_dir, f"timeout after {timeout_s}s")
            logger.warning("%s timed out after %ds", log_label, timeout_s)
            return SkillDispatchResult(
                ran=False, skipped_reason=f"timeout after {timeout_s}s",
                run_dir=run_dir, duration_s=time.monotonic() - t0)
        except OSError as e:
            lifecycle_settled = True
            fail_lifecycle(run_dir, f"launch failed: {e}")
            logger.warning("%s failed to launch: %s", log_label, e)
            return SkillDispatchResult(
                ran=False, skipped_reason=f"launch failed: {e}",
                run_dir=run_dir, duration_s=time.monotonic() - t0)

        if proc.returncode != 0:
            lifecycle_settled = True
            fail_lifecycle(run_dir, f"subprocess returned {proc.returncode}")
            logger.warning("%s returned %d: %s", log_label, proc.returncode,
                           (proc.stderr or "")[:500])
            return SkillDispatchResult(
                ran=False,
                skipped_reason=f"subprocess returned {proc.returncode}",
                run_dir=run_dir, duration_s=time.monotonic() - t0)

        if validate_outputs is not None:
            error = validate_outputs(run_dir)
            if error is not None:
                lifecycle_settled = True
                fail_lifecycle(run_dir, error)
                logger.warning("%s: %s", log_label, error)
                return SkillDispatchResult(
                    ran=False, skipped_reason=error, run_dir=run_dir,
                    duration_s=time.monotonic() - t0)

        complete_lifecycle(run_dir)
        lifecycle_settled = True

        return SkillDispatchResult(ran=True, run_dir=run_dir,
                                   duration_s=time.monotonic() - t0)

    except Exception:
        # Make sure the lifecycle is marked failed before propagating.
        lifecycle_settled = True
        fail_lifecycle(run_dir, "unexpected exception")
        raise
    finally:
        # KeyboardInterrupt / SystemExit / any other BaseException
        # bypasses the except-Exception clause above. Make sure the run
        # dir is marked failed so downstream consumers (the bridge)
        # don't keep finding it as "in progress".
        if not lifecycle_settled:
            fail_lifecycle(run_dir, "interrupted")


__all__ = [
    "MAX_VALIDATE_FINDINGS",
    "SkillDispatchResult",
    "StageError",
    "build_checklist",
    "complete_lifecycle",
    "fail_lifecycle",
    "run_skill_dispatch",
    "start_lifecycle",
    "truncate_findings_by_signal",
]
