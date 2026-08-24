"""Graduated engine-rules directory resolution.

Graduation writes trusted engine config (Semgrep/Coccinelle rules that
later runs LOAD AND EXECUTE), so WHERE it writes is a privilege
decision:

* run pinned to project P → ``<P.output_dir>/engine-rules`` (requires
  an AUTHORITATIVE pin — the legacy containment fallback authorizes
  reads only);
* standalone run (pin null) → ``<out-root>/engine-rules/<target-id>/``
  — TARGET-KEYED, preserving the working standalone audit→scan
  rule-reuse loop while killing the pre-fix cross-target hazard
  (rules graduated from any tree landing in the shared
  ``out/engine-rules`` and loading as trusted config for EVERY future
  standalone run of ANY target);
* pin-less legacy run dir → no graduation (reads-only rule).

The read side (``packages/static-analysis/scanner.py``'s candidate
walk — the dashed package dir is not importable, keep it in sync — and
``core/audit/corpus/rule_eval.py``) probes the same locations.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def target_rules_key(target: Path | str) -> str:
    """Stable per-target subdir name: sha256 of the resolved target
    path (16 hex chars — the SAGE repo-key idiom)."""
    resolved = str(Path(target).resolve())
    return hashlib.sha256(resolved.encode("utf-8")).hexdigest()[:16]


def graduation_dir(out_dir: Path | str | None,
                   target: Path | str | None) -> Path | None:
    """Where THIS run's graduated rules go, or None (suppressed)."""
    if out_dir is None:
        return None
    try:
        from core.run.pin import pin_project_dir, resolve_run_pin
        pin = resolve_run_pin(out_dir)
        if not pin.authoritative:
            logger.info(
                "rule library: graduation suppressed for %s — legacy "
                "(pin-less) run dir; containment authorizes reads only",
                out_dir)
            return None
        from core.run.pin import pinned_write_target_ok
        proj_dir = pin_project_dir(out_dir, for_write=True)
        if proj_dir is not None and pinned_write_target_ok(out_dir, target):
            return proj_dir / "engine-rules"
        if target is None:
            return None
        from core.config import RaptorConfig
        return (RaptorConfig.get_out_dir() / "engine-rules"
                / target_rules_key(target))
    except Exception:  # noqa: BLE001 — graduation is best-effort
        logger.debug("rule library: graduation dir resolution failed",
                     exc_info=True)
        return None


def standalone_read_candidates(target: Path | str | None) -> list[Path]:
    """Target-keyed standalone locations the READ side probes."""
    if target is None:
        return []
    try:
        from core.config import RaptorConfig
        return [RaptorConfig.get_out_dir() / "engine-rules"
                / target_rules_key(target)]
    except Exception:  # noqa: BLE001
        return []
