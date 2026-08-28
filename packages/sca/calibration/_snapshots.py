"""Retention pruning for dated calibration snapshot directories.

``validation/<date>.json`` and ``refit/<date>[.joint].json`` are
append-per-run outputs: every refresh adds a file and nothing ever
deleted one, so the directories (and every consumer that lists or
globs them — ``risk._load_latest_validation_verdict`` sorts the whole
listing on first use in each SCA process; the refit workflow globs the
directory as a precondition) grew without bound in the repo.

Retention is applied by the writers right after a successful write.
Consumers only ever need the latest snapshot plus enough history to
judge verdict stability (the validation PR flow reads ~6 months of
weekly snapshots), so the keep-window defaults preserve that.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# ~6 months of weekly validation runs.
VALIDATION_KEEP = 26
# Refits are operator-triggered and rare; a year's worth is plenty.
REFIT_KEEP = 12

# Strictly date-shaped snapshot names — anything else in the directory
# (README, operator notes) is never touched.
_SNAPSHOT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(\.joint)?\.json$")


def prune_dated_snapshots(directory: Path, *, keep: int) -> list[Path]:
    """Delete the oldest date-named snapshots beyond ``keep``.

    Filenames are ISO dates, so lexicographic order is chronological.
    Returns the deleted paths (empty when nothing was pruned). Delete
    failures are logged and skipped — retention is housekeeping, never
    worth failing a corpus write over.
    """
    if keep < 1:
        msg = f"keep must be >= 1, got {keep}"
        raise ValueError(msg)
    try:
        snapshots = sorted(
            p for p in directory.iterdir()
            if p.is_file() and _SNAPSHOT_RE.match(p.name)
        )
    except OSError:
        return []
    doomed = snapshots[:-keep] if len(snapshots) > keep else []
    deleted: list[Path] = []
    for p in doomed:
        try:
            p.unlink()
            deleted.append(p)
        except OSError as e:
            logger.warning(
                "sca.calibration: could not prune snapshot %s: %s", p, e,
            )
    if deleted:
        logger.info(
            "sca.calibration: pruned %d old snapshot(s) from %s "
            "(keep=%d)", len(deleted), directory.name, keep,
        )
    return deleted


__all__ = ["REFIT_KEEP", "VALIDATION_KEEP", "prune_dated_snapshots"]
