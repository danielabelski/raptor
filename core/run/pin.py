"""Run-scoped project pinning.

A run is pinned to one project IDENTITY for its whole lifetime: the
resolved project name and the layer that produced it are recorded in
``.raptor-run.json`` at the first ``start_run`` and never re-resolved
ambiently afterwards — in-run consumers read the pin through the run
dir. This is what makes a mid-session ``/project use`` (or another
session's activity) unable to move trust markers, persisted binaries,
IRIS stores, graduated rules, journal merges, or threat models under a
run that is already in flight.

Two halves:

* **Start-time resolution** (:func:`resolve_pin_for_start`): the layer
  precedence — explicit ``--project`` argv (process-scoped, set by the
  entry points), then the session binding, then the ``.active``
  symlink, then none. ``--project -`` is the explicit bound-to-none
  argv. The pin value for "no project" is JSON ``null`` — NEVER the
  string ``"none"``, which is a legal project name.
* **In-run resolution** (:func:`resolve_run_pin`): walk UP from an
  explicit run-dir handle (an argument or a config ``out_dir`` — never
  the cwd) to the nearest ``.raptor-run.json`` and apply the state
  table:

  ========================================  =================================
  pin ``project=P``, P exists               P, authoritative
  pin ``project=null``                      authoritative none — containment
                                            inference FORBIDDEN
  pin ``project=P``, P deleted/renamed      loud warn + authoritative none
  no ``.raptor-run.json`` found             legacy fallback: containment
                                            inference — READS ONLY
  ========================================  =================================

  The legacy containment fallback (pre-series run dirs) authorizes
  READS only: privilege-bearing writes (engine-rules graduation,
  domain-model promotion, journal-index merges, threat-model writes)
  require a real pin and are suppressed without one.

Walk-up safety: the walk stops at the first marker, a known project
output dir, ``$HOME``, a filesystem boundary, or depth 8 — and a
marker is IGNORED when its directory is not owned by the current uid
or is group/world-writable, so a planted ``/tmp/.raptor-run.json``
can never capture privilege-bearing writes.
"""

from __future__ import annotations

import logging
import os
import stat as stat_mod
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

RUN_METADATA_FILE = ".raptor-run.json"

#: The pin's provenance enum (``project_source`` in run metadata).
PIN_SOURCES = ("argv", "session", "symlink", "none", "adopted", "merged")

#: Explicit bound-to-none argv value (``--project -``): special-cased
#: BEFORE name validation at every consumer.
ARGV_NONE = "-"

_WALK_DEPTH = 8

#: Process-scoped ``--project`` override. Set exactly once by an entry
#: point's arg parsing; children receive the value by explicit argv
#: threading, never ambiently.
_process_project: str | None = None
_process_project_set = False


@dataclass(frozen=True)
class RunPin:
    """Resolved pin for a run dir.

    ``project`` — the pinned project name, or None (standalone /
    unresolvable). ``source`` — the pin's provenance (one of
    PIN_SOURCES, or ``"containment"`` for the legacy fallback,
    ``"unresolved"`` when nothing matched). ``run_dir`` — the dir whose
    marker answered, when one did. ``authoritative`` — True when the
    answer came from a real pin (never from containment inference).
    ``writes_allowed`` — False on the legacy fallback: containment
    inference authorizes reads only.
    """

    project: str | None
    source: str
    run_dir: Path | None
    authoritative: bool
    writes_allowed: bool


def set_process_project(value: str | None) -> None:
    """Record the entry point's ``--project`` argv (``'-'`` = explicit
    bound-to-none; None = flag not given). Validation against the
    project registry happens at resolution (hard error, never a
    fallback)."""
    global _process_project, _process_project_set
    _process_project = value
    _process_project_set = value is not None


def get_process_project() -> str | None:
    return _process_project if _process_project_set else None


class ProjectArgvError(ValueError):
    """``--project`` revalidation failure — a hard error by contract
   : never a fallback to any ambient layer."""


def _project_exists(name: str) -> bool:
    try:
        from core.project.project import ProjectManager
        return ProjectManager().load(name) is not None
    except Exception:  # noqa: BLE001 — registry unreadable = not found
        logger.debug("pin: project existence check failed", exc_info=True)
        return False


def _validate_argv_project(value: str) -> None:
    from core.project.sessions import _NAME_RE
    if not _NAME_RE.match(value):
        msg = f"--project: invalid project name {value!r}"
        raise ProjectArgvError(msg)
    if not _project_exists(value):
        msg = f"--project: project {value!r} does not exist"
        raise ProjectArgvError(msg)


def resolve_pin_for_start() -> tuple[str | None, str]:
    """The (project, source) pair ``start_run`` records.

    Precedence: argv override > session binding > symlink > none.
    An invalid argv value raises :class:`ProjectArgvError` (hard
    error). A stale session binding (project deleted) resolves as
    authoritative none with a loud warning, never symlink fallthrough.
    """
    override = get_process_project()
    if override is not None:
        if override == ARGV_NONE:
            return None, "argv"
        _validate_argv_project(override)
        return override, "argv"

    from core.project.sessions import session_binding
    name, state = session_binding()
    if state == "bound":
        if name is not None and _project_exists(name):
            return name, "session"
        logger.warning(
            "pin: session binding names missing project %r — "
            "authoritatively projectless for this run", name)
        return None, "session"
    if state == "none":
        return None, "session"

    # advisory / absent → symlink layer (with the machine-expiry vet
    # applied by get_active itself).
    try:
        from core.project.project import ProjectManager
        active = ProjectManager().get_active()
    except Exception:  # noqa: BLE001 — resolution failure = standalone
        logger.debug("pin: symlink resolution failed", exc_info=True)
        active = None
    if active:
        return active, "symlink"
    return None, "none"


# ---------------------------------------------------------------------------
# in-run resolution
# ---------------------------------------------------------------------------

def _marker_trustworthy(directory: Path) -> bool:
    """A marker only counts when its directory is ours and not open to
    other writers — a world-writable ancestor (``/tmp``!) could carry a
    planted marker that captures privilege-bearing writes.

    Group-writable is accepted ONLY for our own primary group: on
    user-private-group systems (umask 002) every dir we create is
    0775 with a group containing just us — rejecting those would
    disable pinning wholesale. A shared group is a real second writer
    and stays rejected.
    """
    try:
        st = directory.stat()
    except OSError:
        return False
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        return False
    if st.st_mode & stat_mod.S_IWOTH:
        return False
    if st.st_mode & stat_mod.S_IWGRP and hasattr(os, "getgid") \
            and st.st_gid != os.getgid():
        return False
    return True


def _walk_boundary(directory: Path, start_dev: int | None) -> bool:
    """Should the walk stop AT (before examining) *directory*?"""
    try:
        if directory == Path.home() or directory == directory.parent:
            return True
    except OSError:
        return True
    if start_dev is not None:
        try:
            if directory.stat().st_dev != start_dev:
                return True  # filesystem boundary
        except OSError:
            return True
    return False


def _containment_project(start_dir: Path) -> str | None:
    """Legacy fallback: the project whose output dir contains
    *start_dir* — today's shape inference, reads only."""
    try:
        from core.project.project import ProjectManager
        resolved = start_dir.resolve()
        for project in ProjectManager().list_projects():
            try:
                out = Path(project.output_dir).resolve()
            except (OSError, ValueError):
                continue
            if out in resolved.parents or out == resolved:
                return project.name
    except Exception:  # noqa: BLE001 — registry unreadable = standalone
        logger.debug("pin: containment inference failed", exc_info=True)
    return None


def resolve_run_pin(start_dir: str | os.PathLike[str]) -> RunPin:
    """Resolve the project pin governing *start_dir* (state table in
    the module docstring). *start_dir* must be an explicit run-dir
    handle — an argument or config out_dir — NEVER the cwd."""
    try:
        current = Path(start_dir).resolve()
    except (OSError, ValueError):
        return RunPin(None, "unresolved", None, False, False)
    try:
        start_dev: int | None = current.stat().st_dev
    except OSError:
        start_dev = None

    probe = current
    for _ in range(_WALK_DEPTH):
        marker = probe / RUN_METADATA_FILE
        try:
            has_marker = marker.is_file()
        except OSError:
            has_marker = False
        if has_marker and _marker_trustworthy(probe):
            return _pin_from_marker(probe)
        if has_marker:
            logger.warning(
                "pin: ignoring untrustworthy run marker in %s "
                "(not owned by us, or group/world-writable)", probe)
        parent = probe.parent
        if parent == probe or _walk_boundary(parent, start_dev):
            break
        try:
            from core.project.project import is_project_output_dir
            if is_project_output_dir(parent):
                break  # never walk above a project output dir
        except Exception:  # noqa: BLE001 — boundary probe only
            pass
        probe = parent

    # No marker: legacy containment fallback — READS ONLY.
    name = _containment_project(current)
    return RunPin(name, "containment", None, False, False)


def _pin_from_marker(run_dir: Path) -> RunPin:
    from core.json import load_json
    meta = load_json(run_dir / RUN_METADATA_FILE)
    if not isinstance(meta, dict):
        return RunPin(None, "unresolved", run_dir, False, False)
    if "project" not in meta:
        # Legacy (pre-series) run dir: containment inference, reads only.
        name = _containment_project(run_dir)
        return RunPin(name, "containment", run_dir, False, False)
    project = meta.get("project")
    source = str(meta.get("project_source") or "none")
    if source not in PIN_SOURCES:
        source = "none"
    if project is None:
        return RunPin(None, source, run_dir, True, True)
    project = str(project)
    if not _project_exists(project):
        logger.warning(
            "pin: run %s is pinned to missing project %r — "
            "authoritatively projectless (was it deleted/renamed?)",
            run_dir, project)
        return RunPin(None, source, run_dir, True, True)
    return RunPin(project, source, run_dir, True, True)


def bootstrap_process_pin(out_dir: str | os.PathLike[str] | None) -> None:
    """Child-process pin bootstrap: a run's
    child process (scan/codeql/analysis workers spawned with an
    ``--out`` under the run dir) adopts the OWNING RUN's pin as its
    process-scoped project override, so every ambient consumer in the
    child — trust resolvers, IRIS store, exemplar pools, threat model,
    verified outcomes — follows the pin with zero per-site threading.

    Only AUTHORITATIVE pins bootstrap (a real ``project`` key in the
    owning run's metadata): the legacy containment fallback authorizes
    reads only, and promoting it to a process override would authorize
    privilege-bearing writes. An explicit ``--project`` argv set by the
    entry point always wins (never overwritten here).
    """
    if out_dir is None or get_process_project() is not None:
        return
    pin = resolve_run_pin(out_dir)
    if not pin.authoritative:
        return
    set_process_project(pin.project if pin.project is not None
                        else ARGV_NONE)
