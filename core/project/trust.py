"""Consumption of per-project trust markers by run entry points.

Mirrors the persisted-binaries loading path
(``core.analysis.binary_oracle_cli._project_binaries``): at /agentic
and /codeql start the active project's trust markers are loaded and
resolved against the per-run flags.

Resolution (per marker, both directions):

    explicit negative flag  >  explicit positive flag
                            >  project marker  >  default (off)

SECURITY:
- Markers are operator assertions persisted in the project JSON under
  the RAPTOR projects dir (``~/.raptor/projects``) — NEVER read from
  anywhere inside the scanned repo, NEVER auto-set from detection
  heuristics.
- A marker may only loosen gates the corresponding per-run flag can
  already loosen — this module introduces no new authority:
    config  → the ``--trust-repo`` umbrella (cc_trust + codeql_trust)
    build   → ``--traced-build`` C/C++ CodeQL extraction
    dynamic → ``config.dynamic_validation`` (Frida / target execution)
- ``build`` does NOT imply ``config`` — the markers are resolved
  independently, matching the per-run-flag independence pinned by
  ``TestTracedBuildTrustIndependence``.
- Trust state must never be invisible: when a marker affects a run,
  a single banner line is printed at start.
"""

from __future__ import annotations

from core.project.project import VALID_TRUST_MARKERS


def active_project_trust() -> tuple[dict[str, str], str | None]:
    """Load the active project's trust markers. Returns
    ``(markers, project_name)``. Best-effort — a missing project or
    schema mismatch returns ``({}, None)`` rather than crashing the
    run (mirrors ``binary_oracle_cli._project_binaries``)."""
    try:
        from core.project.project import ProjectManager
        mgr = ProjectManager()
        active = mgr.get_active()
        if not active:
            return {}, None
        proj = mgr.load(active)
        if not proj:
            return {}, active
        raw = getattr(proj, "trust", None) or {}
        markers = {
            m: str(ts) for m, ts in raw.items()
            if m in VALID_TRUST_MARKERS and isinstance(ts, str) and ts
        }
        return markers, active
    except Exception:  # noqa: BLE001 — trust loading must never break a run
        return {}, None


def resolve_trust_flag(
    negative: bool, positive: bool, marker_set: bool, default: bool = False,
) -> bool:
    """Single-marker precedence: explicit negative > explicit positive
    > project marker > default(off)."""
    if negative:
        return False
    if positive:
        return True
    if marker_set:
        return True
    return default


def emit_trust_banner(affecting: list[str]) -> None:
    """One line at run start whenever a project marker changed the
    run's behaviour. Trust state must never be invisible."""
    if affecting:
        print(f"[*] project trust: {', '.join(affecting)} "
              f"(per-run flags override)")


def apply_project_trust_flags(args, *, banner: bool = True) -> list[str]:
    """Resolve the ``config`` and ``build`` markers into
    ``args.trust_repo`` / ``args.traced_build`` for the /agentic and
    /codeql entry points.

    Mutates ``args`` in place to the *effective* values so downstream
    consumers (the ``set_trust_override`` block, the ``--traced-build``
    forwarding) stay unchanged. Returns the list of markers that
    actually affected this run (marker present AND no explicit per-run
    flag in either direction).

    ``dynamic`` is deliberately NOT handled here — it is consumed where
    ``config.dynamic_validation`` is built (see
    :func:`resolve_dynamic_validation`).
    """
    markers, _name = active_project_trust()
    affecting: list[str] = []

    neg_trust = bool(getattr(args, "no_trust_repo", False))
    pos_trust = bool(getattr(args, "trust_repo", False))
    if hasattr(args, "trust_repo"):
        args.trust_repo = resolve_trust_flag(
            neg_trust, pos_trust, "config" in markers)
        if "config" in markers and not neg_trust and not pos_trust:
            affecting.append("config")

    neg_build = bool(getattr(args, "no_traced_build", False))
    pos_build = bool(getattr(args, "traced_build", False))
    if hasattr(args, "traced_build"):
        args.traced_build = resolve_trust_flag(
            neg_build, pos_build, "build" in markers)
        if "build" in markers and not neg_build and not pos_build:
            affecting.append("build")

    if banner:
        emit_trust_banner(affecting)
    return affecting


def resolve_dynamic_validation(
    explicit: bool | None, *, banner: bool = True,
) -> bool:
    """Resolve ``config.dynamic_validation`` for /audit-/validate-side
    consumers: explicit per-run choice (True/False from ``--dynamic`` /
    ``--no-dynamic``) wins; else the project's ``dynamic`` marker; else
    off."""
    if explicit is not None:
        return bool(explicit)
    markers, _name = active_project_trust()
    if "dynamic" in markers:
        if banner:
            emit_trust_banner(["dynamic"])
        return True
    return False


__all__ = [
    "active_project_trust",
    "apply_project_trust_flags",
    "emit_trust_banner",
    "resolve_dynamic_validation",
    "resolve_trust_flag",
]
