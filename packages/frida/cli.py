"""CLI entry point for ``raptor frida``.

Invoked as ``python3 -m packages.frida.cli`` from the libexec
wrapper (which also handles the run-lifecycle output directory). The
``--out`` flag is injected by the lifecycle layer, so this module
treats it as a required input rather than constructing one itself.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .runner import (
    RunConfig,
    list_templates,
    load_script_source,
    parse_target,
    run,
    FridaUnavailable,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="raptor frida",
        description=("Dynamic instrumentation via Frida. Attach to or spawn "
                     "a target, load a hook script, capture events."),
    )
    parser.add_argument("--target", required=True,
                        help="PID (digits), process name, bundle id, "
                             "or path to a binary to spawn.")
    parser.add_argument("--out", required=True,
                        help="Lifecycle-managed output directory "
                             "(injected by libexec/raptor-frida).")

    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--template", metavar="NAME",
                     help=("Bundled hook template name. Use --list-templates "
                           "to see options."))
    src.add_argument("--script", metavar="PATH",
                     help="Path to an operator-supplied JS hook file.")
    src.add_argument("--sink-watch", metavar="FILE",
                     help=("Watch a finding-specific sink list: a sinks "
                           "JSON (names or {fn, module} objects) or a "
                           "validation run's attack-paths.json."))

    dev = parser.add_mutually_exclusive_group()
    dev.add_argument("--host", metavar="HOST[:PORT]",
                     help=("Connect to a remote frida-server. Default "
                           "port 27042 if not specified."))
    dev.add_argument("--usb", action="store_true",
                     help="Connect to the first USB-attached device.")

    parser.add_argument("--duration", type=float, default=60.0,
                        help="Seconds to run before detaching. Default 60.")
    parser.add_argument("--spawn", action="store_true",
                        help=("Force spawn-and-attach. Implied when --target "
                              "is an existing file path."))
    parser.add_argument("--unsafe-attach", action="store_true",
                        help=("Required for templates / attach modes needing "
                              "PTRACE_ATTACH or task_for_pid. Logged in "
                              "metadata."))
    parser.add_argument("--follow-children", action="store_true",
                        help=("Trace fork()/exec() children too (Frida "
                              "child gating): each child gets the same "
                              "hook script; events land in the same "
                              "events.jsonl."))
    parser.add_argument("--list-templates", action="store_true",
                        help="Print bundled template names and exit.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    # --list-templates is a query mode; skip the required flags by
    # short-circuiting before parse_args's required-arg check.
    if argv is None:
        argv = sys.argv[1:]
    if "--list-templates" in argv:
        for name in list_templates():
            print(name)
        return 0

    args = parser.parse_args(argv)

    try:
        target = parse_target(args.target)
    except ValueError as e:
        print(f"frida: invalid --target: {e}", file=sys.stderr)
        return 2

    # A PID identifies an already-running process; you cannot spawn it.
    # Without this guard the runner would fall into the spawn branch and
    # try to launch a program literally named after the PID - a confusing
    # failure. Reject it up front instead.
    if target.kind == "pid" and args.spawn:
        print("frida: --spawn is incompatible with a PID target "
              "(a PID is already running; pass a binary path or name to "
              "spawn).", file=sys.stderr)
        return 2

    try:
        if args.sink_watch:
            from json import JSONDecodeError

            from .sink_watch import render_sink_watch, specs_from_file

            try:
                source = render_sink_watch(specs_from_file(args.sink_watch))
            except (OSError, JSONDecodeError) as e:
                msg = f"unreadable --sink-watch file: {e}"
                raise ValueError(msg) from e
            origin = f"sink-watch:{Path(args.sink_watch).resolve()}"
        else:
            source, origin = load_script_source(args.template, args.script)
    except (FileNotFoundError, ValueError) as e:
        print(f"frida: {e}", file=sys.stderr)
        return 2

    cfg = RunConfig(
        target=target,
        out_dir=Path(args.out),
        script_source=source,
        script_origin=origin,
        duration_sec=args.duration,
        host=args.host,
        use_usb=args.usb,
        spawn=args.spawn,
        unsafe_attach=args.unsafe_attach,
        follow_children=args.follow_children,
    )

    try:
        result = run(cfg)
    except FridaUnavailable as e:
        print(f"frida: {e}", file=sys.stderr)
        return 3

    if not result.ok:
        # Detail already in metadata.json + frida-report.md; the CLI
        # prints a one-liner so a caller wrapping us in a shell knows
        # what happened without parsing JSON.
        print(f"frida: run failed: {result.error}", file=sys.stderr)
        return 1

    print(f"frida: ok - {result.events_captured} events captured in "
          f"{result.duration_actual_sec:.1f}s → {args.out}")
    _maybe_harvest_seeds(Path(args.out))
    return 0


def _maybe_harvest_seeds(out_dir: Path) -> None:
    """Distill data-carrying events into a seed corpus after a run.

    Any template or operator script that emits ``args.data_hex``
    payloads (seed-harvest ships this convention) gets its unique
    buffers written as individual seed files. Additive: a harvest
    failure never fails a completed run.
    """
    try:
        from .seeds import extract_seeds

        manifest = extract_seeds(out_dir)
    except Exception as e:  # noqa: BLE001 — harvest is additive
        print(f"frida: seed harvest skipped: {e}", file=sys.stderr)
        return
    if manifest["seed_count"]:
        print(f"frida: {manifest['seed_count']} unique seeds harvested → "
              f"{manifest['out_dir']}")
        print("frida: fuzz them with: raptor fuzz --binary <target> "
              f"--corpus {manifest['out_dir']}")
        print("frida: note: seeds are raw bytes the target received "
              "(may include secrets) — review before sharing")


if __name__ == "__main__":
    raise SystemExit(main())
