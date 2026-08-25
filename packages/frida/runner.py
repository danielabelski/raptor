"""Frida session runner.

Wraps the frida-python API into a single ``run()`` entry point:

  * Resolve the device (local / USB / remote frida-server).
  * Resolve the target (PID, name, bundle id, or binary path).
  * Spawn or attach.
  * Load the hook script (template or operator-supplied JS).
  * Capture ``send(...)`` messages into ``events.jsonl``.
  * Run for ``duration`` seconds, detach cleanly, write
    ``metadata.json`` + ``frida-report.md``.

The frida import is deferred so a) ``raptor doctor`` and the SKILL.md
remain usable on a host without frida-python installed and b) unit
tests can monkey-patch frida.* without import-time side effects.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TYPE_CHECKING

from core.json import append_jsonl, save_json

from .platform import HostInfo, detect_host

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

__all__ = [
    "FridaUnavailable",
    "RunConfig",
    "RunResult",
    "TargetSpec",
    "list_templates",
    "load_script_source",
    "parse_target",
    "resolve_template",
    "run",
]

TEMPLATES_DIR = Path(__file__).parent / "templates"


class FridaUnavailable(RuntimeError):
    """Raised when frida-python isn't installed.

    Kept as a distinct exception so callers (CLI, libexec wrapper)
    can give an actionable error rather than a bare ImportError.
    """


@dataclass
class TargetSpec:
    """Parsed target descriptor.

    ``raw`` is what the operator typed; ``pid``, ``name``, ``binary``
    are the resolved interpretations. Exactly one of pid/name/binary
    is set after :func:`parse_target`.
    """
    raw: str
    pid: int | None = None
    name: str | None = None         # process name OR bundle id
    binary: str | None = None       # filesystem path → spawn

    @property
    def kind(self) -> str:
        if self.pid is not None:
            return "pid"
        if self.binary is not None:
            return "binary"
        return "name"


def parse_target(raw: str) -> TargetSpec:
    """Classify a ``--target`` value.

    Order: numeric → PID; existing file → binary (spawn); else name
    (process name or bundle id, distinguished by frida at attach time).
    """
    raw = raw.strip()
    if not raw:
        msg = "empty target"
        raise ValueError(msg)
    if raw.isdigit():
        return TargetSpec(raw=raw, pid=int(raw))
    p = Path(raw)
    if p.exists() and p.is_file():
        return TargetSpec(raw=raw, binary=str(p.resolve()))
    return TargetSpec(raw=raw, name=raw)


@dataclass
class RunConfig:
    """Inputs to one :func:`run` invocation.

    All fields besides ``target`` and ``out_dir`` have sensible
    defaults; the CLI populates from argparse.
    """
    target: TargetSpec
    out_dir: Path
    script_source: str
    script_origin: str                  # "template:<name>" or "file:<path>"
    duration_sec: float = 60.0
    host: str | None = None          # frida-server host[:port]
    use_usb: bool = False
    spawn: bool = False
    unsafe_attach: bool = False         # informational; logged in metadata
    # Trace fork()/exec() children too (Frida child gating): each
    # gated child is attached, gets the same hook script, and is
    # resumed; its events land in the same events.jsonl. Without this
    # a fork()+exec pattern emits nothing (the session traces ONE
    # process), which downstream readers can misread as "the sink
    # never fired".
    follow_children: bool = False


@dataclass
class RunResult:
    """Outcome of a run. Populated incrementally; the JSON-serialisable
    fields are what gets written to ``metadata.json``.
    """
    ok: bool = False
    error: str | None = None
    events_captured: int = 0
    duration_actual_sec: float = 0.0
    resolved_pid: int | None = None
    device_id: str | None = None
    host_info: HostInfo | None = None
    children_observed: int = 0          # gated children instrumented


def resolve_template(name: str) -> Path:
    """Map a ``--template`` name to its on-disk JS file.

    Restricts to ``[a-zA-Z0-9_-]`` to defend against ``--template
    ../../../etc/passwd``. The eventual real path must live inside
    TEMPLATES_DIR; symlink-escape is rejected via ``.resolve()``
    comparison against the templates root.
    """
    if not name or not all(c.isalnum() or c in "-_" for c in name):
        msg = f"invalid template name: {name!r}"
        raise ValueError(msg)
    candidate = (TEMPLATES_DIR / f"{name}.js").resolve()
    root = TEMPLATES_DIR.resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        msg = f"template path escaped templates dir: {name!r}"
        raise ValueError(msg) from None
    if not candidate.is_file():
        msg = f"template not found: {name}"
        raise FileNotFoundError(msg)
    return candidate


def list_templates() -> list[str]:
    """Names of the bundled hook templates (sans .js)."""
    if not TEMPLATES_DIR.is_dir():
        return []
    return sorted(p.stem for p in TEMPLATES_DIR.glob("*.js"))


# Bundled-template slot markers → JSON payload producers. Marker-driven
# so any template can opt in; the slot syntax keeps an unrendered
# template valid JS (empty list) rather than a ReferenceError.
_PARSER_HOOKS_SLOT = "/*__PARSER_HOOKS__*/ []"
_INGEST_HOOKS_SLOT = "/*__INGEST_HOOKS__*/ []"
_EXEC_HOOKS_SLOT = "/*__EXEC_HOOKS__*/ []"
_SINK_WATCH_SLOT = "/*__SINK_WATCH__*/ []"


def _taxonomy_ingest_names() -> list[str]:
    from core.function_taxonomy import (
        NETWORK_INGEST_FUNCS,
        STREAM_INPUT_FUNCS,
    )

    return sorted(NETWORK_INGEST_FUNCS | STREAM_INPUT_FUNCS)


def _render_template_slots(source: str) -> str:
    """Fill generated-vocabulary slots in a bundled template.

    Hook-name lists are generated from the central function taxonomy
    (``core.function_taxonomy``) so the JS never carries a hand-copied
    mirror of it. Templates keep their per-function argument readers
    inline (arg-position knowledge, not name vocabulary) and skip
    rendered names they have no reader for.
    """
    if _PARSER_HOOKS_SLOT in source:
        from core.function_taxonomy import PARSER_FUNCS

        payload = json.dumps(sorted(PARSER_FUNCS))
        source = source.replace(_PARSER_HOOKS_SLOT, payload)
    if _INGEST_HOOKS_SLOT in source:
        source = source.replace(
            _INGEST_HOOKS_SLOT, json.dumps(_taxonomy_ingest_names()))
    if _EXEC_HOOKS_SLOT in source:
        from core.function_taxonomy import EXEC_FUNCS

        source = source.replace(
            _EXEC_HOOKS_SLOT, json.dumps(sorted(EXEC_FUNCS)))
    if _SINK_WATCH_SLOT in source:
        # Default sink vocabulary for plain `--template sink-watch`.
        # `--sink-watch <file>` renders a finding-specific list via
        # packages.frida.sink_watch instead.
        from core.function_taxonomy import (
            EXEC_FUNCS,
            FORMAT_STRING_FUNCS,
            MEMORY_COPY_FUNCS,
            STRING_OVERFLOW_FUNCS,
        )

        names = sorted(MEMORY_COPY_FUNCS | STRING_OVERFLOW_FUNCS
                       | FORMAT_STRING_FUNCS | EXEC_FUNCS)
        source = source.replace(
            _SINK_WATCH_SLOT, json.dumps([{"fn": n} for n in names]))
    return source


def load_script_source(template: str | None,
                      script_path: str | None) -> tuple[str, str]:
    """Return (source, origin_label). Exactly one input must be set.

    ``--template a+b`` combines bundled templates into one session:
    each is wrapped in an IIFE (templates share top-level names like
    ``hooks``; concatenating them raw is a redeclaration SyntaxError)
    and all hooks fire into the same events.jsonl. The combination
    that motivated this is ``seed-harvest+exec-and-load`` — one run
    capturing both ingest payloads and exec argv, which the
    io-correlation post-processor joins.
    """
    if bool(template) == bool(script_path):
        msg = "specify exactly one of --template or --script"
        raise ValueError(msg)
    if template:
        names = template.split("+")
        if (not names or any(not n for n in names)
                or len(set(names)) != len(names)):
            msg = (f"invalid template combination: {template!r} "
                   "(empty or duplicate member)")
            raise ValueError(msg)
        if len(names) == 1:
            path = resolve_template(names[0])
            source = _render_template_slots(
                path.read_text(encoding="utf-8"))
            return source, f"template:{names[0]}"
        parts = []
        for name in names:
            path = resolve_template(name)
            rendered = _render_template_slots(
                path.read_text(encoding="utf-8"))
            parts.append(
                f"// ─── combined template: {name} ───\n"
                f";(function () {{\n{rendered}\n}})();\n")
        return "\n".join(parts), f"template:{'+'.join(names)}"
    assert script_path is not None
    p = Path(script_path).resolve()
    if not p.is_file():
        msg = f"script not found: {script_path}"
        raise FileNotFoundError(msg)
    return p.read_text(encoding="utf-8"), f"file:{p}"


def _bounded_frida_call(fn, timeout_s: float, what: str) -> bool:
    """Run a blocking frida call with a hard time bound.

    frida-python's rpc/detach/load primitives park on events with NO
    timeout; a frida-core race can block them unboundedly, and any
    unbounded call sitting before the metadata write destroys the
    run's evidence (this arc has now hit that three separate ways).
    Returns True when the call completed in time. On timeout the
    daemon worker is abandoned and the caller must degrade — never
    wait.
    """
    done = threading.Event()

    def _worker() -> None:
        try:
            fn()
        except Exception:
            logger.debug("frida %s failed", what, exc_info=True)
        finally:
            done.set()

    threading.Thread(target=_worker, daemon=True,
                     name=f"frida-{what}").start()
    if not done.wait(timeout_s):
        logger.warning(
            "frida %s did not complete within %ss; continuing without "
            "it", what, timeout_s)
        return False
    return True


def _import_frida():
    """Late-bind frida-python with a useful error.

    Returning the module rather than importing at module-scope keeps
    this whole package importable on hosts without frida - important
    for `raptor doctor` and for unit tests that inject a fake.
    """
    try:
        import frida  # type: ignore[import-untyped, import-not-found]
        return frida
    except ImportError as e:
        msg = (
            "frida-python not installed. Install via: "
            "pipx install frida-tools  (or pip install --user frida-tools)"
        )
        raise FridaUnavailable(msg) from e


def _resolve_device(frida_mod: Any, cfg: RunConfig):
    """Pick the device per the CLI flags.

    Mutually exclusive with --usb / --host already enforced at parse
    time in cli.py; here we just translate to frida-API calls.
    """
    if cfg.host:
        return frida_mod.get_device_manager().add_remote_device(cfg.host)
    if cfg.use_usb:
        return frida_mod.get_usb_device(timeout=5)
    return frida_mod.get_local_device()


def _attach_or_spawn(_frida_mod: Any, device: Any, cfg: RunConfig
                     ) -> tuple[Any, int]:
    """Return (session, pid). Spawned processes start suspended;
    caller must ``device.resume(pid)`` after script load.
    """
    t = cfg.target
    if t.binary or cfg.spawn:
        # Spawn: argv0 = binary. No further args supported in v1 -
        # operator can wrap with a shell script if they need them.
        # env: the spawned process is TARGET code — subtract the
        # target-facing strip set (trust markers + session credential)
        # the frida DRIVER itself legitimately carries. frida's spawn
        # inherits the driver env unless told otherwise.
        binary = t.binary or t.raw
        child_env = dict(os.environ)
        try:
            from core.config import RaptorConfig as _RC
            for _k in _RC.TARGET_ENV_STRIP_SET:
                child_env.pop(_k, None)
        except Exception:  # noqa: BLE001 — strip set unavailable
            for _k in ("CLAUDECODE", "_RAPTOR_TRUSTED",
                       "RAPTOR_SESSION_PID", "RAPTOR_SESSION_TOKEN"):
                child_env.pop(_k, None)
        try:
            pid = device.spawn([binary], env=child_env)
        except TypeError:
            # Older frida bindings without the env kwarg.
            pid = device.spawn([binary])
        session = device.attach(pid)
        return session, pid
    if t.pid is not None:
        session = device.attach(t.pid)
        return session, t.pid
    # name or bundle id
    session = device.attach(t.name)
    # Pid resolution after attach: frida exposes session.pid only
    # since 16.x; fall back to None if absent for older bindings.
    return session, int(getattr(session, "pid", 0) or 0)


def run(cfg: RunConfig,
        on_event: Callable[[dict], None] | None = None,
        frida_mod_override: Any = None) -> RunResult:
    """Execute one Frida session.

    Side effects in ``cfg.out_dir``:
      * ``events.jsonl`` - one JSON object per ``send()`` from the script
      * ``script.js`` - copy of the script source (template or file)
      * ``metadata.json`` - run shape, host info, target, timings
      * ``frida-report.md`` - human-readable summary

    ``on_event`` is called for every message in addition to being
    serialised - used by tests to assert events without parsing the
    jsonl file.
    """
    cfg.out_dir.mkdir(parents=True, exist_ok=True)
    (cfg.out_dir / "script.js").write_text(cfg.script_source, encoding="utf-8")

    host_info = detect_host()
    result = RunResult(host_info=host_info)

    frida_mod = frida_mod_override or _import_frida()

    events_path = cfg.out_dir / "events.jsonl"
    # Create up-front so the file frida-report.md points to always
    # exists - even for a run that captures zero events or fails
    # before the first send().
    events_path.touch()
    events_lock = threading.Lock()
    event_count = {"n": 0}

    def _message_cb(message: dict, data: bytes | None) -> None:
        """Frida's on('message') callback. Both ``send()`` payloads
        (type='send') and uncaught script errors (type='error')
        flow through here. We persist both so a hook crashing
        mid-run leaves a trail.
        """
        record: dict[str, Any] = {
            "ts": time.time(),
            "type": message.get("type"),
        }
        if message.get("type") == "send":
            record["payload"] = message.get("payload")
        elif message.get("type") == "error":
            record["error"] = {
                "description": message.get("description"),
                "stack": message.get("stack"),
                "fileName": message.get("fileName"),
                "lineNumber": message.get("lineNumber"),
            }
        else:
            record["raw"] = message
        if data is not None:
            # Binary blobs (rare; emitted via send(payload, data) in JS)
            # are summarised, not embedded - JSONL stays line-grep-able.
            record["binary_len"] = len(data)
        with events_lock:
            append_jsonl(events_path, record)
            event_count["n"] += 1
            if data is not None:
                payload = message.get("payload")
                if isinstance(payload, dict) and payload.get("_drcov"):
                    (cfg.out_dir / "coverage.drcov").write_bytes(data)
        if on_event is not None:
            try:
                on_event(record)
            except Exception:  # never let a test callback break the run
                logger.debug("frida on_event callback raised", exc_info=True)

    started = time.monotonic()
    session = None
    device = None
    pid: int | None = None
    spawned = False
    child_sessions: list[Any] = []
    child_handler: Any = None

    try:
        device = _resolve_device(frida_mod, cfg)
        result.device_id = getattr(device, "id", None) or str(device)
        session, pid = _attach_or_spawn(frida_mod, device, cfg)
        spawned = bool(cfg.target.binary or cfg.spawn)
        result.resolved_pid = pid

        script = session.create_script(cfg.script_source)
        script.on("message", _message_cb)
        # Stalker-heavy templates have wedged load() on a suspended
        # spawn; a wedged load must fail the run, not hang it.
        if not _bounded_frida_call(script.load, 30.0, "script-load"):
            msg = "script load did not complete within 30s"
            raise RuntimeError(msg)

        if cfg.follow_children:
            def _instrument_child(child_pid: int) -> None:
                # The gated child arrives SUSPENDED. Instrument it,
                # then ALWAYS resume — a leaked suspension hangs the
                # target's own control flow.
                try:
                    child_session = device.attach(child_pid)
                    # Grandchildren gate too.
                    try:
                        child_session.enable_child_gating()
                    except Exception:
                        logger.debug("child gating on child failed",
                                     exc_info=True)
                    child_script = child_session.create_script(
                        cfg.script_source)
                    child_script.on("message", _message_cb)
                    child_script.load()
                    with events_lock:
                        child_sessions.append(child_session)
                        result.children_observed += 1
                except Exception:  # best-effort: never wedge the child
                    logger.debug("child instrumentation failed",
                                 exc_info=True)
                finally:
                    try:
                        device.resume(child_pid)
                    except Exception:
                        logger.debug("child resume failed", exc_info=True)

            def _on_child_added(child: Any) -> None:
                # The signal fires on frida's runtime event thread;
                # blocking device calls (attach) there DEADLOCK the
                # runtime. Instrument on a worker thread instead — the
                # child stays gated (suspended) until that thread
                # resumes it.
                threading.Thread(
                    target=_instrument_child,
                    args=(child.pid,),
                    name="frida-child-instrument",
                    daemon=True,
                ).start()

            # Handler BEFORE gating, gating BEFORE resume: a child
            # forked in the target's first instructions must find both
            # in place.
            device.on("child-added", _on_child_added)
            child_handler = _on_child_added
            session.enable_child_gating()

        # Controller-driven flushing: a script may export flush() to
        # emit batched evidence (call-edges does). Timers inside the
        # agent are NOT dependable — empirically setInterval/setTimeout
        # never fire on some frida 17 installs — so the controller is
        # the clock: flush right after resume (spawn-mode scripts load
        # while the process is suspended, so thread-following can only
        # start once the target exists), every ~2s during the run, and
        # once more before teardown while the session can still
        # deliver messages.
        script_has_flush = False
        lister = getattr(script, "list_exports_sync", None)
        if callable(lister):
            listed: list = []

            def _list_exports() -> None:
                listed.extend(lister() or [])

            if _bounded_frida_call(_list_exports, 5.0, "export-listing"):
                script_has_flush = "flush" in listed

        flush_state = {"wedged": False}

        def _script_flush() -> None:
            # One wedged flush disables the rest: each timed-out call
            # abandons a daemon worker, and piling those up helps
            # nobody. The evidence emitted so far is already on disk.
            if flush_state["wedged"]:
                return

            def _call() -> None:
                exports = getattr(script, "exports_sync", None)
                if exports is None:
                    exports = getattr(script, "exports", None)
                if exports is not None:
                    exports.flush()

            if not _bounded_frida_call(_call, 5.0, "script-flush"):
                flush_state["wedged"] = True

        # If we spawned, the process is suspended pre-load. Resume it
        # AFTER load so hooks are in place before main() runs.
        if spawned:
            device.resume(pid)
        if script_has_flush:
            _script_flush()

        # Sleep loop with SIGINT trap so Ctrl-C in the operator's shell
        # terminates the run cleanly rather than orphaning the script.
        stop = threading.Event()

        def _on_sigint(_signum, _frame) -> None:
            stop.set()

        try:
            prev_handler = signal.signal(signal.SIGINT, _on_sigint)
            signal_installed = True
        except ValueError:
            signal_installed = False
        try:
            deadline = started + cfg.duration_sec
            last_flush = time.monotonic()
            # Fast cadence for the first two seconds: the immediate
            # post-resume flush races the target's threads becoming
            # enumerable, and a spawn-mode target's interesting
            # activity often happens in its first second — the next
            # flush must not be 2s away.
            early_deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline and not stop.is_set():
                time.sleep(0.1)
                interval = (0.3 if time.monotonic() < early_deadline
                            else 2.0)
                if (script_has_flush
                        and time.monotonic() - last_flush >= interval):
                    _script_flush()
                    last_flush = time.monotonic()
            if script_has_flush:
                _script_flush()
        finally:
            if signal_installed:
                signal.signal(signal.SIGINT, prev_handler)

        result.ok = True
    except FridaUnavailable:
        raise
    except Exception as e:  # noqa: BLE001 — converted to result.error; report/metadata still written in finally
        result.ok = False
        result.error = f"{type(e).__name__}: {e}"
    finally:
        if child_handler is not None and device is not None:
            try:
                device.off("child-added", child_handler)
            except Exception:  # best-effort cleanup
                logger.debug("child-added handler removal failed",
                             exc_info=True)
        if child_sessions:
            # frida-python's detach has NO timeout, and a frida-core
            # race (children dying concurrently with detach) can block
            # it unboundedly — which would wedge the run AFTER a
            # successful capture and lose metadata.json (evidence
            # discovery discards runs without it). Bound the child
            # cleanup; frida's own teardown resumes/kills gated
            # children when the controller exits.
            with events_lock:
                sessions_snapshot = list(child_sessions)

            def _detach_children() -> None:
                for child_session in sessions_snapshot:
                    try:
                        child_session.detach()
                    except Exception:  # best-effort cleanup
                        logger.debug("child session detach failed",
                                     exc_info=True)

            detacher = threading.Thread(
                target=_detach_children,
                name="frida-child-detach", daemon=True)
            detacher.start()
            detacher.join(timeout=5.0)
            if detacher.is_alive():
                logger.warning(
                    "child session detach did not complete within 5s; "
                    "continuing teardown (frida cleans up gated "
                    "children when the controller exits)")
        if session is not None:
            _bounded_frida_call(session.detach, 10.0, "session-detach")
        # Kill the spawned process so it does not remain permanently
        # suspended when attach/create_script/load/resume failed.
        if spawned and device is not None and pid is not None:
            _bounded_frida_call(lambda: device.kill(pid), 5.0,
                                "spawned-process-kill")
        result.duration_actual_sec = round(time.monotonic() - started, 3)
        result.events_captured = event_count["n"]
        _write_metadata(cfg, result)
        _write_report(cfg, result)

    return result


def _write_metadata(cfg: RunConfig, result: RunResult) -> None:
    payload = {
        "ok": result.ok,
        "error": result.error,
        "target": {
            "raw": cfg.target.raw,
            "kind": cfg.target.kind,
            "pid": cfg.target.pid,
            "name": cfg.target.name,
            "binary": cfg.target.binary,
        },
        "script_origin": cfg.script_origin,
        "duration_requested_sec": cfg.duration_sec,
        "duration_actual_sec": result.duration_actual_sec,
        "events_captured": result.events_captured,
        "device": {
            "id": result.device_id,
            "host": cfg.host,
            "usb": cfg.use_usb,
        },
        "host": {
            "system": result.host_info.system if result.host_info else None,
            "arch": result.host_info.arch if result.host_info else None,
            "frida_version": (result.host_info.frida_version
                              if result.host_info else None),
            "frida_bin": (result.host_info.frida_bin
                          if result.host_info else None),
            "sip_status": (result.host_info.sip_status
                           if result.host_info else None),
            "ptrace_scope": (result.host_info.ptrace_scope
                             if result.host_info else None),
        },
        "spawn": cfg.spawn or bool(cfg.target.binary),
        "unsafe_attach": cfg.unsafe_attach,
        "follow_children": cfg.follow_children,
        "children_observed": result.children_observed,
        "resolved_pid": result.resolved_pid,
    }
    save_json(cfg.out_dir / "metadata.json", payload)


def _write_report(cfg: RunConfig, result: RunResult) -> None:
    lines: list[str] = []
    lines.append("# RAPTOR Frida Run")
    lines.append("")
    # Title Case per the output style rule (never ALL-CAPS statuses
    # in human-readable output).
    status = "Ok" if result.ok else "Failed"
    lines.append(f"**Status:** {status}")
    if result.error:
        lines.append(f"**Error:** `{result.error}`")
    lines.append(f"**Target:** `{cfg.target.raw}` ({cfg.target.kind})")
    if result.resolved_pid:
        lines.append(f"**PID:** {result.resolved_pid}")
    lines.append(f"**Script:** `{cfg.script_origin}`")
    lines.append(f"**Events captured:** {result.events_captured}")
    lines.append(
        f"**Duration:** {result.duration_actual_sec:.2f}s "
        f"(requested {cfg.duration_sec:.0f}s)"
    )
    if cfg.host:
        lines.append(f"**Remote frida-server:** `{cfg.host}`")
    if cfg.use_usb:
        lines.append("**Device:** USB")
    if cfg.unsafe_attach:
        lines.append("**Mode:** `--unsafe-attach` (sandbox bypass)")
    lines.append("")
    lines.append("Raw events: see `events.jsonl`. Run metadata: see "
                 "`metadata.json`. Script as executed: see `script.js`.")
    (cfg.out_dir / "frida-report.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8")


