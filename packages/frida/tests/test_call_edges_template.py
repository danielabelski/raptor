"""Tests for the call-edges template shape and the controller-driven
flush mechanism it depends on."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from packages.frida.runner import (
    RunConfig,
    TargetSpec,
    list_templates,
    load_script_source,
    run,
)

_TEMPLATE = (Path(__file__).resolve().parents[1]
             / "templates" / "call-edges.js")


class TestTemplateShape:
    def test_listed_and_loads(self):
        assert "call-edges" in list_templates()
        _source, origin = load_script_source("call-edges", None)
        assert origin == "template:call-edges"

    def test_no_agent_timer_reliance(self):
        # In-agent timers never fire on some frida installs — nothing
        # in this template may depend on them.
        text = _TEMPLATE.read_text(encoding="utf-8")
        assert "setInterval" not in text
        assert "setTimeout" not in text
        assert "rpc.exports" in text

    def test_agent_threads_never_followed(self):
        # Stalking frida's own JS thread stalls the whole agent.
        text = _TEMPLATE.read_text(encoding="utf-8")
        assert "isAgentThread" in text
        assert "getCurrentThreadId" in text

    def test_bounded_and_owned_only(self):
        text = _TEMPLATE.read_text(encoding="utf-8")
        assert "MAX_EDGE_KEYS" in text
        assert "MAX_EMITTED" in text
        # Only target-owned callees are emitted; foreign edges are
        # counted, never silently vanished.
        assert "skipped_foreign_or_unnamed" in text


class _FlushScript:
    def __init__(self):
        self.flush_calls = 0
        self.posted: list[dict] = []
        self.exports_sync = SimpleNamespace(
            flush=lambda: setattr(self, "flush_calls",
                                  self.flush_calls + 1))

    def on(self, _event, _cb):
        pass

    def load(self):
        pass

    def post(self, message):
        self.posted.append(message)

    def list_exports_sync(self):
        return ["flush", "dispose"]


class _Device:
    def __init__(self, script):
        self.id = "local"
        self._script = script

    def attach(self, _target):
        return SimpleNamespace(
            pid=1234,
            create_script=lambda _src: self._script,
            detach=lambda: None,
        )


class TestControllerFlush:
    def test_flush_exports_are_driven_by_the_runner(self, tmp_path):
        script = _FlushScript()
        device = _Device(script)
        fake = SimpleNamespace(__version__="t",
                               get_local_device=lambda: device)
        cfg = RunConfig(
            target=TargetSpec(raw="1234", pid=1234),
            out_dir=tmp_path,
            script_source="// hook",
            script_origin="template:call-edges",
            duration_sec=0.05,
        )
        result = run(cfg, frida_mod_override=fake)
        assert result.ok
        # At least the pre-teardown flush (no immediate post-resume
        # flush: an rpc racing the resume can wedge in delivery).
        assert script.flush_calls >= 1
        assert result.flushes_completed == script.flush_calls

    def test_flush_message_preferred_over_rpc(self, tmp_path):
        """A script handling the flush message gets fire-and-forget
        posts — the blocking rpc export is never called."""
        script = _FlushScript()
        device = _Device(script)
        fake = SimpleNamespace(__version__="t",
                               get_local_device=lambda: device)
        cfg = RunConfig(
            target=TargetSpec(raw="1234", pid=1234),
            out_dir=tmp_path,
            script_source="// hook\nrecv('raptor:flush', onFlushMsg);",
            script_origin="template:call-edges",
            duration_sec=0.05,
        )
        result = run(cfg, frida_mod_override=fake)
        assert result.ok
        assert script.flush_calls == 0
        assert len(script.posted) >= 1
        assert all(m["type"] == "raptor:flush" for m in script.posted)
        assert all("main_tid" in m for m in script.posted)

    def test_scripts_without_flush_are_untouched(self, tmp_path):
        # A script that declares no flush export must never get rpc
        # calls (the exports proxy would raise into the agent).
        calls = {"n": 0}

        class _Plain:
            exports_sync = SimpleNamespace(
                flush=lambda: calls.__setitem__("n", calls["n"] + 1))

            def on(self, _e, _c):
                pass

            def load(self):
                pass

            def list_exports_sync(self):
                return []

        device = _Device(_Plain())
        fake = SimpleNamespace(__version__="t",
                               get_local_device=lambda: device)
        cfg = RunConfig(
            target=TargetSpec(raw="1234", pid=1234),
            out_dir=tmp_path,
            script_source="// hook",
            script_origin="template:api-trace",
            duration_sec=0.05,
        )
        assert run(cfg, frida_mod_override=fake).ok
        assert calls["n"] == 0


class TestBoundedFridaCalls:
    def _cfg(self, tmp_path):
        return RunConfig(
            target=TargetSpec(raw="1234", pid=1234),
            out_dir=tmp_path,
            script_source="// hook",
            script_origin="template:call-edges",
            duration_sec=0.05,
        )

    def test_wedged_flush_cannot_lose_metadata(self, tmp_path):
        """frida rpc calls park on events with NO timeout; a wedged
        flush must be abandoned (and further flushes skipped), never
        allowed to hang the run past the metadata write."""
        import json
        import time

        calls = {"n": 0}

        def _wedge():
            calls["n"] += 1
            time.sleep(60)

        script = _FlushScript()
        script.exports_sync = SimpleNamespace(flush=_wedge)
        device = _Device(script)
        fake = SimpleNamespace(__version__="t",
                               get_local_device=lambda: device)
        cfg = self._cfg(tmp_path)
        cfg.duration_sec = 0.3
        start = time.monotonic()
        result = run(cfg, frida_mod_override=fake)
        elapsed = time.monotonic() - start
        assert result.ok
        # Bounded attempts (5s cap each), latched after two
        # consecutive wedges; the teardown flush always gets its shot
        # — never one 5s stall per cycle, never a 60s hang.
        assert calls["n"] <= 3
        assert elapsed < 20
        assert json.loads(
            (tmp_path / "metadata.json").read_text())["ok"] is True

    def test_wedged_load_fails_the_run_with_metadata(self, tmp_path):
        import json
        import time

        class _WedgedLoadScript:
            def on(self, _e, _c):
                pass

            def load(self):
                time.sleep(60)

        device = _Device(_WedgedLoadScript())
        fake = SimpleNamespace(__version__="t",
                               get_local_device=lambda: device)
        start = time.monotonic()
        result = run(self._cfg(tmp_path), frida_mod_override=fake)
        elapsed = time.monotonic() - start
        assert not result.ok
        assert "load" in (result.error or "")
        assert elapsed < 45
        # The evidence contract survives even a load wedge.
        assert json.loads(
            (tmp_path / "metadata.json").read_text())["ok"] is False
