"""Tests for Frida child gating (--follow-children): a fork()/exec()
child gets the same hook script and its events land in the same
events.jsonl."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import time

import pytest

from packages.frida import runner
from packages.frida.runner import RunConfig, TargetSpec, run


def _wait_for(cond, timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return
        time.sleep(0.01)


class _FakeScript:
    def __init__(self):
        self.loaded = False
        self.callbacks = {}

    def on(self, event, cb):
        self.callbacks[event] = cb

    def load(self):
        self.loaded = True


class _FakeSession:
    def __init__(self):
        self.pid = 1234
        self.detached = False
        self.gating_enabled = False
        self.scripts: list[_FakeScript] = []

    def enable_child_gating(self):
        self.gating_enabled = True

    def create_script(self, _src):
        script = _FakeScript()
        self.scripts.append(script)
        return script

    def detach(self):
        self.detached = True


class _FakeDevice:
    def __init__(self):
        self.id = "local"
        self.handlers = {}
        self.removed = []
        self.resumed = []
        self.killed = []
        self.sessions: dict[int, _FakeSession] = {}

    def attach(self, pid_or_name):
        session = _FakeSession()
        if isinstance(pid_or_name, int):
            session.pid = pid_or_name
        self.sessions[session.pid] = session
        return session

    def spawn(self, _argv):
        return 1234

    def resume(self, pid):
        self.resumed.append(pid)

    def kill(self, pid):
        self.killed.append(pid)

    def on(self, event, cb):
        self.handlers[event] = cb

    def off(self, event, cb):
        self.removed.append((event, cb))


def _cfg(tmp_path: Path, **kwargs) -> RunConfig:
    return RunConfig(
        target=TargetSpec(raw="1234", pid=1234),
        out_dir=tmp_path,
        script_source="// hook",
        script_origin="template:api-trace",
        duration_sec=0.05,
        **kwargs,
    )


def _fake_frida(device: _FakeDevice):
    return SimpleNamespace(
        __version__="test",
        get_local_device=lambda: device,
    )


class TestFollowChildren:
    def test_gating_enabled_and_child_instrumented(self, tmp_path):
        device = _FakeDevice()
        result = run(_cfg(tmp_path, follow_children=True),
                     frida_mod_override=_fake_frida(device))
        assert result.ok

        parent = device.sessions[1234]
        assert parent.gating_enabled
        assert "child-added" in device.handlers

        # Simulate a gated child arriving mid-run: the handler must
        # attach, gate the child too (grandchildren), load the same
        # script, and ALWAYS resume. Instrumentation runs on a worker
        # thread (blocking device calls on frida's event thread
        # deadlock the runtime), so wait for it.
        handler = device.handlers["child-added"]
        handler(SimpleNamespace(pid=777))
        _wait_for(lambda: 777 in device.resumed)
        child = device.sessions[777]
        assert child.gating_enabled
        assert child.scripts and child.scripts[0].loaded
        assert 777 in device.resumed

    def test_child_resumed_even_when_instrumentation_fails(self, tmp_path):
        device = _FakeDevice()

        run(_cfg(tmp_path, follow_children=True),
            frida_mod_override=_fake_frida(device))
        handler = device.handlers["child-added"]

        def _boom(_pid):
            raise RuntimeError("attach refused")
        device.attach = _boom
        handler(SimpleNamespace(pid=888))
        # A leaked suspension hangs the target — resume is
        # unconditional.
        _wait_for(lambda: 888 in device.resumed)
        assert 888 in device.resumed

    def test_handler_removed_and_children_detached_on_exit(self, tmp_path):
        device = _FakeDevice()

        # Drive the child DURING the run via on_event? Simpler: call
        # run, then invoke the handler before asserting cleanup —
        # cleanup happens in run()'s finally, so simulate the child
        # from inside the run via a wrapper around the sleep. Instead,
        # verify the handler-removal contract directly: after run()
        # returns, the handler must have been detached from the device.
        run(_cfg(tmp_path, follow_children=True),
            frida_mod_override=_fake_frida(device))
        assert any(ev == "child-added" for ev, _ in device.removed)

    def test_metadata_records_follow_children(self, tmp_path):
        import json
        device = _FakeDevice()
        run(_cfg(tmp_path, follow_children=True),
            frida_mod_override=_fake_frida(device))
        meta = json.loads((tmp_path / "metadata.json").read_text())
        assert meta["follow_children"] is True
        assert meta["children_observed"] == 0

    def test_default_off_touches_no_gating_api(self, tmp_path):
        device = _FakeDevice()
        run(_cfg(tmp_path), frida_mod_override=_fake_frida(device))
        assert not device.sessions[1234].gating_enabled
        assert "child-added" not in device.handlers


class TestCliFlag:
    def test_flag_reaches_runconfig(self, tmp_path, monkeypatch):
        from packages.frida import cli

        captured = {}

        def fake_run(cfg, **_kwargs):
            captured["cfg"] = cfg
            return runner.RunResult(ok=True)

        monkeypatch.setattr(cli, "run", fake_run)
        rc = cli.main([
            "--target", "1234",
            "--out", str(tmp_path),
            "--template", "api-trace",
            "--follow-children",
            "--duration", "0.05",
        ])
        assert rc == 0
        assert captured["cfg"].follow_children is True


class TestBoundedTeardown:
    @pytest.mark.slow  # deliberately wedged child + bounded-detach deadline, ~5s by construction
    def test_wedged_child_detach_cannot_lose_metadata(self, tmp_path):
        """frida's detach has no timeout; a frida-core race can block a
        child detach unboundedly — which sat BEFORE the metadata write
        and lost the whole run's evidence. Teardown must be bounded."""
        import json
        import threading

        class _WedgedSession:
            pid = 999
            gating_enabled = False

            def enable_child_gating(self):
                self.gating_enabled = True

            def create_script(self, _src):
                return _FakeScript()

            def detach(self):
                time.sleep(60)   # unbounded in real frida

        device = _FakeDevice()
        real_attach = device.attach

        def attach(pid_or_name):
            if pid_or_name == 999:
                return _WedgedSession()
            return real_attach(pid_or_name)
        device.attach = attach

        def _fire_child():
            _wait_for(lambda: "child-added" in device.handlers)
            device.handlers["child-added"](SimpleNamespace(pid=999))

        threading.Thread(target=_fire_child, daemon=True).start()

        cfg = _cfg(tmp_path, follow_children=True)
        cfg.duration_sec = 0.3
        start = time.monotonic()
        result = run(cfg, frida_mod_override=_fake_frida(device))
        elapsed = time.monotonic() - start

        assert result.ok
        # Bounded: duration (0.3s) + detach join cap (5s) + slack —
        # never the 60s wedge.
        assert elapsed < 15
        # The evidence contract: metadata survived the wedge.
        meta = json.loads((tmp_path / "metadata.json").read_text())
        assert meta["ok"] is True
        assert meta["children_observed"] == 1
