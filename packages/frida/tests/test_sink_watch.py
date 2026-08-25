"""Tests for finding-parameterized sink watching: spec parsing,
template rendering, CLI wiring, and the validation-bridge round trip."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from packages.frida import cli, runner
from packages.frida.runner import load_script_source
from packages.frida.sink_watch import (
    SinkSpec,
    render_sink_watch,
    specs_from_file,
)


class TestRenderSinkWatch:
    def test_renders_specs_into_slot(self):
        source = render_sink_watch([
            SinkSpec(fn="memcpy"),
            SinkSpec(fn="EVP_DecryptUpdate", module="libcrypto.so.3"),
        ])
        assert "/*__SINK_WATCH__*/ []" not in source
        assert '{"fn": "memcpy"}' in source
        assert '"module": "libcrypto.so.3"' in source

    def test_empty_specs_rejected(self):
        with pytest.raises(ValueError, match="no sinks"):
            render_sink_watch([])

    def test_garbage_symbol_rejected(self):
        with pytest.raises(ValueError, match="sink symbol"):
            render_sink_watch([SinkSpec(fn="mem'); Interceptor.detachAll(")])

    def test_garbage_module_rejected(self):
        with pytest.raises(ValueError, match="module name"):
            render_sink_watch([SinkSpec(fn="memcpy", module="../lib.so")])

    def test_cap_enforced(self):
        specs = [SinkSpec(fn=f"fn_{i}") for i in range(65)]
        with pytest.raises(ValueError, match="too many sinks"):
            render_sink_watch(specs)


class TestSpecsFromFile:
    def _write(self, tmp_path: Path, data) -> Path:
        p = tmp_path / "sinks.json"
        p.write_text(json.dumps(data), encoding="utf-8")
        return p

    def test_bare_names(self, tmp_path):
        p = self._write(tmp_path, ["memcpy", "system"])
        assert specs_from_file(p) == [
            SinkSpec(fn="memcpy"), SinkSpec(fn="system")]

    def test_objects_with_module_and_alias(self, tmp_path):
        p = self._write(tmp_path, [
            {"fn": "memcpy"},
            {"function": "SSL_write", "module": "libssl.so.3"},
            {"fn": "memcpy"},                     # duplicate
        ])
        assert specs_from_file(p) == [
            SinkSpec(fn="memcpy"),
            SinkSpec(fn="SSL_write", module="libssl.so.3"),
        ]

    def test_attack_paths_list_shape(self, tmp_path):
        p = self._write(tmp_path, [
            {"steps": [
                {"function": "parse_header"},
                {"action": "call memcpy(dst, src, n)"},
            ]},
        ])
        specs = specs_from_file(p)
        assert SinkSpec(fn="parse_header") in specs
        assert SinkSpec(fn="memcpy") in specs

    def test_attack_paths_wrapper_shape(self, tmp_path):
        p = self._write(tmp_path, {"paths": [
            {"steps": [{"name": "handle_request()"}]},
        ]})
        assert specs_from_file(p) == [SinkSpec(fn="handle_request")]

    def test_nothing_usable_raises(self, tmp_path):
        p = self._write(tmp_path, [{"note": "no functions here"}])
        with pytest.raises(ValueError, match="no usable sink entries"):
            specs_from_file(p)

    def test_unrecognised_shape_raises(self, tmp_path):
        p = self._write(tmp_path, {"weird": True})
        with pytest.raises(ValueError, match="unrecognised"):
            specs_from_file(p)


class TestDefaultTemplateRender:
    def test_plain_template_gets_taxonomy_vocabulary(self):
        source, origin = load_script_source("sink-watch", None)
        assert origin == "template:sink-watch"
        assert "/*__SINK_WATCH__*/ []" not in source
        # Representatives of each rendered sink family.
        assert '{"fn": "memcpy"}' in source
        assert '{"fn": "strcpy"}' in source
        assert '{"fn": "system"}' in source

    def test_unrendered_template_is_self_contained(self):
        tpl = (Path(__file__).resolve().parents[1]
               / "templates" / "sink-watch.js")
        text = tpl.read_text(encoding="utf-8")
        assert "/*__SINK_WATCH__*/ []" in text
        # Unresolved sinks must surface, not vanish.
        assert "unresolved" in text


class _FakeDevice:
    def __init__(self):
        self.id = "local"

    def attach(self, _target):
        return SimpleNamespace(
            pid=1234,
            create_script=lambda _src: SimpleNamespace(
                on=lambda _ev, _cb: None, load=lambda: None),
            detach=lambda: None,
        )


def _fake_frida():
    dev = _FakeDevice()
    return SimpleNamespace(
        __version__="test",
        get_local_device=lambda: dev,
    )


class TestCliSinkWatch:
    def test_mutually_exclusive_with_template(self, tmp_path):
        with pytest.raises(SystemExit) as exc:
            cli.main([
                "--target", "1",
                "--out", str(tmp_path),
                "--template", "sink-watch",
                "--sink-watch", str(tmp_path / "sinks.json"),
            ])
        assert exc.value.code == 2

    def test_missing_file_exits_2(self, tmp_path):
        rc = cli.main([
            "--target", "1234",
            "--out", str(tmp_path),
            "--sink-watch", str(tmp_path / "nonexistent.json"),
        ])
        assert rc == 2

    def test_happy_path_renders_specs(self, tmp_path, monkeypatch):
        sinks = tmp_path / "sinks.json"
        sinks.write_text(json.dumps(["memcpy"]), encoding="utf-8")
        monkeypatch.setattr(runner, "_import_frida", lambda: _fake_frida())
        out = tmp_path / "run"
        rc = cli.main([
            "--target", "1234",
            "--out", str(out),
            "--sink-watch", str(sinks),
            "--duration", "0.05",
        ])
        assert rc == 0
        script = (out / "script.js").read_text(encoding="utf-8")
        assert '{"fn": "memcpy"}' in script
        meta = json.loads((out / "metadata.json").read_text())
        assert meta["script_origin"].startswith("sink-watch:")


class TestValidationBridgeRoundTrip:
    def test_sink_events_feed_runtime_evidence(self, tmp_path):
        # A sink-watch run directory in the exact shape evidence
        # discovery expects...
        run_dir = tmp_path / "frida_run"
        run_dir.mkdir()
        (run_dir / "metadata.json").write_text(json.dumps({
            "ok": True,
            "target": {"raw": "./srv", "kind": "binary",
                       "binary": str(tmp_path / "srv")},
        }), encoding="utf-8")
        # caller_module = target basename: sink evidence is
        # target-attributed (library-internal calls don't count).
        event = {
            "ts": 1.0, "type": "send",
            "payload": {
                "category": "sink", "fn": "memcpy",
                "caller_module": "srv",
                "args": {"dst": "0x1", "src": "0x2", "n": 512},
                "tid": 7,
            },
        }
        (run_dir / "events.jsonl").write_text(
            json.dumps(event) + "\n", encoding="utf-8")

        # ...feeds Stage B's runtime-evidence map with no extra wiring.
        from core.orchestration.frida_validation_bridge import (
            collect_runtime_evidence,
        )
        evidence = collect_runtime_evidence([tmp_path])
        assert "memcpy" in evidence
        assert evidence["memcpy"].call_count == 1
        assert 512 in evidence["memcpy"].observed_args


class TestDerivationHardening:
    def test_cxx_qualified_names_accepted(self, tmp_path):
        # DebugSymbol.fromName resolves demangled C++ names on
        # symbol-bearing targets; the validator must not drop them.
        source = render_sink_watch([SinkSpec(fn="Parser::parse")])
        assert '{"fn": "Parser::parse"}' in source

    def test_cxx_steps_survive_derivation(self, tmp_path):
        p = tmp_path / "paths.json"
        p.write_text(json.dumps([
            {"steps": [{"function": "ns::Frobnicate"}]},
        ]), encoding="utf-8")
        assert specs_from_file(p) == [SinkSpec(fn="ns::Frobnicate")]

    def test_unhookable_step_names_logged_not_silent(self, tmp_path, caplog):
        import logging
        p = tmp_path / "paths.json"
        p.write_text(json.dumps([
            {"steps": [{"function": "operator<<"},
                       {"function": "memcpy"}]},
        ]), encoding="utf-8")
        with caplog.at_level(logging.WARNING,
                             logger="packages.frida.sink_watch"):
            specs = specs_from_file(p)
        assert specs == [SinkSpec(fn="memcpy")]
        assert any("operator<<" in r.message for r in caplog.records)

    def test_mixed_shape_file_routes_per_item(self, tmp_path):
        # One steps-less entry must not reclassify the whole file.
        p = tmp_path / "mixed.json"
        p.write_text(json.dumps([
            {"steps": [{"function": "memcpy"}]},
            {"fn": "system"},
        ]), encoding="utf-8")
        specs = specs_from_file(p)
        assert SinkSpec(fn="memcpy") in specs
        assert SinkSpec(fn="system") in specs

    def test_template_cap_is_prototype_safe(self):
        # A hostile repo can name a function 'constructor'/'__proto__';
        # plain-object counters inherit Object.prototype members and
        # the cap never trips. The counter map must be null-prototype
        # and the reader lookup hasOwnProperty-guarded.
        tpl = (Path(__file__).resolve().parents[1]
               / "templates" / "sink-watch.js")
        text = tpl.read_text(encoding="utf-8")
        assert "Object.create(null)" in text
        assert "hasOwnProperty" in text

    def test_prototype_names_render_fine(self):
        # Python-side rendering stays permissive (they ARE legal C
        # identifiers); the JS side carries the containment.
        source = render_sink_watch([SinkSpec(fn="constructor")])
        assert '{"fn": "constructor"}' in source


class TestShapeRouting:
    def _write(self, tmp_path: Path, data) -> Path:
        p = tmp_path / "f.json"
        p.write_text(json.dumps(data), encoding="utf-8")
        return p

    def test_empty_steps_item_still_contributes_fn(self, tmp_path):
        # LLM-written artifacts plausibly carry steps: [] plus a fn.
        p = self._write(tmp_path, [{"steps": [], "fn": "system"}])
        assert specs_from_file(p) == [SinkSpec(fn="system")]

    def test_mixed_over_cap_slice_is_logged(self, tmp_path, caplog):
        import logging
        data = [{"steps": [{"function": f"fn_{i}"} for i in range(60)]}]
        data += [{"fn": f"extra_{i}"} for i in range(10)]
        p = self._write(tmp_path, data)
        with caplog.at_level(logging.WARNING,
                             logger="packages.frida.sink_watch"):
            specs = specs_from_file(p)
        assert len(specs) == 64
        assert any("watching the first 64" in r.message
                   for r in caplog.records)


class TestTemplateAliasEmission:
    def test_alias_group_reaches_events_and_meta(self):
        tpl = (Path(__file__).resolve().parents[1]
               / "templates" / "sink-watch.js")
        text = tpl.read_text(encoding="utf-8")
        # One attach per shared address, every event carries the full
        # alias group so evidence credits all names.
        assert "record.aliases = group.aliases" in text
        assert "fallbacks" in text
        # Attach failures surface, never kill remaining hooks.
        assert "delete attached[addrKey]" in text


class TestTemplateResolutionVisibility:
    def test_self_alias_and_debug_symbol_accounting(self):
        text = (Path(__file__).resolve().parents[1]
                / "templates" / "sink-watch.js").read_text(encoding="utf-8")
        # Self-alias (same fn watched twice) never enters the alias
        # group — evidence would double-count it.
        assert "spec.fn !== existing.primary" in text
        # Debug-symbol resolutions are distinguishable from
        # export-resolved hooks in the loaded meta.
        assert "debug_symbols" in text
