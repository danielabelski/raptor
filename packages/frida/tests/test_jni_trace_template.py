"""Tests for the jni-trace template shape (pure JS; no slot rendering)."""

from __future__ import annotations

from pathlib import Path

from packages.frida.runner import list_templates, load_script_source

_TEMPLATE = (Path(__file__).resolve().parents[1]
             / "templates" / "jni-trace.js")


def test_template_is_listed():
    assert "jni-trace" in list_templates()


def test_template_loads_verbatim():
    source, origin = load_script_source("jni-trace", None)
    assert origin == "template:jni-trace"
    assert source == _TEMPLATE.read_text(encoding="utf-8")


def test_template_shape():
    text = _TEMPLATE.read_text(encoding="utf-8")
    # Hooks the real RegisterNatives, not the CheckJNI twin.
    assert "RegisterNatives" in text
    assert "CheckJNI" in text
    # Degrades loudly on non-ART targets instead of erroring.
    assert "not an ART/Android process" in text
    # Emits the fn-keyed shape the evidence consumers count.
    assert "'RegisterNatives'" in text
    # Bounded batch walk - a corrupt count argument must not spin.
    assert "MAX_METHODS_PER_BATCH" in text


def test_template_has_global_event_cap():
    # A hostile app looping RegisterNatives must not flood events.jsonl.
    text = _TEMPLATE.read_text(encoding="utf-8")
    assert "MAX_METHOD_EVENTS" in text
    assert "cap reached" in text


def test_template_hooks_every_instantiation():
    # Android 11+ ART compiles art::JNI<kEnableIndexIds> twice; hooking
    # only the first enumerated symbol can miss all registrations.
    text = _TEMPLATE.read_text(encoding="utf-8")
    assert "targets.forEach" in text
