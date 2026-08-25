"""Tests for the exec-and-load template: slot rendering from the
central taxonomy and the self-contained shape of the unrendered JS."""

from __future__ import annotations

from pathlib import Path

from packages.frida.runner import list_templates, load_script_source

_TEMPLATE = (Path(__file__).resolve().parents[1]
             / "templates" / "exec-and-load.js")


def test_template_is_listed():
    assert "exec-and-load" in list_templates()


def test_template_renders_exec_taxonomy_slot():
    source, origin = load_script_source("exec-and-load", None)
    assert origin == "template:exec-and-load"
    assert "/*__EXEC_HOOKS__*/ []" not in source
    # Taxonomy vocabulary must reach the JS.
    assert '"system"' in source
    assert '"execve"' in source
    assert '"posix_spawn"' in source


def test_unrendered_template_is_valid_and_hooks_loader_locally():
    text = _TEMPLATE.read_text(encoding="utf-8")
    # Unrendered slot stays valid JS (empty list).
    assert "/*__EXEC_HOOKS__*/ []" in text
    # Loader entry points are template-local, not taxonomy-rendered.
    assert "'dlopen'" in text
    assert "'dlmopen'" in text


def test_readers_capture_on_enter():
    # execve does not return on success; an onLeave-only emit would
    # miss it. The template must send from onEnter.
    text = _TEMPLATE.read_text(encoding="utf-8")
    assert "onEnter: function" in text
    assert "onLeave: function" not in text


def test_template_has_event_cap():
    # A hostile target looping dlopen()/system() must not flood
    # events.jsonl for the whole session; caps are loud, never silent.
    text = _TEMPLATE.read_text(encoding="utf-8")
    assert "MAX_EVENTS_PER_FN" in text
    assert "cap reached" in text
    assert "Object.create(null)" in text
