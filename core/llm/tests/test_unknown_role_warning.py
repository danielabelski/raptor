"""Unknown model roles in models.json surface loudly at config load.

A role value outside the valid set (e.g. ``"role": "primary"``) is a
trap wherever roles are consulted: Bedrock default-primary selection
skips the entry and multi-model role resolution rejects it — so a
config that *names* the operator's intent can silently produce the
opposite (the run falls through to the CLI transport with zero
diagnostics). Paths that ignore roles still pick the entry, so the
warning states that the role is never honoured rather than claiming
the entry is dead. The load chokepoint must warn once, naming the
entry, the offending role, and the valid set. Selection semantics
themselves do not change.
"""

from __future__ import annotations

import json

import pytest

import core.llm.detection as det
from core.llm.config import (
    VALID_ROLES,
    _config_bedrock_primary,
    _get_configured_models,
)


@pytest.fixture(autouse=True)
def _fresh_warn_state(monkeypatch):
    """Each test observes first-load behaviour of the once-guard."""
    monkeypatch.setattr(det, "_warned_unknown_roles", set(), raising=False)
    monkeypatch.setattr(
        "core.llm.model_resolution.resolve_anthropic",
        lambda name, api_key: name,
    )


def _capture_warnings(monkeypatch):
    lines: list[str] = []

    def _sink(msg, *args, **kwargs):
        try:
            lines.append(str(msg) % args if args else str(msg))
        except (TypeError, ValueError):
            lines.append(str(msg))

    monkeypatch.setattr(det.logger, "warning", _sink)
    return lines


def _write_config(tmp_path, monkeypatch, models):
    cfg_path = tmp_path / "models.json"
    cfg_path.write_text(json.dumps({"models": models}))
    monkeypatch.setenv("RAPTOR_CONFIG", str(cfg_path))
    return cfg_path


class TestUnknownRoleWarnsAtLoad:
    def test_unknown_role_warns_with_entry_role_and_valid_set(
        self, monkeypatch, tmp_path,
    ):
        _write_config(tmp_path, monkeypatch, [
            {"provider": "bedrock", "model": "anthropic.claude-opus-4-6",
             "role": "primary"},
        ])
        warnings = _capture_warnings(monkeypatch)

        _get_configured_models()

        role_warnings = [m for m in warnings if "'primary'" in m]
        assert role_warnings, warnings
        msg = role_warnings[0]
        assert "anthropic.claude-opus-4-6" in msg
        for valid in sorted(VALID_ROLES):
            assert valid in msg

    def test_default_primary_resolution_path_also_warns(
        self, monkeypatch, tmp_path,
    ):
        """A Bedrock entry with an unknown role is skipped by
        ``_config_bedrock_primary`` (behaviour pinned here, unchanged)
        — but the skip is no longer silent, because the resolution
        path reads the config through the warning chokepoint."""
        _write_config(tmp_path, monkeypatch, [
            {"provider": "bedrock", "model": "anthropic.claude-opus-4-6",
             "role": "primary"},
        ])
        warnings = _capture_warnings(monkeypatch)

        assert _config_bedrock_primary() is None
        assert any("'primary'" in m for m in warnings), warnings

    def test_warning_fires_once_per_entry_across_reads(
        self, monkeypatch, tmp_path,
    ):
        _write_config(tmp_path, monkeypatch, [
            {"provider": "openai", "model": "gpt-5.4", "role": "primarily"},
        ])
        warnings = _capture_warnings(monkeypatch)

        for _ in range(5):
            _get_configured_models()

        assert len([m for m in warnings if "'primarily'" in m]) == 1

    def test_distinct_bad_entries_each_warn(self, monkeypatch, tmp_path):
        _write_config(tmp_path, monkeypatch, [
            {"provider": "openai", "model": "gpt-5.4", "role": "primary"},
            {"provider": "gemini", "model": "gemini-2.5-pro", "role": "main"},
        ])
        warnings = _capture_warnings(monkeypatch)

        _get_configured_models()

        assert any("gpt-5.4" in m and "'primary'" in m for m in warnings)
        assert any(
            "gemini-2.5-pro" in m and "'main'" in m for m in warnings
        )

    def test_keyed_entry_with_unknown_role_still_resolves_and_warns(
        self, monkeypatch, tmp_path,
    ):
        """Role-ignoring resolution paths still pick the entry (pinned:
        the thinking-model scorer doesn't consult the role), so the
        warning must not claim the entry is dead — it says the role is
        never honoured. Both the pick and the warning happen."""
        import core.llm.config as cfg
        from core.llm.config import _get_default_primary_model

        _write_config(tmp_path, monkeypatch, [
            {"provider": "gemini", "model": "gemini-2.5-pro",
             "api_key": "test-key", "role": "primary"},
        ])
        warnings = _capture_warnings(monkeypatch)

        monkeypatch.setattr(cfg, "_thinking_model_checked", False)
        monkeypatch.setattr(cfg, "_cached_thinking_model", None)
        picked = _get_default_primary_model()

        assert picked is not None
        assert (picked.provider, picked.model_name) == (
            "gemini", "gemini-2.5-pro")
        role_warnings = [m for m in warnings if "'primary'" in m]
        assert role_warnings, warnings
        assert "never honoured" in role_warnings[0]

    def test_non_string_role_warns(self, monkeypatch, tmp_path):
        _write_config(tmp_path, monkeypatch, [
            {"provider": "openai", "model": "gpt-5.4", "role": 5},
        ])
        warnings = _capture_warnings(monkeypatch)

        _get_configured_models()

        assert any("gpt-5.4" in m for m in warnings), warnings


class TestKnownRolesStayQuiet:
    @pytest.mark.parametrize("role", sorted(VALID_ROLES))
    def test_valid_roles_do_not_warn(self, monkeypatch, tmp_path, role):
        _write_config(tmp_path, monkeypatch, [
            {"provider": "openai", "model": "gpt-5.4", "role": role},
        ])
        warnings = _capture_warnings(monkeypatch)

        _get_configured_models()

        assert warnings == []

    @pytest.mark.parametrize("role", ["thinking", "reasoning"])
    def test_scorer_hint_roles_do_not_warn(
        self, monkeypatch, tmp_path, role,
    ):
        # Recognised by the thinking-model scorer (they boost entry
        # scores), so they are configuration the code acts on — not
        # unknown values.
        _write_config(tmp_path, monkeypatch, [
            {"provider": "openai", "model": "gpt-5.4", "role": role},
        ])
        warnings = _capture_warnings(monkeypatch)

        _get_configured_models()

        assert warnings == []

    def test_omitted_and_empty_role_do_not_warn(
        self, monkeypatch, tmp_path,
    ):
        _write_config(tmp_path, monkeypatch, [
            {"provider": "openai", "model": "gpt-5.4"},
            {"provider": "gemini", "model": "gemini-2.5-pro", "role": ""},
            {"provider": "mistral", "model": "mistral-large-latest",
             "role": None},
        ])
        warnings = _capture_warnings(monkeypatch)

        _get_configured_models()

        assert warnings == []
