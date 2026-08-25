"""The CLI-transport banner names the models config file state.

"No external LLM configured" is technically true even when a models
config file exists but yields nothing — a ``{"models": []}`` stub or
an unparseable file then reads as an intentional setup and the
misconfig goes undiagnosed. The banner must say what the file yielded
and where it lives, so the operator can fix the file instead of
assuming the CLI transport was chosen on purpose.
"""

from __future__ import annotations

import types

import pytest

import core.llm.client as client_mod
from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig


def _availability():
    return types.SimpleNamespace(
        external_llm=False, claude_code=True, llm_available=True,
    )


def _config():
    return LLMConfig(
        primary_model=ModelConfig(
            provider="claudecode", model_name="sonnet", api_key="",
        ),
        enable_caching=False,
        enable_fallback=False,
    )


def _capture_banner_lines(monkeypatch):
    """Collect rendered logger.info + logger.warning lines."""
    lines: list[str] = []

    def _sink(msg, *args, **kwargs):
        try:
            lines.append(str(msg) % args if args else str(msg))
        except (TypeError, ValueError):
            lines.append(str(msg))

    monkeypatch.setattr(client_mod.logger, "info", _sink)
    monkeypatch.setattr(client_mod.logger, "warning", _sink)
    return lines


@pytest.fixture()
def banner(monkeypatch):
    monkeypatch.setattr(client_mod, "_TRANSPORT_BANNER_SHOWN", False)
    monkeypatch.setattr(
        "core.llm.detection.detect_llm_availability",
        lambda: _availability(),
    )
    return _capture_banner_lines(monkeypatch)


def _construct_client_with_config(monkeypatch, tmp_path, text):
    cfg_file = tmp_path / "models.json"
    if text is not None:
        cfg_file.write_text(text)
    monkeypatch.setenv("RAPTOR_CONFIG", str(cfg_file))
    LLMClient(_config())
    return cfg_file


class TestBannerNamesConfigState:
    def test_empty_models_list_names_file_and_state(
        self, banner, monkeypatch, tmp_path,
    ):
        cfg_file = _construct_client_with_config(
            monkeypatch, tmp_path, '{"models": []}',
        )
        joined = [m for m in banner if "claude CLI" in m]
        assert joined, banner
        assert any(
            "lists no models" in m and str(cfg_file) in m for m in joined
        ), joined

    def test_unparseable_file_names_file_and_state(
        self, banner, monkeypatch, tmp_path,
    ):
        cfg_file = _construct_client_with_config(
            monkeypatch, tmp_path, "{not valid json",
        )
        joined = [m for m in banner if "claude CLI" in m]
        assert joined, banner
        assert any(
            "could not be parsed" in m and str(cfg_file) in m
            for m in joined
        ), joined

    def test_unusable_external_entries_named(
        self, banner, monkeypatch, tmp_path,
    ):
        cfg_file = _construct_client_with_config(
            monkeypatch, tmp_path,
            '{"models": [{"provider": "openai", "model": "gpt-5.4"}]}',
        )
        joined = [m for m in banner if "claude CLI" in m]
        assert joined, banner
        assert any(
            "none are usable" in m and str(cfg_file) in m for m in joined
        ), joined

    def test_absent_file_keeps_generic_wording(
        self, banner, monkeypatch, tmp_path,
    ):
        _construct_client_with_config(monkeypatch, tmp_path, None)
        joined = [m for m in banner if "claude CLI" in m]
        assert joined, banner
        assert any("No external LLM configured" in m for m in joined), joined

    def test_cli_only_config_keeps_generic_wording(
        self, banner, monkeypatch, tmp_path,
    ):
        # An explicit {"provider": "claudecode"} config declares the CLI
        # transport on purpose — no misconfig to warn about.
        _construct_client_with_config(
            monkeypatch, tmp_path,
            '{"models": [{"provider": "claudecode"}]}',
        )
        joined = [m for m in banner if "claude CLI" in m]
        assert joined, banner
        assert any("No external LLM configured" in m for m in joined), joined
        assert not any("lists no models" in m for m in joined), joined


class TestModelsConfigStatus:
    def _status(self, monkeypatch, tmp_path, text):
        from core.llm.detection import models_config_status
        cfg_file = tmp_path / "models.json"
        if text is not None:
            cfg_file.write_text(text)
        monkeypatch.setenv("RAPTOR_CONFIG", str(cfg_file))
        status, path = models_config_status()
        assert path == cfg_file
        return status

    def test_absent(self, monkeypatch, tmp_path):
        assert self._status(monkeypatch, tmp_path, None) == "absent"

    def test_empty_models_key(self, monkeypatch, tmp_path):
        assert self._status(
            monkeypatch, tmp_path, '{"models": []}') == "empty"

    def test_empty_bare_list(self, monkeypatch, tmp_path):
        assert self._status(monkeypatch, tmp_path, "[]") == "empty"

    def test_bad_json(self, monkeypatch, tmp_path):
        assert self._status(
            monkeypatch, tmp_path, "{oops") == "unparseable"

    def test_blank_file(self, monkeypatch, tmp_path):
        assert self._status(monkeypatch, tmp_path, "") == "unparseable"

    def test_models_key_not_a_list(self, monkeypatch, tmp_path):
        assert self._status(
            monkeypatch, tmp_path, '{"models": "nope"}') == "unparseable"

    def test_external_entry(self, monkeypatch, tmp_path):
        assert self._status(
            monkeypatch, tmp_path,
            '{"models": [{"provider": "gemini", "model": "gemini-2.5-pro"}]}',
        ) == "external"

    def test_claudecode_only(self, monkeypatch, tmp_path):
        assert self._status(
            monkeypatch, tmp_path,
            '{"models": [{"provider": "claudecode"}]}',
        ) == "cli_only"

    def test_cli_alias_spellings_count_as_cli(self, monkeypatch, tmp_path):
        # create_provider accepts these spellings as the CLI transport,
        # so a config listing them declares the CLI transport on purpose.
        assert self._status(
            monkeypatch, tmp_path,
            '{"models": [{"provider": "claude-code"},'
            ' {"provider": "claude_code"}]}',
        ) == "cli_only"

    def test_mixed_counts_as_external(self, monkeypatch, tmp_path):
        assert self._status(
            monkeypatch, tmp_path,
            '{"models": [{"provider": "claudecode"},'
            ' {"provider": "openai", "model": "gpt-5.4"}]}',
        ) == "external"

    def test_non_dict_entries_count_as_external(self, monkeypatch, tmp_path):
        # Bare-string entries route nowhere — they are a misconfig, not
        # a declared CLI-transport setup, so they must not classify as
        # cli_only (which would suppress the diagnostic banner).
        assert self._status(
            monkeypatch, tmp_path,
            '{"models": ["gpt-5.4", "gemini-2.5-pro"]}',
        ) == "external"

    def test_analysis_settings_file_is_other_schema(
        self, monkeypatch, tmp_path,
    ):
        # The config reader already logs a precise error for an
        # analysis-settings file at RAPTOR_CONFIG; the banner must not
        # pile a contradictory "could not be parsed" on top of it.
        assert self._status(
            monkeypatch, tmp_path,
            '{"checksec_path": "/usr/bin/checksec", "enable_caching": true}',
        ) == "other_schema"
