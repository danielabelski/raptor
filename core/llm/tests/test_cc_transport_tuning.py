"""Tests for claudecode transport tuning: model pinning, worker
derivation, dispatch knobs, and retry classification of surfaced
abort causes."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in (
        "RAPTOR_CC_MODEL",
        "RAPTOR_CC_PIN_MODEL",
        "RAPTOR_CC_MAX_WORKERS",
        "RAPTOR_CC_EFFORT",
        "RAPTOR_CC_FALLBACK_MODEL",
    ):
        monkeypatch.delenv(var, raising=False)


class TestResolveClaudecodeModel:
    def test_env_override_wins(self, monkeypatch):
        from core.llm import config as cfg

        monkeypatch.setenv("RAPTOR_CC_MODEL", "operator-choice")
        monkeypatch.setattr(
            "core.llm.cc_probe.cached_cc_session_model",
            lambda: "probed-model",
        )
        assert cfg._resolve_claudecode_model() == "operator-choice"

    def test_cached_probe_pins(self, monkeypatch):
        from core.llm import config as cfg

        monkeypatch.setattr(
            "core.llm.cc_probe.cached_cc_session_model",
            lambda: "backend.resolved-id",
        )
        assert cfg._resolve_claudecode_model() == "backend.resolved-id"

    def test_pin_opt_out_returns_sentinel(self, monkeypatch):
        from core.llm import config as cfg

        monkeypatch.setenv("RAPTOR_CC_PIN_MODEL", "0")
        monkeypatch.setattr(
            "core.llm.cc_probe.cached_cc_session_model",
            lambda: "backend.resolved-id",
        )
        assert (
            cfg._resolve_claudecode_model() == cfg.CLAUDECODE_SESSION_MODEL
        )

    def test_cold_cache_returns_sentinel(self, monkeypatch):
        from core.llm import config as cfg

        monkeypatch.setattr(
            "core.llm.cc_probe.cached_cc_session_model", lambda: None,
        )
        assert (
            cfg._resolve_claudecode_model() == cfg.CLAUDECODE_SESSION_MODEL
        )

    def test_provider_omits_model_flag_only_for_sentinel(self):
        from core.llm.config import CLAUDECODE_SESSION_MODEL, ModelConfig
        from core.llm.providers import ClaudeCodeLLMProvider

        sentinel = ClaudeCodeLLMProvider(ModelConfig(
            provider="claudecode",
            model_name=CLAUDECODE_SESSION_MODEL,
            api_key=None, timeout=30,
        ))
        assert sentinel._cli_model() is None

        pinned = ClaudeCodeLLMProvider(ModelConfig(
            provider="claudecode",
            model_name="backend.resolved-id",
            api_key=None, timeout=30,
        ))
        assert pinned._cli_model() == "backend.resolved-id"
