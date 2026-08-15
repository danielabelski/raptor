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


class TestClaudecodeWorkerCap:
    def _mock_primary(self, monkeypatch, provider, model_name):
        class _MC:
            pass
        mc = _MC()
        mc.provider = provider
        mc.model_name = model_name
        monkeypatch.setattr(
            "core.llm.config._get_default_primary_model",
            lambda prefer=None: mc,
        )

    def test_claudecode_primary_clamped(self, monkeypatch):
        from core.llm.concurrency import (
            CC_MAX_WORKERS_DEFAULT,
            derive_max_workers,
        )

        self._mock_primary(
            monkeypatch, "claudecode", "anthropic.claude-mythos-5",
        )
        monkeypatch.setattr(
            "core.llm.concurrency.read_tuning_max_llm_workers",
            lambda: None,
        )
        assert (
            derive_max_workers("anthropic.claude-mythos-5")
            == CC_MAX_WORKERS_DEFAULT
        )

    def test_env_override_raises_cap(self, monkeypatch):
        from core.llm.concurrency import derive_max_workers

        self._mock_primary(
            monkeypatch, "claudecode", "anthropic.claude-mythos-5",
        )
        monkeypatch.setattr(
            "core.llm.concurrency.read_tuning_max_llm_workers",
            lambda: None,
        )
        monkeypatch.setenv("RAPTOR_CC_MAX_WORKERS", "8")
        assert derive_max_workers("anthropic.claude-mythos-5") == 8

    def test_non_claudecode_primary_uncapped(self, monkeypatch):
        from core.llm.concurrency import derive_max_workers

        self._mock_primary(monkeypatch, "anthropic", "claude-opus-5")
        monkeypatch.setattr(
            "core.llm.concurrency.read_tuning_max_llm_workers",
            lambda: None,
        )
        assert derive_max_workers("claude-opus-5") > 4

    def test_tuning_override_beats_cc_cap(self, monkeypatch):
        from core.llm.concurrency import derive_max_workers

        self._mock_primary(
            monkeypatch, "claudecode", "anthropic.claude-mythos-5",
        )
        monkeypatch.setattr(
            "core.llm.concurrency.read_tuning_max_llm_workers",
            lambda: 12,
        )
        assert derive_max_workers("anthropic.claude-mythos-5") == 12


class TestDispatchKnobs:
    def _cmd(self):
        from core.llm.cc_adapter import CCDispatchConfig, build_cc_command
        return build_cc_command(CCDispatchConfig(claude_bin="claude"))

    def test_exclude_dynamic_sections_default_on(self):
        assert "--exclude-dynamic-system-prompt-sections" in self._cmd()

    def test_exclude_dynamic_sections_can_be_disabled(self):
        from core.llm.cc_adapter import CCDispatchConfig, build_cc_command
        cmd = build_cc_command(CCDispatchConfig(
            claude_bin="claude", exclude_dynamic_sections=False,
        ))
        assert "--exclude-dynamic-system-prompt-sections" not in cmd

    def test_effort_env_knob(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_CC_EFFORT", "low")
        cmd = self._cmd()
        idx = cmd.index("--effort")
        assert cmd[idx + 1] == "low"

    def test_invalid_effort_dropped(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_CC_EFFORT", "turbo")
        assert "--effort" not in self._cmd()

    def test_fallback_model_env_knob(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_CC_FALLBACK_MODEL", "backup-model")
        cmd = self._cmd()
        idx = cmd.index("--fallback-model")
        assert cmd[idx + 1] == "backup-model"

    def test_knobs_absent_by_default(self):
        cmd = self._cmd()
        assert "--effort" not in cmd
        assert "--fallback-model" not in cmd


class TestSurfacedCauseRetryClassification:
    """The stream-json abort causes surfaced on nonzero exit classify
    correctly: budget aborts never retry (same cost every time),
    transient transport failures do."""

    def test_budget_abort_not_retryable(self):
        from core.llm.client import _is_retryable_error

        err = RuntimeError("claude -p exited 1: error_max_budget_usd")
        assert _is_retryable_error(err) is False

    def test_timeout_retryable(self):
        from core.llm.client import _is_retryable_error

        err = RuntimeError("claude -p timed out after 600s")
        assert _is_retryable_error(err) is True

    def test_connection_failure_retryable(self):
        from core.llm.client import _is_retryable_error

        err = RuntimeError(
            "claude -p exited 1: connection refused by upstream",
        )
        assert _is_retryable_error(err) is True
