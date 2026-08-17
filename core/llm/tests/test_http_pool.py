"""Tests for the pooled SDK HTTP transport (``core.llm.http_pool``).

httpx's default pool expires idle keepalive connections after 5
seconds — shorter than RAPTOR's typical inter-call gap, so every LLM
call re-established its connection (and, behind chained proxies, paid
CONNECT negotiation per hop). The factory pins a keepalive window
that outlives the gap and gives every SDK the same tunable pool.
"""

from __future__ import annotations

import sys
import types

import httpx
import pytest

from core.llm import http_pool

_KNOB_VARS = (
    "RAPTOR_HTTP_KEEPALIVE_S",
    "RAPTOR_HTTP_MAX_KEEPALIVE",
    "RAPTOR_HTTP_MAX_CONNECTIONS",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in _KNOB_VARS:
        monkeypatch.delenv(var, raising=False)


class TestPoolLimits:

    def test_defaults_outlive_inter_call_gap(self):
        limits = http_pool.pool_limits()
        # The whole point: idle keepalive must comfortably exceed
        # httpx's 5s default, which is shorter than the think-time
        # gap between RAPTOR LLM calls.
        assert limits.keepalive_expiry == 60.0
        assert limits.max_keepalive_connections == 20
        assert limits.max_connections == 100

    def test_env_overrides(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_HTTP_KEEPALIVE_S", "120")
        monkeypatch.setenv("RAPTOR_HTTP_MAX_KEEPALIVE", "8")
        monkeypatch.setenv("RAPTOR_HTTP_MAX_CONNECTIONS", "16")
        limits = http_pool.pool_limits()
        assert limits.keepalive_expiry == 120.0
        assert limits.max_keepalive_connections == 8
        assert limits.max_connections == 16

    @pytest.mark.parametrize("bad", ["", "abc", "0", "-5"])
    def test_invalid_env_falls_back(self, monkeypatch, bad):
        monkeypatch.setenv("RAPTOR_HTTP_KEEPALIVE_S", bad)
        limits = http_pool.pool_limits()
        assert limits.keepalive_expiry == 60.0


class TestSdkHttpClient:

    def test_returns_httpx_client_with_pool_limits(self):
        client = http_pool.sdk_http_client(30)
        try:
            assert isinstance(client, httpx.Client)
            assert client.timeout.read == 30.0
        finally:
            client.close()

    def test_trust_env_passthrough(self):
        trusted = http_pool.sdk_http_client(10)
        pinned = http_pool.sdk_http_client(10, trust_env=False)
        try:
            assert trusted.trust_env is True
            assert pinned.trust_env is False
        finally:
            trusted.close()
            pinned.close()


class TestProviderWiring:
    """The provider constructors must hand the SDK the pooled client
    on their env-direct (non-dispatcher) paths."""

    @pytest.fixture(autouse=True)
    def _no_dispatcher(self, monkeypatch):
        monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)

    def _spy_factory(self, monkeypatch):
        built = []
        real = http_pool.sdk_http_client

        def spy(timeout, **kwargs):
            client = real(timeout, **kwargs)
            built.append((timeout, kwargs, client))
            return client

        monkeypatch.setattr(http_pool, "sdk_http_client", spy)
        return built

    def test_anthropic_direct_uses_pooled_client(self, monkeypatch):
        anthropic_mod = pytest.importorskip("anthropic")
        del anthropic_mod
        from core.llm.config import ModelConfig
        from core.llm.providers import AnthropicProvider

        built = self._spy_factory(monkeypatch)
        provider = AnthropicProvider(ModelConfig(
            provider="anthropic", model_name="claude-test",
            api_key="k", timeout=33,
        ))
        assert len(built) == 1
        timeout, _, client = built[0]
        assert timeout == 33
        assert provider.client._client is client

    def test_openai_remote_keeps_trust_env(self, monkeypatch):
        pytest.importorskip("openai")
        from core.llm.config import ModelConfig
        from core.llm.providers import OpenAICompatibleProvider

        built = self._spy_factory(monkeypatch)
        OpenAICompatibleProvider(ModelConfig(
            provider="openai", model_name="gpt-test",
            api_key="k", timeout=20,
        ))
        assert len(built) == 1
        _, kwargs, client = built[0]
        assert kwargs == {"trust_env": True}
        assert client.trust_env is True

    def test_openai_loopback_pins_trust_env_false(self, monkeypatch):
        pytest.importorskip("openai")
        from core.llm.config import ModelConfig
        from core.llm.providers import OpenAICompatibleProvider

        built = self._spy_factory(monkeypatch)
        OpenAICompatibleProvider(ModelConfig(
            provider="ollama", model_name="llama-test",
            api_base="http://localhost:11434/v1", timeout=20,
        ))
        assert len(built) == 1
        _, kwargs, client = built[0]
        assert kwargs == {"trust_env": False}
        assert client.trust_env is False


class TestGeminiHttpOptions:
    """Feature detection for google-genai's httpx_client injection
    point — pooled when the field exists, SDK-default otherwise."""

    def test_none_when_sdk_absent(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "google", None)
        from core.llm.providers import _pooled_gemini_http_options
        assert _pooled_gemini_http_options(30) is None

    def _stub_genai_types(self, monkeypatch, fields):
        class HttpOptions:
            model_fields = dict.fromkeys(fields)

            def __init__(self, **kwargs):
                self.kwargs = kwargs

        genai_types = types.ModuleType("google.genai.types")
        genai_types.HttpOptions = HttpOptions
        genai = types.ModuleType("google.genai")
        genai.types = genai_types
        google = types.ModuleType("google")
        google.genai = genai
        monkeypatch.setitem(sys.modules, "google", google)
        monkeypatch.setitem(sys.modules, "google.genai", genai)
        monkeypatch.setitem(sys.modules, "google.genai.types", genai_types)
        return HttpOptions

    def test_none_when_field_missing(self, monkeypatch):
        self._stub_genai_types(monkeypatch, fields=("base_url",))
        from core.llm.providers import _pooled_gemini_http_options
        assert _pooled_gemini_http_options(30) is None

    def test_pooled_client_when_field_present(self, monkeypatch):
        HttpOptions = self._stub_genai_types(
            monkeypatch, fields=("base_url", "httpx_client"),
        )
        from core.llm.providers import _pooled_gemini_http_options
        opts = _pooled_gemini_http_options(30)
        assert isinstance(opts, HttpOptions)
        client = opts.kwargs["httpx_client"]
        try:
            assert isinstance(client, httpx.Client)
        finally:
            client.close()
