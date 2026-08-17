"""Per-process caching of the Ollama availability probe.

``_get_available_ollama_models`` promises "Cached per-process to avoid
repeated HTTP checks", but only the successful (HTTP 200) path set the
cache flag — when Ollama was absent or unreachable, every
``LLMConfig()`` construction re-ran the probe and paid up to the 2s
connect timeout on filtered/proxied hosts. Negative results (probe
exception, non-200) must be cached too.
"""

from __future__ import annotations

import pytest

from core.llm import detection


@pytest.fixture(autouse=True)
def _reset_probe_cache(monkeypatch):
    """Isolate each test (and the rest of the suite) from the module-
    level probe cache."""
    monkeypatch.setattr(detection, "_ollama_checked", False)
    monkeypatch.setattr(detection, "_cached_ollama_models", None)


def _patch_probe(monkeypatch, side_effect=None, response=None):
    calls = []

    def fake_get(url, timeout=None, **kwargs):
        calls.append(url)
        if side_effect is not None:
            raise side_effect
        return response

    from core.llm import egress
    monkeypatch.setattr(egress, "loopback_safe_get", fake_get)
    return calls


class _Resp:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


def test_unreachable_probe_is_cached(monkeypatch):
    calls = _patch_probe(monkeypatch, side_effect=ConnectionError("refused"))
    assert detection._get_available_ollama_models() == []
    assert detection._get_available_ollama_models() == []
    assert len(calls) == 1, (
        "negative probe result was not cached — every call re-pays the "
        "connect timeout"
    )


def test_non_200_probe_is_cached(monkeypatch):
    calls = _patch_probe(monkeypatch, response=_Resp(503))
    assert detection._get_available_ollama_models() == []
    assert detection._get_available_ollama_models() == []
    assert len(calls) == 1


def test_successful_probe_still_cached(monkeypatch):
    payload = {"models": [{"name": "llama3:8b"}]}
    calls = _patch_probe(monkeypatch, response=_Resp(200, payload))
    assert detection._get_available_ollama_models() == ["llama3:8b"]
    assert detection._get_available_ollama_models() == ["llama3:8b"]
    assert len(calls) == 1
