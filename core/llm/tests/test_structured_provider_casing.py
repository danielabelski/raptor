"""Provider casing on ``StructuredResponse``.

``generate()``'s cached path was already fixed to lowercase the
provider so cached and fresh responses land in the same bucket for
consumers grouping by provider (telemetry summaries, cost rollups).
``generate_structured()`` had reintroduced the same inconsistency on
both its cached and fresh paths — an ``LLMConfig`` with
``provider="Anthropic"`` returned ``"Anthropic"`` from structured
calls and ``"anthropic"`` from everything else.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any

from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig

_SCHEMA = {"type": "object", "properties": {"verdict": {"type": "string"}}}


class _FakeProvider:
    def __init__(self):
        self.calls = 0
        self.total_cost = 0.0
        self.total_tokens = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cache_read_tokens = 0
        self.total_cache_write_tokens = 0

    def generate_structured(
        self, prompt: str, schema: dict[str, Any],
        system_prompt: str | None = None, **kwargs,
    ) -> tuple[dict[str, Any], str]:
        self.calls += 1
        self.total_cost += 0.001
        self.total_tokens += 100
        return {"verdict": "safe"}, '{"verdict":"safe"}'


def _client(tmp_path: Path) -> LLMClient:
    """Minimal client with a MIXED-CASE provider name (accepted by the
    constructor — downstream lookups are case-insensitive)."""
    cfg = LLMConfig.__new__(LLMConfig)
    cfg.primary_model = ModelConfig(
        provider="Anthropic",
        model_name="test-primary",
        max_context=200000,
        api_key="not-used",
    )
    cfg.fallback_models = []
    cfg.specialized_models = {}
    cfg.enable_fallback = False
    cfg.max_retries = 1
    cfg.retry_delay = 0.0
    cfg.retry_delay_remote = 0.0
    cfg.enable_caching = True
    cfg.cache_dir = tmp_path / "llm_cache"
    cfg.cache_ttl_seconds = None
    cfg.cache_max_entries = None
    cfg.enable_cost_tracking = False
    cfg.max_cost_per_scan = 100.0
    cfg.scorecard_enabled = False
    cfg.cache_dir.mkdir(parents=True, exist_ok=True)

    client = LLMClient.__new__(LLMClient)
    client.config = cfg
    client.providers = {}
    client.total_cost = 0.0
    client.request_count = 0
    client.cache_hits = 0
    client.task_type_costs = {}
    client._daily_quota_exhausted = set()
    client._stats_lock = threading.RLock()
    client._key_locks = OrderedDict()
    client._key_locks_guard = threading.Lock()
    client._key_locks_cap = 4096

    pm = cfg.primary_model
    client.providers[f"{pm.provider}:{pm.model_name}"] = _FakeProvider()
    return client


def test_fresh_structured_response_provider_is_lowercased(tmp_path: Path):
    client = _client(tmp_path)
    r = client.generate_structured("Is this safe?", _SCHEMA)
    assert r.cached is False
    assert r.provider == "anthropic"


def test_cached_structured_response_provider_is_lowercased(tmp_path: Path):
    client = _client(tmp_path)
    client.generate_structured("Is this safe?", _SCHEMA)
    r2 = client.generate_structured("Is this safe?", _SCHEMA)
    assert r2.cached is True
    assert r2.provider == "anthropic"
