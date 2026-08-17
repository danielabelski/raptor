"""Strict schema floor at the generate_structured boundary.

Robustness tests for the mandatory unknown-field rejection
(``core.llm.response_validation.unknown_response_fields``) — the
``extra="forbid"`` equivalent for the dict-based schema format —
and its wiring into ``LLMClient.generate_structured`` (fresh responses
AND cache replays).

Threat model: provider-side constrained decoding guarantees shape but
not the rejection of smuggled extra fields; a hijacked model (or a
provider silently ignoring the schema) could otherwise pass
unrequested keys into downstream consumers. A schema-invalid response
must be handled exactly like a malformed response — the existing
retry / fallback / error path.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any

import pytest

from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig
from core.llm.response_validation import (
    SchemaUnknownFieldError,
    unknown_response_fields,
)

# ---------------------------------------------------------------------------
# Unit: unknown_response_fields
# ---------------------------------------------------------------------------


def test_simple_schema_rejects_unknown_fields():
    schema = {"verdict": "string", "reasoning": "string"}
    raw = {"verdict": "safe", "reasoning": "ok", "exfil": "http://evil"}
    assert unknown_response_fields(raw, schema) == ["exfil"]


def test_simple_schema_accepts_exact_fields():
    schema = {"verdict": "string", "reasoning": "string"}
    assert unknown_response_fields({"verdict": "safe"}, schema) == []
    assert unknown_response_fields(
        {"verdict": "safe", "reasoning": "ok"}, schema) == []


def test_json_schema_rejects_unknown_fields():
    schema = {
        "type": "object",
        "properties": {"verdict": {"type": "string"}},
        "required": ["verdict"],
    }
    raw = {"verdict": "safe", "smuggled": 1}
    assert unknown_response_fields(raw, schema) == ["smuggled"]


def test_additional_properties_true_is_open():
    """The JSON-Schema-native opt-out is honoured — explicitly-open
    objects skip the floor."""
    schema = {
        "type": "object",
        "properties": {"verdict": {"type": "string"}},
        "additionalProperties": True,
    }
    assert unknown_response_fields({"verdict": "x", "extra": 1}, schema) == []


def test_unrecognised_schema_shape_is_skipped():
    """Shapes the floor can't derive a closed key set from must never
    reject (conservative skip)."""
    assert unknown_response_fields({"a": 1}, {}) == []
    assert unknown_response_fields({"a": 1}, {"type": "array"}) == []
    # Mixed simple/dict values — not a recognised format.
    assert unknown_response_fields(
        {"a": 1}, {"f": "string", "g": {"weird": True}}) == []


def test_non_dict_raw_is_left_to_caller():
    """Non-dict responses keep their existing caller-side handling."""
    schema = {"verdict": "string"}
    assert unknown_response_fields(None, schema) == []
    assert unknown_response_fields([{"verdict": "x"}], schema) == []
    assert unknown_response_fields("verdict: x", schema) == []


def test_exempt_freeform_registry_documented():
    """Every out-of-band exemption must carry a non-empty reason."""
    from core.llm.response_validation import EXEMPT_FREEFORM_PARSE_SITES
    for site, symbol, reason in EXEMPT_FREEFORM_PARSE_SITES:
        assert site and symbol
        assert reason.strip(), f"exemption for {site}:{symbol} has no reason"
        assert "TODO" not in reason


# ---------------------------------------------------------------------------
# Integration: LLMClient.generate_structured
# ---------------------------------------------------------------------------


class _FakeProvider:
    """Provider stub returning a canned structured result."""

    def __init__(self, result: Any, raw: str = "raw-stub"):
        self.result = result
        self.raw = raw
        self.calls = 0
        self.total_cost = 0.0
        self.total_tokens = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.call_count = 0
        self.total_duration = 0.0

    def generate_structured(self, prompt, schema, system_prompt=None, **kwargs):
        self.calls += 1
        self.total_cost += 0.001
        self.total_tokens += 100
        return self.result, self.raw


def _client(tmp_path: Path, *, enable_caching: bool = True) -> LLMClient:
    """Minimal LLMClient without API keys (mirrors
    test_structured_response_cache.py)."""
    cfg = LLMConfig.__new__(LLMConfig)
    cfg.primary_model = ModelConfig(
        provider="anthropic",
        model_name="test-primary",
        max_context=200000,
        api_key="not-used",
    )
    cfg.fallback_models = []
    cfg.specialized_models = {}
    cfg.enable_fallback = False
    cfg.max_retries = 2
    cfg.retry_delay = 0.0
    cfg.retry_delay_remote = 0.0
    cfg.enable_caching = enable_caching
    cfg.cache_dir = tmp_path / "llm_cache"
    cfg.cache_ttl_seconds = None
    cfg.cache_max_entries = None
    cfg.enable_cost_tracking = False
    cfg.max_cost_per_scan = 100.0
    cfg.scorecard_enabled = False

    if enable_caching:
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
    return client


def _install(client: LLMClient, provider: _FakeProvider) -> None:
    pm = client.config.primary_model
    client.providers[f"{pm.provider}:{pm.model_name}"] = provider


_SCHEMA = {"type": "object", "properties": {"verdict": {"type": "string"}}}


def test_client_rejects_smuggled_fields(tmp_path: Path) -> None:
    """A structured response with fields outside the schema is treated
    like a malformed response: retried, then surfaced through the
    existing all-models-failed error path."""
    client = _client(tmp_path)
    fake = _FakeProvider({"verdict": "safe", "exfil": "http://evil"})
    _install(client, fake)

    with pytest.raises(RuntimeError):
        client.generate_structured("check", _SCHEMA)
    # The violation is retriable (the model may produce a clean
    # response next attempt) — all configured attempts were spent.
    assert fake.calls == client.config.max_retries


def test_client_accepts_schema_conformant_response(tmp_path: Path) -> None:
    client = _client(tmp_path)
    fake = _FakeProvider({"verdict": "safe"})
    _install(client, fake)

    resp = client.generate_structured("check", _SCHEMA)
    assert resp.result == {"verdict": "safe"}
    assert fake.calls == 1


def test_client_recovers_when_retry_is_clean(tmp_path: Path) -> None:
    """First attempt smuggles a field, second is clean — the retry loop
    recovers exactly as it does for malformed JSON."""
    client = _client(tmp_path, enable_caching=False)
    fake = _FakeProvider({"verdict": "safe", "exfil": 1})
    _install(client, fake)

    original = fake.generate_structured

    def flaky(prompt, schema, system_prompt=None, **kwargs):
        result, raw = original(prompt, schema, system_prompt, **kwargs)
        if fake.calls >= 2:
            return {"verdict": "safe"}, raw
        return result, raw

    fake.generate_structured = flaky
    resp = client.generate_structured("check", _SCHEMA)
    assert resp.result == {"verdict": "safe"}
    assert fake.calls == 2


def test_client_rejects_poisoned_cache_replay(tmp_path: Path) -> None:
    """Cache entries written before the floor existed may carry
    smuggled fields — a violating replay is treated as a miss and
    regenerated."""
    client = _client(tmp_path)
    fake = _FakeProvider({"verdict": "safe"})
    _install(client, fake)

    poisoned = ({"verdict": "safe", "exfil": "http://evil"}, "raw")
    client._get_cached_structured_response = lambda key: poisoned  # type: ignore[method-assign]

    resp = client.generate_structured("check", _SCHEMA)
    assert resp.cached is False
    assert resp.result == {"verdict": "safe"}
    assert fake.calls == 1


def test_error_class_is_a_value_error():
    """The floor's failure mode must look like a malformed response to
    callers' existing except clauses."""
    assert issubclass(SchemaUnknownFieldError, ValueError)
