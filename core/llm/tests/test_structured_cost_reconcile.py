"""Exception-path cost reconciliation in ``generate_structured``.

When a provider incurs cost and then raises (e.g. the JSON-fallback
made a real API call before the parse failed), the client records the
incurred cost and cancels the budget reservation. With cost tracking
disabled no reservation was ever taken (``_acquire_budget`` is a
no-op), so the cancellation must be skipped — the old code subtracted
the reservation unconditionally, drifting ``total_cost`` low by $0.10
per such failure.
"""

from __future__ import annotations

import pytest

from core.llm.client import _BUDGET_RESERVATION, LLMClient
from core.llm.config import LLMConfig, ModelConfig


class _CostlyFailingProvider:
    """Incurs cost on each structured call, then raises (parse failure)."""

    def __init__(self):
        self.total_cost = 0.0
        self.total_tokens = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cache_read_tokens = 0
        self.total_cache_write_tokens = 0
        self.calls = 0

    def generate_structured(self, prompt, schema, system_prompt=None, **kwargs):
        self.calls += 1
        self.total_cost += 0.05
        raise ValueError("simulated post-API parse failure")


def _client(*, cost_tracking: bool) -> tuple[LLMClient, _CostlyFailingProvider]:
    config = LLMConfig(
        primary_model=ModelConfig(
            provider="anthropic", model_name="test-model", api_key="test-key",
        ),
        enable_caching=False,
        enable_fallback=False,
        enable_cost_tracking=cost_tracking,
        max_retries=1,
    )
    client = LLMClient(config)
    provider = _CostlyFailingProvider()
    client._get_provider = lambda model_config: provider
    return client, provider


_SCHEMA = {"type": "object", "properties": {"x": {"type": "string"}}}


def test_no_reservation_subtracted_when_cost_tracking_disabled():
    client, provider = _client(cost_tracking=False)
    with pytest.raises(RuntimeError):
        client.generate_structured("prompt", _SCHEMA)
    assert provider.calls == 1
    # Only the incurred cost lands — no phantom reservation cancel
    # (old behaviour: 0.05 - 0.10 = -0.05 per failure).
    assert client.total_cost == pytest.approx(0.05)


def test_reservation_still_reconciled_when_cost_tracking_enabled():
    client, provider = _client(cost_tracking=True)
    with pytest.raises(RuntimeError):
        client.generate_structured("prompt", _SCHEMA)
    assert provider.calls == 1
    # _acquire_budget pre-debited the reservation; the except path
    # nets it back out and records the actual cost.
    assert client.total_cost == pytest.approx(
        _BUDGET_RESERVATION + (0.05 - _BUDGET_RESERVATION),
    )
