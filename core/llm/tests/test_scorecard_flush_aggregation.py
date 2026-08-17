"""Process-level scorecard flush aggregation.

Observed field failure: transports that spawn an LLMClient per call
(claude-CLI) made a single /audit run print 16 separate
"scorecard: 1 calls across 1 model(s) ..." stderr lines at exit — one
per client's own atexit hook. Clients now enroll in ONE process-level
aggregator that flushes every client's window into the scorecard (no
data loss) and prints a single summed line.
"""

from __future__ import annotations

import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import core.llm.client as client_mod
from core.llm.client import (
    LLMClient,
    _flush_all_scorecards,
    _print_scorecard_summary,
    _register_scorecard_flush,
)


def _make_client(alias: str, *, calls: int, cost: float,
                 lat_ms: int = 100) -> LLMClient:
    """Bare client (skips __init__ — a supported construction path)
    with a fired window for *alias* and a mock scorecard."""
    c = LLMClient.__new__(LLMClient)
    c.config = SimpleNamespace(scorecard_enabled=True)
    c._stats_lock = threading.Lock()
    c._fired_models = {("prov", alias, None, "primary"): calls}
    c._fired_usage = {
        alias: {
            "cost_usd": cost, "tokens": 10,
            "input_tokens": 6, "output_tokens": 4,
            "latency_ms_sum": lat_ms, "latency_ms_max": lat_ms,
        },
    }
    c._fired_schema = {}
    # ``scorecard`` is a lazy property over ``_scorecard`` — pre-seed
    # the backing slot so the flush writes to a mock, never to disk.
    c._scorecard = MagicMock()
    return c


# Captured at import time, BEFORE the conftest's autouse
# ``_isolate_scorecard`` fixture stubs the method on the class — the
# fixture below restores it so these tests exercise the real flush.
_REAL_FLUSH = LLMClient.flush_usage_to_scorecard


@pytest.fixture(autouse=True)
def _reset_registry(monkeypatch):
    """Isolate the module-level registry per test. The conftest's
    autouse flush stub is removed so THESE tests exercise the real
    flush against mock scorecards (still no disk / network)."""
    monkeypatch.setattr(client_mod, "_SCORECARD_FLUSH_CLIENTS", [])
    monkeypatch.setattr(client_mod, "_SCORECARD_ATEXIT_ARMED", True)
    monkeypatch.setattr(LLMClient, "flush_usage_to_scorecard", _REAL_FLUSH)


class TestFlushReturnsStats:
    def test_stats_shape(self):
        c = _make_client("haiku", calls=3, cost=0.5, lat_ms=300)
        stats = c.flush_usage_to_scorecard(emit_summary=False)
        assert stats == {
            "calls": 3, "cost_usd": 0.5, "latency_ms_sum": 300,
            "models": {"haiku": 3},
        }
        # The scorecard write still happened (no data loss).
        assert c._scorecard.register_uses.called

    def test_nothing_fired_returns_none(self):
        c = _make_client("haiku", calls=1, cost=0.1)
        c._fired_models = {}
        assert c.flush_usage_to_scorecard(emit_summary=False) is None

    def test_second_flush_is_empty_window(self):
        c = _make_client("haiku", calls=1, cost=0.1)
        assert c.flush_usage_to_scorecard(emit_summary=False) is not None
        assert c.flush_usage_to_scorecard(emit_summary=False) is None
        assert c._scorecard.register_uses.call_count == 1


class TestProcessAggregation:
    def test_sixteen_clients_one_line(self, capsys):
        """The observed failure shape: 16 per-call clients must produce
        ONE aggregate line, not 16."""
        clients = [
            _make_client("haiku", calls=1, cost=0.505, lat_ms=100)
            for _ in range(16)
        ]
        for c in clients:
            _register_scorecard_flush(c)

        _flush_all_scorecards()

        err = capsys.readouterr().err
        lines = [ln for ln in err.splitlines() if ln.startswith("scorecard:")]
        assert len(lines) == 1
        # Accurate aggregate: 16 calls, one model, summed cost.
        assert lines[0].startswith("scorecard: 16 calls across 1 model(s) ")
        assert "[haiku 16c]" in lines[0]
        assert "$8.0800" in lines[0]
        # Every client's window still reached the scorecard.
        for c in clients:
            assert c._scorecard.register_uses.call_count == 1

    def test_multiple_models_summed(self, capsys):
        _register_scorecard_flush(_make_client("haiku", calls=2, cost=0.2))
        _register_scorecard_flush(_make_client("pro", calls=1, cost=0.3))
        _register_scorecard_flush(_make_client("haiku", calls=3, cost=0.1))

        _flush_all_scorecards()

        err = capsys.readouterr().err
        lines = [ln for ln in err.splitlines() if ln.startswith("scorecard:")]
        assert len(lines) == 1
        assert lines[0].startswith("scorecard: 6 calls across 2 model(s) ")
        assert "[haiku 5c, pro 1c]" in lines[0]
        assert "$0.6000" in lines[0]

    def test_no_line_when_nothing_fired(self, capsys):
        c = _make_client("haiku", calls=1, cost=0.1)
        c._fired_models = {}
        _register_scorecard_flush(c)
        _flush_all_scorecards()
        assert "scorecard:" not in capsys.readouterr().err

    def test_stubbed_legacy_signature_tolerated(self, capsys):
        """A client whose flush was monkeypatched to the legacy
        zero-kwarg signature must not break the aggregator."""
        legacy = SimpleNamespace()
        legacy.flush_usage_to_scorecard = lambda: None  # no **kwargs
        _register_scorecard_flush(legacy)
        _register_scorecard_flush(_make_client("haiku", calls=1, cost=0.7))

        _flush_all_scorecards()

        err = capsys.readouterr().err
        lines = [ln for ln in err.splitlines() if ln.startswith("scorecard:")]
        assert len(lines) == 1
        assert lines[0].startswith("scorecard: 1 calls across 1 model(s) ")

    def test_registry_cleared_after_flush(self, capsys):
        _register_scorecard_flush(_make_client("haiku", calls=1, cost=0.4))
        _flush_all_scorecards()
        capsys.readouterr()
        # Second run: nothing left to flush, no duplicate line.
        _flush_all_scorecards()
        assert "scorecard:" not in capsys.readouterr().err

    def test_arm_registers_in_process_registry(self):
        c = _make_client("haiku", calls=1, cost=0.1)
        c._usage_flush_armed = False
        c._arm_usage_flush()
        assert c in client_mod._SCORECARD_FLUSH_CLIENTS
        # Idempotent per client.
        c._arm_usage_flush()
        assert client_mod._SCORECARD_FLUSH_CLIENTS.count(c) == 1


class TestSummaryLineSuppression:
    def test_quiet_env_suppresses(self, capsys, monkeypatch):
        monkeypatch.setenv("RAPTOR_LLM_QUIET", "1")
        _print_scorecard_summary(
            {"calls": 2, "cost_usd": 1.0, "latency_ms_sum": 10,
             "models": {"haiku": 2}},
        )
        assert capsys.readouterr().err == ""

    def test_zero_cost_under_pytest_suppressed(self, capsys):
        # This test session IS pytest, so a zero-cost summary must not
        # print (the anti-noise rule the per-instance path had).
        _print_scorecard_summary(
            {"calls": 2, "cost_usd": 0.0, "latency_ms_sum": 10,
             "models": {"haiku": 2}},
        )
        assert capsys.readouterr().err == ""
