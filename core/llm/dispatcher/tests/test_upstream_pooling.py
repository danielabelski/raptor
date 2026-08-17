"""Tests for the dispatcher's pooled forwarding-leg client.

The forwarding leg used to build a fresh ``httpx.Client`` per
request, paying a full TCP + TLS handshake (and, behind chained
proxies, CONNECT negotiation per hop) on every forwarded LLM call.
The dispatcher now owns one pooled client, keyed on the proxy env
(httpx resolves proxy routes at client construction, and the egress
chokepoint mutates HTTPS_PROXY in-process after the dispatcher may
already exist). Requests pass their timeout per-call so the
``RAPTOR_LLM_DISPATCHER_UPSTREAM_TIMEOUT_S`` knob keeps per-request
semantics.
"""

from __future__ import annotations

import os

import httpx
import pytest

from core.llm.dispatcher.auth import CredentialStore
from core.llm.dispatcher.server import _TOKEN_HEADER, LLMDispatcher


@pytest.fixture
def fake_creds():
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {
        "anthropic": "real-secret-key",
        "openai": None,
        "gemini": None,
    }
    return creds


@pytest.fixture
def dispatcher(fake_creds, tmp_path):
    d = LLMDispatcher(
        run_id="pool-test",
        audit_path=tmp_path / "audit.jsonl",
        token_ttl_s=3600,
        token_budget=100,
        creds=fake_creds,
    )
    yield d
    d.shutdown()


def _issue_token(dispatcher, label):
    _, fd = dispatcher.allocate_worker(label=label)
    token = os.read(fd, 64).decode().strip()
    os.close(fd)
    return token


class TestClientCache:

    def test_same_env_reuses_client(self, dispatcher):
        first = dispatcher._upstream_client()
        assert isinstance(first, httpx.Client)
        assert dispatcher._upstream_client() is first

    def test_proxy_env_change_rebuilds_client(self, dispatcher, monkeypatch):
        first = dispatcher._upstream_client()
        # The egress chokepoint's startup mutation: HTTPS_PROXY now
        # points at the in-process proxy. A construction-time client
        # would keep dialling the old route and bypass it.
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:59999")
        second = dispatcher._upstream_client()
        assert second is not first
        assert first.is_closed
        # Stable from there.
        assert dispatcher._upstream_client() is second

    def test_shutdown_closes_upstream_client(self, fake_creds, tmp_path):
        d = LLMDispatcher(
            run_id="pool-close-test",
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=3600,
            token_budget=100,
            creds=fake_creds,
        )
        client = d._upstream_client()
        assert not client.is_closed
        d.shutdown()
        assert client.is_closed

    def test_shutdown_with_no_client_built_is_clean(self, fake_creds, tmp_path):
        d = LLMDispatcher(
            run_id="pool-lazy-test",
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=3600,
            token_budget=100,
            creds=fake_creds,
        )
        assert d._upstream_http is None
        d.shutdown()  # must not raise


class TestForwardingUsesPool:

    def test_requests_reuse_the_dispatcher_client(self, dispatcher, monkeypatch):
        """Two forwarded requests must go through the SAME client
        object — the whole point of the hoist."""
        pooled = dispatcher._upstream_client()
        used = []
        real_stream = pooled.stream

        def recording_stream(method, url, **kwargs):
            used.append(pooled)
            return real_stream(
                "GET", "http://127.0.0.1:1/unreachable",
                timeout=kwargs.get("timeout"),
            )

        monkeypatch.setattr(pooled, "stream", recording_stream)
        token = _issue_token(dispatcher, "pool-e2e")

        transport = httpx.HTTPTransport(uds=str(dispatcher.socket_path))
        with httpx.Client(transport=transport, timeout=10.0) as c:
            for _ in range(2):
                # The upstream dial fails (nothing listens on port 1)
                # — the dispatcher maps that to 502. What matters is
                # WHICH client carried the attempt.
                resp = c.post(
                    "http://_/anthropic/v1/messages",
                    headers={_TOKEN_HEADER: token},
                    content=b"{}",
                )
                assert resp.status_code == 502

        assert len(used) == 2

    def test_per_request_timeout_still_env_driven(self, dispatcher, monkeypatch):
        """The pooled client must not freeze the timeout at
        construction — each request passes the live env value."""
        monkeypatch.setenv("RAPTOR_LLM_DISPATCHER_UPSTREAM_TIMEOUT_S", "77")
        pooled = dispatcher._upstream_client()
        seen = {}
        real_stream = pooled.stream

        def recording_stream(method, url, **kwargs):
            seen["timeout"] = kwargs.get("timeout")
            return real_stream(
                "GET", "http://127.0.0.1:1/unreachable",
                timeout=kwargs.get("timeout"),
            )

        monkeypatch.setattr(pooled, "stream", recording_stream)
        token = _issue_token(dispatcher, "pool-timeout")

        transport = httpx.HTTPTransport(uds=str(dispatcher.socket_path))
        with httpx.Client(transport=transport, timeout=10.0) as c:
            c.post(
                "http://_/anthropic/v1/messages",
                headers={_TOKEN_HEADER: token},
                content=b"{}",
            )

        assert seen["timeout"] is not None
        assert seen["timeout"].read == 77.0
