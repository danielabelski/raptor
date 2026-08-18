"""Pooled ``httpx`` clients for the in-process LLM SDK transports.

Why this exists
---------------
Every LLM SDK RAPTOR drives in-process (anthropic, openai,
google-genai) builds its transport on ``httpx``, and httpx's default
pool expires idle keepalive connections after 5 seconds
(``httpx.Limits().keepalive_expiry``). RAPTOR's call pattern has
think-time gaps between LLM calls — prompt assembly, tool runs,
verdict processing — that routinely exceed 5 seconds, so the pooled
connection is already gone when the next call starts and every call
pays connection establishment again.

On a direct network that is one TCP + TLS handshake. Behind the
in-process egress chokepoint chained to a corporate proxy
(:mod:`core.llm.egress`) it is TCP to the chokepoint, a fresh TCP +
CONNECT negotiation to the corporate proxy, a CONNECT to the API
host, then the TLS handshake over both hops — several round trips,
each inflated by proxy latency, on every call. A keepalive window
that matches the actual inter-call gap makes connection reuse happen
at all.

Trade-off: a longer keepalive widens the stale-connection race — the
far side of an idle connection goes away and the next request fails
on first byte. The SDKs already retry connection errors, and the
same race exists today for any gap over 5 seconds; the window moves,
it does not appear.

Knobs (all optional; invalid values fall back to the default):

``RAPTOR_HTTP_KEEPALIVE_S``
    Idle keepalive expiry in seconds (default 60).
``RAPTOR_HTTP_MAX_KEEPALIVE``
    Idle connections kept in the pool (default 20).
``RAPTOR_HTTP_MAX_CONNECTIONS``
    Total concurrent connections per client (default 100).
``RAPTOR_HTTP2``
    Opt-in HTTP/2 (default off; needs the ``h2`` package). All
    concurrent calls multiplex over one connection — one CONNECT
    chain and one TLS handshake total instead of one per pooled
    connection. Off by default because the failure modes are real:
    TCP head-of-line blocking stalls every multiplexed stream on one
    lost packet, and some middleboxes misbehave on long-lived
    multiplexed tunnels. Enable per-deployment and verify.
"""

from __future__ import annotations

import importlib.util
import logging
import os

import httpx

logger = logging.getLogger(__name__)

_KEEPALIVE_ENV = "RAPTOR_HTTP_KEEPALIVE_S"
_MAX_KEEPALIVE_ENV = "RAPTOR_HTTP_MAX_KEEPALIVE"
_MAX_CONNECTIONS_ENV = "RAPTOR_HTTP_MAX_CONNECTIONS"
_HTTP2_ENV = "RAPTOR_HTTP2"

# Warn-once flag for "opted in but h2 not installed" — the fallback
# is silent-safe (HTTP/1.1 keeps working) but the operator asked for
# something they are not getting, so say so exactly once.
_http2_missing_warned = False

_DEFAULT_KEEPALIVE_S = 60.0
_DEFAULT_MAX_KEEPALIVE = 20
_DEFAULT_MAX_CONNECTIONS = 100


def _env_number(name: str, default: float) -> float:
    """Parse a positive number from ``name``; fall back on anything
    that is absent, unparseable, or not strictly positive."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        logger.warning(
            "%s=%r is not a number — using default %s", name, raw, default,
        )
        return default
    if value <= 0:
        logger.warning(
            "%s=%r must be positive — using default %s", name, raw, default,
        )
        return default
    return value


def http2_enabled() -> bool:
    """True when the operator opted in via ``RAPTOR_HTTP2`` AND the
    ``h2`` stack is installed.

    ALPN happens end-to-end inside the CONNECT tunnel, so HTTP/2
    works through the egress chokepoint and a chained corporate
    proxy. Opted-in-but-missing-h2 warns once and stays on HTTP/1.1
    — httpx would otherwise raise at client construction.
    """
    if os.environ.get(_HTTP2_ENV, "").strip().lower() not in (
        "1", "true", "yes", "on",
    ):
        return False
    if importlib.util.find_spec("h2") is None:
        global _http2_missing_warned
        if not _http2_missing_warned:
            _http2_missing_warned = True
            logger.warning(
                "%s is set but the 'h2' package is not installed — "
                "staying on HTTP/1.1. Install with: pip install h2",
                _HTTP2_ENV,
            )
        return False
    return True


def pool_limits() -> httpx.Limits:
    """Connection-pool limits for LLM transports.

    Read from the env on every call (cheap — three lookups) so the
    knobs behave like the dispatcher's timeout knob: tunable without
    code edits, effective for every client built after the change.
    """
    return httpx.Limits(
        keepalive_expiry=_env_number(_KEEPALIVE_ENV, _DEFAULT_KEEPALIVE_S),
        max_keepalive_connections=int(
            _env_number(_MAX_KEEPALIVE_ENV, _DEFAULT_MAX_KEEPALIVE)
        ),
        max_connections=int(
            _env_number(_MAX_CONNECTIONS_ENV, _DEFAULT_MAX_CONNECTIONS)
        ),
    )


def sdk_http_client(
    timeout: float | httpx.Timeout,
    *,
    trust_env: bool = True,
) -> httpx.Client:
    """Build the transport client an LLM SDK constructor receives.

    ``trust_env=False`` pins a client that ignores proxy env — for
    loopback gateways (Ollama, vLLM, LM Studio) that must never
    detour through a corporate proxy. Remote bases keep proxy-env
    behaviour so calls flow through the egress chokepoint.

    The client's own ``timeout`` is a fallback — the SDKs set their
    per-request timeout on each request they send.
    """
    return httpx.Client(
        timeout=timeout,
        trust_env=trust_env,
        limits=pool_limits(),
        http2=http2_enabled(),
    )


__all__ = [
    "http2_enabled",
    "pool_limits",
    "sdk_http_client",
]
