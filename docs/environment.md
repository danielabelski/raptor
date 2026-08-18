# Environment variable reference

Canonical registry of operator-facing environment variables RAPTOR
reads. One row per variable. When a change introduces a new variable,
add its row here in the same change — subsystem docs carry the
explanatory prose; this file is the index.

This registry currently covers the HTTP-transport and egress-proxy
tuning family. Rows for the pre-existing variable population are
added by the census that owns them; see the per-subsystem docs
(`docs/llm.md`, `docs/sandbox.md`, `docs/configuration.md`) in the
meantime.

## LLM HTTP transport

Prose: `docs/llm.md`, "HTTP Transport Tuning".

| Variable | Default | Purpose |
|----------|---------|---------|
| `RAPTOR_HTTP_KEEPALIVE_S` | `60` | Idle keepalive expiry (seconds) for pooled SDK transports |
| `RAPTOR_HTTP_MAX_KEEPALIVE` | `20` | Idle connections kept in each SDK transport pool |
| `RAPTOR_HTTP_MAX_CONNECTIONS` | `100` | Total concurrent connections per SDK transport |
| `RAPTOR_HTTP2` | off | `1` opts pooled transports into HTTP/2 (requires `h2`) |
| `RAPTOR_LLM_STREAM_TRANSPORT` | off | `1` carries non-streaming Anthropic calls over the SDK streaming transport |

## Egress proxy

Prose: `docs/sandbox.md`, "Upstream proxy support".

| Variable | Default | Purpose |
|----------|---------|---------|
| `RAPTOR_PROXY_UPSTREAM_HANDSHAKE_TIMEOUT_S` | `10` | Budget (seconds) for connecting to and CONNECT-negotiating with the operator's upstream proxy |
