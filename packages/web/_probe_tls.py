"""TLS context for raw scanner probes — scanner semantics, not client.

Every consumer here is attack traffic aimed at an authorized target:
the probe exists to elicit a parsing or protocol differential from
whatever stack the target runs, legacy included, and there is nothing
of ours to protect on the transport. Certificate validation and
hostname checking are therefore off by design (self-signed staging
targets are common), and the version floor is pinned to TLS 1.0
explicitly instead of inheriting build defaults (distro OpenSSL policy
may still refuse below 1.2 at handshake time, which only narrows
reach).

This module is the single home for that deliberately-insecure
construction so the scanner checks that use it stay fully analysable:
static analysis flags an unvalidated TLS client as a defect — correct
for client code, inverted for a scanner probe — so this shim, and only
this shim, is excluded from CodeQL scanning in
``.github/codeql/codeql-config.yml``. Never use it for RAPTOR's own
egress (LLM providers, registries, SAGE): those are real clients and
keep real validation.
"""

from __future__ import annotations

import ssl


def probe_tls_context() -> ssl.SSLContext:
    """Return an SSL context for probing an authorized scan target."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx
