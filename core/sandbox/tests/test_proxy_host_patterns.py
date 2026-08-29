"""Allowlist suffix-pattern matching (region-sharded registry CDNs)."""

from __future__ import annotations

from core.sandbox.proxy import _host_matches_allowlist

_ENTRIES = frozenset({
    "mcr.microsoft.com",
    "*.data.mcr.microsoft.com",
    "registry-1.docker.io",
})


def test_exact_entries_still_match() -> None:
    assert _host_matches_allowlist("mcr.microsoft.com", _ENTRIES)
    assert _host_matches_allowlist("registry-1.docker.io", _ENTRIES)


def test_pattern_matches_region_prefixes() -> None:
    assert _host_matches_allowlist(
        "centralus.data.mcr.microsoft.com", _ENTRIES)
    assert _host_matches_allowlist(
        "westeurope.data.mcr.microsoft.com", _ENTRIES)


def test_pattern_is_label_boundary_safe() -> None:
    # The bare suffix host is NOT admitted by the pattern...
    assert not _host_matches_allowlist(
        "data.mcr.microsoft.com", _ENTRIES)
    # ...and neither is a host merely ENDING in the letters.
    assert not _host_matches_allowlist(
        "evildata.mcr.microsoft.com", _ENTRIES)
    assert not _host_matches_allowlist(
        "mcr.microsoft.com.evil.example", _ENTRIES)


def test_unrelated_hosts_still_denied() -> None:
    assert not _host_matches_allowlist("example.com", _ENTRIES)
