"""Shared fixtures for the static-analysis test suite."""

from __future__ import annotations

import json

import pytest

from core.config import RaptorConfig


@pytest.fixture
def stub_semgrep_registry_cache(monkeypatch, tmp_path):
    """Make registry-pack resolution local and deterministic.

    ``RaptorConfig.get_semgrep_config`` resolves a registry pack id
    (``p/secrets``) to a cached local JSON when one exists under
    ``SEMGREP_REGISTRY_CACHE_DIR``, else falls through to the raw
    registry id. Raw ids then hit the reachability probe in
    ``scanner._drop_unreachable_registry_packs``, which drops ALL
    uncached registry packs on hosts without semgrep.dev access (no
    cache, no network, no proxy — i.e. CI). Tests asserting baseline
    ``semgrep_*`` pack names therefore passed on developer hosts with
    a reachable egress proxy and failed on CI.

    This fixture pins the cached path on every host: it points the
    cache dir at a tmp dir pre-populated with stub pack JSONs for
    every registry pack the scanner can add (baseline set + policy
    group packs), so resolution yields local paths, no probe fires,
    and pack naming is deterministic. Stub content is the minimal
    valid cache shape (``{"rules": []}``) consumers such as
    ``_pack_rules_applicable_count`` parse.
    """
    cache_dir = tmp_path / "registry-cache"
    cache_dir.mkdir()
    pack_ids = {pid for _, pid in RaptorConfig.BASELINE_SEMGREP_PACKS}
    pack_ids |= {
        pid for _, pid in RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK.values()
    }
    for pack_id in pack_ids:
        cache_file = cache_dir / ("c." + pack_id.replace("/", ".") + ".json")
        cache_file.write_text(json.dumps({"rules": []}), encoding="utf-8")
    monkeypatch.setattr(RaptorConfig, "SEMGREP_REGISTRY_CACHE_DIR", cache_dir)
    return cache_dir
