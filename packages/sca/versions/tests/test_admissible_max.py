"""Tests for ``affects_admissible_max`` — corridor (range-pin) matching.

The function models the version a maximising resolver would install
for a corridor (``pkg<2.0`` → greatest release below 2.0; no ceiling →
latest release) and asks whether an OSV vulnerable interval contains
that version.
"""

from __future__ import annotations

import pytest

from packages.sca.versions import VersionError, affects_admissible_max


def test_interval_reaching_past_ceiling_matches() -> None:
    events = [{"introduced": "0"}, {"fixed": "41.0.0"}]
    assert affects_admissible_max("PyPI", events, None, "40.0.0")


def test_interval_fixed_exactly_at_ceiling_matches() -> None:
    # For an exclusive ``<C`` corridor every admissible version
    # predates a fix landing exactly at C.
    events = [{"introduced": "0"}, {"fixed": "40.0.0"}]
    assert affects_admissible_max("PyPI", events, None, "40.0.0")


def test_interval_fixed_below_ceiling_does_not_match() -> None:
    events = [{"introduced": "0"}, {"fixed": "3.2"}]
    assert not affects_admissible_max("PyPI", events, None, "40.0.0")


def test_interval_entirely_above_ceiling_does_not_match() -> None:
    events = [{"introduced": "41.0"}, {"fixed": "42.0"}]
    assert not affects_admissible_max("PyPI", events, None, "40.0.0")


def test_open_interval_matches_any_ceiling() -> None:
    events = [{"introduced": "1.0"}]
    assert affects_admissible_max("PyPI", events, None, "40.0.0")


def test_no_ceiling_matches_only_unfixed() -> None:
    open_events = [{"introduced": "1.0"}]
    fixed_events = [{"introduced": "0"}, {"fixed": "2.0"}]
    assert affects_admissible_max("PyPI", open_events, "1.0", None)
    assert not affects_admissible_max("PyPI", fixed_events, "1.0", None)


def test_last_affected_closes_the_interval() -> None:
    # ``last_affected`` is a closed upper bound, not an open interval —
    # without a ceiling (resolver-max = latest) it must not match.
    events = [{"introduced": "0"}, {"last_affected": "1.9"}]
    assert not affects_admissible_max("PyPI", events, None, None)
    # With a ceiling below/at the last_affected version it does.
    assert affects_admissible_max("PyPI", events, None, "1.5")


def test_empty_corridor_matches_nothing() -> None:
    events = [{"introduced": "0"}, {"fixed": "41.0.0"}]
    assert not affects_admissible_max("PyPI", events, "50.0", "40.0.0")


def test_empty_events_match_nothing() -> None:
    assert not affects_admissible_max("PyPI", [], None, "40.0.0")


def test_unparseable_bound_raises_version_error() -> None:
    events = [{"introduced": "not-a-version"}, {"fixed": "2.0"}]
    with pytest.raises(VersionError):
        affects_admissible_max("PyPI", events, None, "1.0")


def test_multi_interval_any_match_wins() -> None:
    events = [
        {"introduced": "0"}, {"fixed": "1.0"},
        {"introduced": "2.0"}, {"fixed": "3.0"},
    ]
    assert affects_admissible_max("PyPI", events, None, "2.5")
    assert not affects_admissible_max("PyPI", events, None, "1.5")
