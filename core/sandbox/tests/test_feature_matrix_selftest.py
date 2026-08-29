"""Wiring check for the sandbox feature-matrix harness.

`run-matrix.sh --self-test` is the docker-free lane: it generates the
derived seccomp profiles, runs the capability probe on this host, and
exercises the report aggregator on synthetic clean/diverged fixtures
(asserting the divergence gate actually gates). Running it here keeps
the weekly workflow's substrate from bit-rotting between Saturdays —
a broken profile generator or report schema surfaces in the PR tier.
"""

import os
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="harness targets the Linux sandbox",
)

_REPO_ROOT = os.path.realpath(
    os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_SCRIPT = os.path.join(_REPO_ROOT, "core", "sandbox", "scripts",
                       "feature-matrix", "run-matrix.sh")


def test_self_test_passes():
    r = subprocess.run([_SCRIPT, "--self-test"], capture_output=True,
                       text=True, timeout=120, check=False,
                       cwd=_REPO_ROOT)
    assert r.returncode == 0, (
        f"feature-matrix self-test failed:\n{r.stdout[-800:]}"
        f"\n{r.stderr[-800:]}")
    assert "self-test OK" in r.stdout
