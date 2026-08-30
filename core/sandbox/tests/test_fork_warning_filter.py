"""The multi-threaded-fork DeprecationWarning stays silenced.

Python 3.12+ can emit a DeprecationWarning from ``os.fork()`` in a
multi-threaded process. _spawn's fork sites honour the module's
fork-safety contract, so the warning is noise on this codebase — but
whether the interpreter emits it at all is environment-dependent, so
these pins emit the exact CI-observed message themselves and assert
each suppression layer swallows it:

* the module-level filter in core/sandbox/_spawn (covers production
  and CLI runs) — pinned in a bare subprocess with warnings escalated
  to errors;
* the pytest.ini ``filterwarnings`` entry (covers the test tiers,
  where pytest's per-test filter reset discards runtime-installed
  module filters — the mechanism that let the warning escape into
  nightly output) — pinned by running a warning-emitting test under
  the repo config and asserting an empty warnings summary.
"""

import os
import subprocess
import sys
import textwrap
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]

# Verbatim shape of the CI-observed message (pid varies).
_MSG = ("This process (pid=4667) is multi-threaded, "
        "use of fork() may lead to deadlocks in the child.")

_MODULE_LAYER_CHILD = f"""
import warnings
import core.sandbox._spawn  # installs the module-level filter
warnings.warn({_MSG!r}, DeprecationWarning, stacklevel=2)
print("SUPPRESSED-OK")
"""


def test_module_filter_swallows_the_exact_message():
    r = subprocess.run(
        [sys.executable, "-W", "error::DeprecationWarning",
         "-c", _MODULE_LAYER_CHILD],
        capture_output=True, text=True, timeout=60,
        cwd=_REPO, env={**os.environ},
    )
    assert r.returncode == 0, f"stdout={r.stdout}\nstderr={r.stderr}"
    assert "SUPPRESSED-OK" in r.stdout


def test_pytest_config_swallows_the_exact_message(tmp_path):
    probe = tmp_path / "test_forkwarn_probe.py"
    probe.write_text(textwrap.dedent(f"""
        import warnings

        def test_emit():
            warnings.warn({_MSG!r}, DeprecationWarning, stacklevel=2)
    """))
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "-c", str(_REPO / "pytest.ini"),
         "-p", "no:cacheprovider", "-q", str(probe)],
        capture_output=True, text=True, timeout=120,
        cwd=_REPO, env={**os.environ},
    )
    assert r.returncode == 0, f"stdout={r.stdout}\nstderr={r.stderr}"
    assert "1 passed" in r.stdout
    assert "warnings summary" not in r.stdout, (
        "the fork DeprecationWarning escaped the pytest.ini filter:\n"
        + r.stdout
    )
