"""Pipe-handling in ``run_cc_streaming`` — no real ``claude`` calls,
children are tiny ``python -c`` scripts.

Two failure modes the read loop must survive:

1. A chatty child that writes more than the 64KB pipe buffer to
   stderr blocks in write(2) if the parent never drains stderr — the
   call then dies as a timeout instead of surfacing the real output.
2. A child that exits at startup (bad flag, missing backend) closes
   stdin before consuming the prompt; the unguarded prompt write
   raised BrokenPipeError instead of reaching the nice
   ``claude -p exited N`` error path.
"""

from __future__ import annotations

import json
import os
import sys

from core.llm.cc_adapter import run_cc_streaming

# Well over the 64KB pipe buffer.
_STDERR_SPEW = 256 * 1024


def _env() -> dict[str, str]:
    return dict(os.environ)


def test_chatty_stderr_child_does_not_deadlock():
    """Child floods stderr past the pipe buffer BEFORE writing its
    stdout result. Without a stderr drain the child blocks in
    write(2) forever and the parent times out."""
    result_line = json.dumps({
        "type": "result",
        "session_id": "sess-spew",
        "is_error": False,
    })
    script = (
        "import sys\n"
        f"sys.stderr.write('x' * {_STDERR_SPEW})\n"
        "sys.stderr.flush()\n"
        f"sys.stdout.write({result_line!r} + '\\n')\n"
    )
    sr = run_cc_streaming(
        [sys.executable, "-c", script],
        prompt="",
        env=_env(),
        timeout_s=30,
    )
    assert sr.error is None
    assert sr.session_id == "sess-spew"


def test_chatty_stderr_is_reported_on_failure():
    """When the chatty child fails, its (drained) stderr must reach
    the error message."""
    script = (
        "import sys\n"
        f"sys.stderr.write('E' * {_STDERR_SPEW})\n"
        "sys.stderr.flush()\n"
        "sys.exit(2)\n"
    )
    sr = run_cc_streaming(
        [sys.executable, "-c", script],
        prompt="",
        env=_env(),
        timeout_s=30,
    )
    assert sr.error is not None
    assert "exited 2" in sr.error
    assert "E" in sr.error


def test_child_exiting_before_reading_prompt_reports_exit_code():
    """Child exits immediately without touching stdin while the
    parent writes a prompt larger than the pipe buffer — the write
    hits EPIPE. That must surface as the ``exited N`` error result,
    not a BrokenPipeError crash."""
    sr = run_cc_streaming(
        [sys.executable, "-c", "import sys; sys.exit(7)"],
        prompt="y" * (1024 * 1024),
        env=_env(),
        timeout_s=30,
    )
    assert sr.error is not None
    assert "exited 7" in sr.error
