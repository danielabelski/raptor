"""Wedged-pool watchdog: in-flight files are retried, not blamed.

A zero-completion stall window means the WORKERS wedged (the known
class: a pool forked from a multi-threaded parent inherits fork-
frozen locks), not that the in-flight files are pathological. The
watchdog must retry them in a fresh pool; only a second failure may
exclude them — under the honest ``worker_stalled`` reason.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.inventory import builder as builder_mod
from core.inventory.builder import build_inventory


def _mk_tree(tmp_path: Path, n: int = 14) -> Path:
    src = tmp_path / "proj"
    src.mkdir()
    for i in range(n):
        (src / f"mod_{i:02d}.py").write_text(
            f"def fn_{i}(x):\n    return x + {i}\n",
        )
    return src


def test_wedge_on_first_drain_recovers_via_retry(
    tmp_path: Path, monkeypatch,
) -> None:
    real_drain = builder_mod._drain_futures
    calls = {"n": 0}

    def wedge_once(futures, timeout_s, on_done):
        calls["n"] += 1
        if calls["n"] == 1:
            # Simulated wedged pool: full window, zero completions.
            return set(futures)
        return real_drain(futures, timeout_s, on_done)

    monkeypatch.setattr(builder_mod, "_drain_futures", wedge_once)
    src = _mk_tree(tmp_path)
    inv = build_inventory(str(src), output_dir=str(tmp_path / "out"))
    names = {f["path"] for f in inv["files"]}
    assert len(names) == 14           # every file rescued by the retry
    reasons = {e["reason"] for e in inv.get("excluded_files", [])}
    assert "worker_stalled" not in reasons
    assert calls["n"] >= 2            # the retry pool drained for real


def test_double_wedge_excludes_with_honest_reason(
    tmp_path: Path, monkeypatch,
) -> None:
    def always_wedged(futures, timeout_s, on_done):
        return set(futures)

    monkeypatch.setattr(builder_mod, "_drain_futures", always_wedged)
    src = _mk_tree(tmp_path)
    inv = build_inventory(str(src), output_dir=str(tmp_path / "out"))
    stalled = [e for e in inv.get("excluded_files", [])
               if e["reason"] == "worker_stalled"]
    assert len(stalled) == 14
    assert all("retry failed" in e["pattern_matched"] for e in stalled)


def test_pool_context_is_never_bare_fork() -> None:
    """Fork from a threaded parent inherits frozen locks; the pool
    must use forkserver where the platform offers it."""
    ctx = builder_mod._pool_mp_context()
    if ctx is None:
        pytest.skip("platform without forkserver")
    assert ctx.get_start_method() == "forkserver"


def test_pool_factory_falls_past_a_broken_context(tmp_path: Path) -> None:
    """A context whose workers cannot spawn (forkserver under a
    file-less __main__ is the production case) must fall through to
    the next candidate instead of blowing up at first submit."""
    import multiprocessing

    class _BrokenCtx(type(multiprocessing.get_context())):
        def Process(self, *a, **k):  # noqa: N802 — mp context API
            raise OSError("simulated spawn failure")

        def get_start_method(self, *a, **k):
            return "broken-probe"

    initargs = _probe_initargs(tmp_path)
    pool = builder_mod._make_extractor_pool(
        initargs, max_workers=1,
        contexts=(_BrokenCtx(), None),
    )
    try:
        assert pool is not None
        assert pool.submit(builder_mod._pool_probe).result(timeout=60)
    finally:
        if pool is not None:
            pool.shutdown(wait=True)


def _probe_initargs(tmp_path: Path):
    """Minimal valid initargs tuple for the worker initializer."""
    import inspect

    from core.inventory.builder import _init_inventory_worker
    n = len(inspect.signature(_init_inventory_worker).parameters)
    src = tmp_path / "p"
    src.mkdir(exist_ok=True)
    # target, exclude_patterns, skip_generated, old_files_by_path,
    # allow_unreachable, macro_config, build_tus, crate_modules
    args = [src, [], True, {}, False, None, None, None]
    return tuple(args[:n])


def test_build_inventory_survives_fileless_main(tmp_path: Path) -> None:
    """forkserver preloads __main__; drivers running from stdin
    (python - <<'PY' heredocs — the stress sweep's own shape) have no
    file-backed main and killed the forkserver at first spawn,
    LAZILY, past the constructor-level fallback. The probed factory
    must keep every file in the inventory regardless."""
    import subprocess
    import sys

    src = _mk_tree(tmp_path)
    code = f"""
import sys, json
sys.path.insert(0, {str(Path(builder_mod.__file__).resolve().parents[2])!r})
from core.inventory.builder import build_inventory
inv = build_inventory({str(src)!r}, output_dir={str(tmp_path / 'out')!r})
print("FILES:" + str(len(inv["files"])))
stalled = [e for e in inv.get("excluded_files", [])
           if e["reason"] == "worker_stalled"]
print("STALLED:" + str(len(stalled)))
"""
    proc = subprocess.run(
        [sys.executable, "-"], input=code, capture_output=True,
        text=True, timeout=300,
        env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin",
             "RAPTOR_DIR": str(Path(builder_mod.__file__).resolve().parents[2])},
        check=False,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert "FILES:14" in proc.stdout, proc.stdout + proc.stderr[-1000:]
    assert "STALLED:0" in proc.stdout
    # The doomed spawn-shaped contexts are skipped BEFORE any child
    # is spawned — no forkserver/spawn child traceback may leak to
    # stderr (it printed 15 lines that read like a crash before the
    # fall-through line).
    assert "Traceback" not in proc.stderr, proc.stderr[-2000:]
    assert "FileNotFoundError" not in proc.stderr, proc.stderr[-2000:]


def test_forkserver_pools_leave_process_exit_clean(tmp_path: Path) -> None:
    """RED-FIRST exit-hygiene pin. The probed pool factory makes
    forkserver use routine in test processes; multiprocessing roots
    its process-lifetime temp dir (pymp-*, the forkserver socket)
    under whatever TMPDIR is current at first use — the test
    session's contained scratch dir. The session-tmp owner removes
    that dir at session teardown, and multiprocessing's atexit
    finalizer then crashed the INTERPRETER EXIT with FileNotFoundError
    (traceback after the pytest summary; composed single-process
    gates flag it). The owner must drain multiprocessing's exit
    machinery before deleting the dir — this test runs a full nested
    pytest session that exercises a real pool and asserts the exit is
    byte-clean."""
    import subprocess
    import sys

    repo = str(Path(builder_mod.__file__).resolve().parents[2])
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:xdist",
         "core/inventory/tests/test_builder_stall_retry.py::"
         "test_wedge_on_first_drain_recovers_via_retry"],
        capture_output=True, text=True, timeout=600, cwd=repo,
        env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin",
             "RAPTOR_DIR": repo,
             "RAPTOR_MAX_TEST_SECONDS": "300"},
        check=False,
    )
    tail = proc.stdout[-2000:] + proc.stderr[-2000:]
    assert proc.returncode == 0, tail
    assert "1 passed" in proc.stdout, tail
    # The defect printed AFTER the summary, from an atexit finalizer.
    assert "FileNotFoundError" not in tail, tail
    assert "Traceback" not in proc.stderr, tail
