"""The spawn child's seccomp install must not import modules post-fork.

The unix-scope notify-export branch of _apply_seccomp ran
``import array`` / ``import socket`` INSIDE the post-fork spawn child,
and the unix-scope receiver daemon thread lazily imported the same
pair. Post-fork/threaded import is unsafe there: the parent is
threaded (unix-scope receiver, proxy lanes), so import-machinery state
can be mid-flight at fork; and the spawn child has already pivoted
into the sandbox root, so an interpreter whose stdlib lives OUTSIDE
the bound system dirs (hostedtoolcache / uv-managed builds under /opt
or $HOME) cannot load a not-yet-cached module from the filesystem at
all. Whether the modules happen to be cached at fork time is an
accident of the calling process — pytest sessions have both; a fresh
minimal driver (libexec entry scripts, subprocess-spawned tools) has
neither. The resulting ImportError was swallowed by the install
catch-all and surfaced as an anonymous rc=126 "seccomp enforcement
failed" — undiagnosable from CI logs.

Pins:
  * AST: _apply_seccomp (the code that runs in the post-fork child)
    and _unix_scope_receiver (the parent daemon thread) contain no
    import statements — module-level imports are the cache. A
    sys.modules-based runtime simulation is deliberately NOT used: the
    parent legitimately re-imports the same modules pre-fork, which
    re-caches them for the child and silently hollows the probe.
  * The install catch-all names the exception it dies on.
"""

import ast
import os
import sys
import textwrap

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="spawn backend is Linux-only",
)


def _function_ast(module_path: str, func_name: str) -> ast.AST:
    tree = ast.parse(open(module_path).read())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            return node
    raise AssertionError(f"{func_name} not found in {module_path}")


def _imports_inside(node: ast.AST) -> list[str]:
    found = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Import):
            found.extend(a.name for a in sub.names)
        elif isinstance(sub, ast.ImportFrom):
            found.append(sub.module or "")
    return found


def test_apply_seccomp_child_performs_no_imports():
    import core.sandbox.seccomp as sc
    node = _function_ast(sc.__file__, "_apply_seccomp")
    assert _imports_inside(node) == [], (
        "the post-fork seccomp install must not execute import "
        "statements — bind needed modules at module level (a pivoted "
        "child cannot reach an out-of-root stdlib, and the resulting "
        "ImportError aborts the run as an anonymous rc=126)")


def test_unix_scope_receiver_performs_no_imports():
    import core.sandbox._spawn as sp
    node = _function_ast(sp.__file__, "_unix_scope_receiver")
    assert _imports_inside(node) == [], (
        "the unix-scope receiver daemon thread must not execute import "
        "statements — an import-starved or fork-racing process kills "
        "the supervisor before it receives the notify fd")


def test_seccomp_module_caches_child_dependencies():
    # The child's bindings resolve to module-level imports: importing
    # the seccomp module alone must be sufficient for the child branch
    # to run without touching the import system.
    import importlib
    import subprocess
    code = textwrap.dedent("""
        import os, sys
        sys.path.insert(0, os.environ["RAPTOR_DIR"])
        import core.sandbox.seccomp
        assert "array" in sys.modules, "array not cached at import"
        assert "socket" in sys.modules, "socket not cached at import"
        print("CACHED-OK")
    """)
    repo = os.path.realpath(
        os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    r = subprocess.run(
        [sys.executable, "-c", code],
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
             "HOME": os.environ.get("HOME", "/tmp"),
             "RAPTOR_DIR": repo},
        capture_output=True, text=True, timeout=60, check=False)
    assert r.returncode == 0 and "CACHED-OK" in r.stdout, (
        f"seccomp module does not pre-cache the child's dependencies: "
        f"{r.stdout!r} {r.stderr[-300:]!r}")
    importlib.invalidate_caches()


def test_seccomp_install_catchall_names_the_exception():
    from unittest import mock

    from core.sandbox import seccomp as sc
    from core.sandbox import state
    if not sc.check_seccomp_available():
        pytest.skip("seccomp unavailable")
    fn = sc._make_seccomp_preexec("full")
    assert fn is not None
    r, w = os.pipe()
    # Same suppression as the production fork-probe sites: the child
    # only calls the (mocked) preexec and _exits — no Python locks.
    import warnings
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore", category=DeprecationWarning,
            message=r".*fork.*may lead to deadlocks.*",
        )
        pid = os.fork()
    if pid == 0:  # throwaway child — the preexec one-way-restricts
        try:
            os.close(r)
            os.dup2(w, 2)
            with mock.patch.object(state._libseccomp_cache, "seccomp_init",
                                   side_effect=RuntimeError("boom-witness")):
                fn()
        finally:
            os._exit(99)  # fn() must have _exited 126 before this
    os.close(w)
    err = b""
    try:
        while True:
            chunk = os.read(r, 4096)
            if not chunk:
                break
            err += chunk
    finally:
        os.close(r)
        _, status = os.waitpid(pid, 0)
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 126, (
        f"expected fail-closed 126, got {status}: {err!r}")
    assert b"seccomp enforcement failed" in err
    assert b"boom-witness" in err, (
        f"catch-all did not name the exception: {err!r}")
