"""Hardening of the synthesised raw-javac fallback.

Two properties of the no-build-system Java path:

  * The generated build script must invoke javac with ``-proc:none``.
    The synthesised classpath includes repo-supplied ``lib/*.jar``,
    and javac auto-discovers annotation processors on the classpath
    via ServiceLoader — without the flag a hostile jar's processor
    executes attacker code inside every javac invocation.

  * ``_dry_run`` must pass read confinement (``restrict_reads``) to
    the sandbox — the script compiles untrusted repo content, so on
    Landlock-only hosts the read restriction is what keeps ``$HOME``
    credentials out of reach.
"""

from __future__ import annotations

import os
import subprocess
import sys
from types import SimpleNamespace
from unittest import mock

from core.build.build_detector import BuildDetector


def _write_java_script(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Main.java").write_text("class Main {}\n")
    build_dir = tmp_path / "build"
    build_dir.mkdir()
    script = tmp_path / "build_script.py"
    script.touch()
    det = BuildDetector(repo)
    det._write_build_script(
        script, build_dir,
        [repo / "Main.java"], "javac",
        ["-sourcepath", str(repo)], [],
    )
    return script


def test_generated_script_disables_annotation_processing(tmp_path):
    """Run the generated script against a stub javac that records its
    argv; the recorded invocation must carry ``-proc:none``."""
    script = _write_java_script(tmp_path)

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    argv_log = tmp_path / "javac-argv.txt"
    stub = bin_dir / "javac"
    stub.write_text(
        "#!/bin/sh\n"
        f'printf \'%s\\n\' "$@" > "{argv_log}"\n'
    )
    stub.chmod(0o755)

    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    proc = subprocess.run(
        [sys.executable, str(script)],
        env=env, capture_output=True, text=True, timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    recorded = argv_log.read_text().splitlines()
    assert "-proc:none" in recorded, (
        "generated javac invocation must disable annotation "
        f"processing; argv was {recorded!r}"
    )


def test_dry_run_passes_read_confinement(tmp_path):
    """The dry-run sandbox call must restrict reads — the script
    executes untrusted-repo-derived compiles."""
    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(returncode=0, stderr="", stdout="")

    with mock.patch(
        "core.build.build_detector._sandbox_run", side_effect=fake_run,
    ):
        BuildDetector(tmp_path)._dry_run(tmp_path / "script.py")
    assert captured.get("restrict_reads") is True
