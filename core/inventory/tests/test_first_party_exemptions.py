"""First-party rescue paths in the inventory's exclusion and language layers.

Three related recall guarantees, each with its miss-direction twin so the
default pruning behaviour is pinned in both directions:

* a nested build-output dir (``build/``/``target/``/``dist/``) that is a
  Python package (direct ``__init__.py``) is source, not artifacts — kept;
  the same name without the marker keeps pruning;
* extensionless interpreter scripts resolve their language from the
  shebang line; non-script extensionless files stay uninventoried;
* a version-suffixed directory (extracted-tarball shape) never drives the
  target-kind verdict, and a scan-root manifest outranks nested ones.
"""

from __future__ import annotations

import json
import os

from core.inventory.builder import build_inventory
from core.inventory.exclusions import (
    DEFAULT_EXCLUDES,
    match_exclusion_reason,
    should_exclude,
)
from core.inventory.languages import detect_language_from_shebang
from core.inventory.library_detection import detect_target_kind


def _write(tmp_path, rel: str, content: str = "") -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


# ---------------------------------------------------------------- build dirs

def test_nested_build_python_package_kept(tmp_path):
    _write(tmp_path, "core/build/__init__.py")
    _write(tmp_path, "core/build/toolchain.py", "def f():\n    return 1\n")
    rel = "core/build/toolchain.py"
    assert should_exclude(rel, DEFAULT_EXCLUDES, target_root=tmp_path) is False
    excluded, _, _ = match_exclusion_reason(
        rel, DEFAULT_EXCLUDES, target_root=tmp_path)
    assert excluded is False


def test_nested_build_without_package_marker_still_pruned(tmp_path):
    _write(tmp_path, "app/build/generated.py", "def g():\n    return 2\n")
    rel = "app/build/generated.py"
    assert should_exclude(rel, DEFAULT_EXCLUDES, target_root=tmp_path) is True
    excluded, _, pattern = match_exclusion_reason(
        rel, DEFAULT_EXCLUDES, target_root=tmp_path)
    assert excluded is True
    assert pattern == "build/"


def test_setuptools_build_lib_tree_still_pruned(tmp_path):
    # ``python setup.py build`` copies packages under build/lib*/pkg/ —
    # the package marker sits below build/, never directly in it, so the
    # artifact tree must keep pruning.
    _write(tmp_path, "build/lib/pkg/__init__.py")
    _write(tmp_path, "build/lib/pkg/mod.py", "def h():\n    return 3\n")
    rel = "build/lib/pkg/mod.py"
    assert should_exclude(rel, DEFAULT_EXCLUDES, target_root=tmp_path) is True


def test_case_variant_ancestor_does_not_shadow_inner_package(tmp_path):
    # The walk keeps 'Build/' (case-sensitive miss) and keeps the inner
    # 'build/' on its package marker; the per-file lowered match hits
    # the ancestor first — the exemption must probe every occurrence,
    # or the walk collects a file the per-file pass then excludes.
    _write(tmp_path, "src/Build/foo/build/__init__.py")
    _write(tmp_path, "src/Build/foo/build/bar.py", "def b():\n    return 4\n")
    rel = os.sep.join(["src", "Build", "foo", "build", "bar.py"])
    assert should_exclude(rel, DEFAULT_EXCLUDES, target_root=tmp_path) is False


def test_without_target_root_string_matching_unchanged(tmp_path):
    _write(tmp_path, "core/build/__init__.py")
    assert should_exclude("core/build/toolchain.py", DEFAULT_EXCLUDES) is True


def test_build_inventory_includes_first_party_build_package(tmp_path):
    _write(tmp_path, "core/build/__init__.py")
    _write(tmp_path, "core/build/toolchain.py", "def probe():\n    return 1\n")
    _write(tmp_path, "app/build/artifact.py", "def dead():\n    return 0\n")
    inv = build_inventory(str(tmp_path), parallel=False)
    paths = {f["path"] for f in inv["files"]}
    assert "core/build/toolchain.py" in paths
    assert "app/build/artifact.py" not in paths


# ------------------------------------------------------------------ shebangs

def test_shebang_detection_python_env_and_direct(tmp_path):
    direct = tmp_path / "tool-direct"
    direct.write_text("#!/usr/bin/python3.12\nprint('x')\n")
    env = tmp_path / "tool-env"
    env.write_text("#!/usr/bin/env python3\nprint('x')\n")
    env_s = tmp_path / "tool-env-s"
    env_s.write_text("#!/usr/bin/env -S python3 -u\nprint('x')\n")
    assert detect_language_from_shebang(str(direct)) == "python"
    assert detect_language_from_shebang(str(env)) == "python"
    assert detect_language_from_shebang(str(env_s)) == "python"


def test_shebang_detection_shell_and_negative(tmp_path):
    sh = tmp_path / "wrapper"
    sh.write_text("#!/bin/bash\necho hi\n")
    plain = tmp_path / "LICENSE"
    plain.write_text("MIT License\n")
    unknown = tmp_path / "runner"
    unknown.write_text("#!/usr/bin/env raku\nsay 'x'\n")
    assert detect_language_from_shebang(str(sh)) == "shell"
    assert detect_language_from_shebang(str(plain)) is None
    assert detect_language_from_shebang(str(unknown)) is None


def test_build_inventory_includes_extensionless_python_script(tmp_path):
    script = tmp_path / "libexec" / "raptor-thing"
    script.parent.mkdir()
    script.write_text("#!/usr/bin/env python3\ndef main():\n    return 0\n")
    _write(tmp_path, "notes", "no shebang here\n")
    inv = build_inventory(str(tmp_path), parallel=False)
    by_path = {f["path"]: f for f in inv["files"]}
    assert "libexec/raptor-thing" in by_path
    assert by_path["libexec/raptor-thing"]["language"] == "python"
    assert any(i["name"] == "main" for i in by_path["libexec/raptor-thing"]["items"])
    assert "notes" not in by_path


# ----------------------------------------------------------- target-kind walk

def test_version_suffixed_dir_manifest_ignored(tmp_path):
    _write(tmp_path, "ansi-regex-6.0.0/package.json",
           json.dumps({"name": "ansi-regex", "main": "index.js"}))
    kind, reason = detect_target_kind(str(tmp_path))
    assert kind == "unknown"
    assert "ansi-regex" not in reason


def test_root_manifest_outranks_nested(tmp_path):
    # Root manifest says bin-only CLI (application); a nested sub-package
    # says library. The scan root defines the project.
    _write(tmp_path, "package.json",
           json.dumps({"name": "app", "bin": {"app": "cli.js"}}))
    _write(tmp_path, "corpus/package.json",
           json.dumps({"name": "dep", "main": "index.js"}))
    kind, reason = detect_target_kind(str(tmp_path))
    assert kind == "application"
    assert "corpus" not in reason
