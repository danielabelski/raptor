"""Tests for core.env.build — containerized build + artifact extraction.

Hermetic: build_image / export_rootfs / remove_labeled_images are
patched; the "exported rootfs" is planted on disk. The live path is
covered by the S5.3 smoke (a real make target through docker).
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import patch

from core.env.build import (
    HARDENED_TOOLCHAIN,
    SOFT_TOOLCHAIN,
    _elf_executables,
    _flag_prefix,
    containerized_build,
)
from core.env.spec import ToolchainSpec


def _plant_elf(path, executable=True):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x7fELF" + b"\x00" * 12)
    if executable:
        os.chmod(path, 0o755)


class TestElfScan:
    def test_finds_executable_elfs_only(self, tmp_path):
        _plant_elf(tmp_path / "app")
        _plant_elf(tmp_path / "build" / "tool")
        _plant_elf(tmp_path / "not-exec", executable=False)
        (tmp_path / "script.sh").write_text("#!/bin/sh\n")
        os.chmod(tmp_path / "script.sh", 0o755)
        found = _elf_executables(tmp_path)
        assert set(found) == {"app", "build/tool"}

    def test_missing_root_is_empty(self, tmp_path):
        assert _elf_executables(tmp_path / "nope") == {}


class TestFlagPrefix:
    def test_none_is_empty(self):
        assert _flag_prefix(None) == ""

    def test_hardened_flags_injected(self):
        prefix = _flag_prefix(HARDENED_TOOLCHAIN)
        assert "-fstack-protector-strong" in prefix
        assert "-Wl,-z,relro,-z,now" in prefix
        assert prefix.startswith("CFLAGS=")

    def test_soft_flags_injected(self):
        prefix = _flag_prefix(SOFT_TOOLCHAIN)
        assert "-fno-stack-protector" in prefix
        assert "-Wl,-z,norelro" in prefix

    def test_debug_appends_g_once(self):
        tc = ToolchainSpec(cflags=("-O0",), debug=True)
        prefix = _flag_prefix(tc)
        assert prefix.count("-g") == 2  # CFLAGS and CXXFLAGS
        assert "CFLAGS='-O0 -g'" in prefix


def _fake_container_layer(rootfs_planter=None, build_ok=True):
    """Patch the three container seams; return the patch context list."""
    def fake_build_image(*, context_dir, tag, dockerfile_text, **kw):
        from pathlib import Path as _P
        fake_build_image.dockerfile = dockerfile_text
        fake_build_image.kwargs = kw
        # The context is a TemporaryDirectory gone by assertion time —
        # record what matters while it exists.
        fake_build_image.context_had_repo = (
            _P(context_dir) / "src" / "Makefile").is_file()
        return SimpleNamespace(ok=build_ok, stderr_tail="boom" if not build_ok else "")

    def fake_export_rootfs(image_ref, dest_dir, **kw):
        if rootfs_planter:
            rootfs_planter(dest_dir)
        return SimpleNamespace(ok=True)

    return [
        patch("core.container.build.build_image", fake_build_image),
        patch("core.container.export.export_rootfs", fake_export_rootfs),
        patch("core.container.lifecycle.remove_labeled_images",
              lambda *a, **k: None),
        patch("core.container.lifecycle.prune_labeled_dangling",
              lambda *a, **k: True),
    ], fake_build_image


class TestContainerizedBuild:
    def _repo(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "Makefile").write_text("all:\n\tcc -o app main.c\n")
        (repo / "main.c").write_text("int main(void){return 0;}\n")
        return repo

    def test_success_extracts_artifacts(self, tmp_path):
        from pathlib import Path

        def planter(dest):
            _plant_elf(Path(dest) / "src" / "app")

        patches, fake_build = _fake_container_layer(planter)
        with patches[0], patches[1], patches[2], patches[3]:
            product = containerized_build(
                self._repo(tmp_path), "make",
                out_dir=tmp_path / "out")
        assert product.ok
        assert list(product.artifacts) == ["app"]
        assert product.artifacts["app"].is_file()
        assert "RUN make" in fake_build.dockerfile
        # the repo was copied into the context (not built in place)
        assert fake_build.context_had_repo

    def test_toolchain_flags_reach_the_run_line(self, tmp_path):
        patches, fake_build = _fake_container_layer(
            lambda d: _plant_elf(__import__("pathlib").Path(d) / "src" / "a"))
        with patches[0], patches[1], patches[2], patches[3]:
            containerized_build(
                self._repo(tmp_path), "make",
                out_dir=tmp_path / "out", toolchain=HARDENED_TOOLCHAIN)
        assert "RUN CFLAGS='" in fake_build.dockerfile
        assert "-fstack-protector-strong" in fake_build.dockerfile

    def test_build_failure_is_structured(self, tmp_path):
        patches, _ = _fake_container_layer(build_ok=False)
        with patches[0], patches[1], patches[2], patches[3]:
            product = containerized_build(
                self._repo(tmp_path), "make", out_dir=tmp_path / "out")
        assert not product.ok
        assert product.reason == "build_failed"
        assert "boom" in product.detail

    def test_no_artifacts_is_structured(self, tmp_path):
        patches, _ = _fake_container_layer(lambda d: None)
        with patches[0], patches[1], patches[2], patches[3]:
            product = containerized_build(
                self._repo(tmp_path), "make", out_dir=tmp_path / "out")
        assert not product.ok
        assert product.reason == "no_artifacts"

    def test_copy_failure_is_structured(self, tmp_path):
        patches, _ = _fake_container_layer()
        with patches[0], patches[1], patches[2], patches[3]:
            product = containerized_build(
                tmp_path / "does-not-exist", "make",
                out_dir=tmp_path / "out")
        assert not product.ok
        assert product.reason == "copy_failed"


class TestSecurityHardening:
    def _repo(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "Makefile").write_text("all:\n\tcc -o app main.c\n")
        (repo / "main.c").write_text("int main(void){return 0;}\n")
        return repo

    def test_untrusted_build_gets_no_network(self, tmp_path):
        """Adversarial-review finding: consent-to-build is not consent
        to egress — the RUN step must be network-isolated."""
        patches, fake_build = _fake_container_layer(
            lambda d: _plant_elf(__import__("pathlib").Path(d) / "src" / "a"))
        with patches[0], patches[1], patches[2], patches[3]:
            containerized_build(self._repo(tmp_path), "make",
                                out_dir=tmp_path / "out")
        assert fake_build.kwargs.get("network") == "none"

    def test_extracted_artifacts_lose_exec_and_setuid(self, tmp_path):
        from pathlib import Path as _P

        def planter(dest):
            target = _P(dest) / "src" / "app"
            _plant_elf(target)
            os.chmod(target, 0o4755)  # setuid + exec from the attacker

        patches, _ = _fake_container_layer(planter)
        with patches[0], patches[1], patches[2], patches[3]:
            product = containerized_build(self._repo(tmp_path), "make",
                                          out_dir=tmp_path / "out")
        mode = product.artifacts["app"].stat().st_mode & 0o7777
        assert mode == 0o444

    def test_dest_collision_disambiguated(self, tmp_path):
        from pathlib import Path as _P

        def planter(dest):
            _plant_elf(_P(dest) / "src" / "a" / "b")
            _plant_elf(_P(dest) / "src" / "a__b")

        patches, _ = _fake_container_layer(planter)
        with patches[0], patches[1], patches[2], patches[3]:
            product = containerized_build(self._repo(tmp_path), "make",
                                          out_dir=tmp_path / "out")
        paths = {str(p) for p in product.artifacts.values()}
        assert len(paths) == 2, "colliding rels must map to distinct files"

    def test_cleanup_runs_on_build_failure(self, tmp_path):
        from unittest.mock import MagicMock
        removed = MagicMock()
        patches, _ = _fake_container_layer(build_ok=False)
        with patches[0], patches[1], patches[3], \
             patch("core.container.lifecycle.remove_labeled_images",
                   removed):
            containerized_build(self._repo(tmp_path), "make",
                                out_dir=tmp_path / "out")
        removed.assert_called_once()
        assert removed.call_args.kwargs.get("tag_repo") == \
            "raptor-env-build"


class TestCacheAndProvenanceHardening:
    def _repo(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "Makefile").write_text("all:\n\tcc -o app main.c\n")
        (repo / "main.c").write_text("int main(void){return 0;}\n")
        return repo

    def test_label_is_first_dockerfile_instruction(self, tmp_path):
        """Intermediate step images inherit config from their parent —
        LABEL-first is what scopes the dangling-cache prune."""
        patches, fake_build = _fake_container_layer(
            lambda d: _plant_elf(__import__("pathlib").Path(d) / "src" / "a"))
        with patches[0], patches[1], patches[2], patches[3]:
            containerized_build(self._repo(tmp_path), "make",
                                out_dir=tmp_path / "out")
        lines = fake_build.dockerfile.splitlines()
        assert lines[0].startswith("FROM ")
        assert lines[1].startswith("LABEL raptor-env-build.id=")

    def test_force_rm_requested(self, tmp_path):
        patches, fake_build = _fake_container_layer(
            lambda d: _plant_elf(__import__("pathlib").Path(d) / "src" / "a"))
        with patches[0], patches[1], patches[2], patches[3]:
            containerized_build(self._repo(tmp_path), "make",
                                out_dir=tmp_path / "out")
        assert fake_build.kwargs.get("force_rm") is True

    def test_dangling_prune_runs_on_failure_paths(self, tmp_path):
        from unittest.mock import MagicMock
        pruned = MagicMock(return_value=True)
        patches, _ = _fake_container_layer(build_ok=False)
        with patches[0], patches[1], patches[2], \
             patch("core.container.lifecycle.prune_labeled_dangling",
                   pruned):
            containerized_build(self._repo(tmp_path), "make",
                                out_dir=tmp_path / "out")
        pruned.assert_called_once()

    def test_checksums_recorded(self, tmp_path):
        from pathlib import Path as _P

        def planter(dest):
            _plant_elf(_P(dest) / "src" / "app")

        patches, _ = _fake_container_layer(planter)
        with patches[0], patches[1], patches[2], patches[3]:
            product = containerized_build(self._repo(tmp_path), "make",
                                          out_dir=tmp_path / "out")
        assert len(product.checksums["app"]) == 64
