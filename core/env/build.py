"""Containerized repo builds with artifact extraction.

The build-on-demand seam for consumers that need a COMPILED artifact
from a source tree (/validate Stage E feasibility, the mitigation
matrix, future instrumented builds): copy the repo into a build
context, run the build command inside a container (build systems
execute repo-influenced code — the container IS the containment), and
extract the produced ELF executables from the image.

Failure posture: a build failure is a structured outcome, never an
exception — every consumer degrades to its no-binary behaviour with
the reason recorded. Complex projects whose dependencies the default
build image lacks simply fail here and the caller proceeds as today.

Hardening variants: the canonical mitigation-matrix postures are
expressed as :class:`~core.env.spec.ToolchainSpec` values whose flags
are injected via ``CFLAGS``/``CXXFLAGS``/``LDFLAGS`` prepended to the
build command — effective for well-behaved make/cmake builds; a build
that ignores the ambient flags produces a variant whose posture the
analyzer then measures as unchanged (the matrix reports what the
binary IS, not what we asked for).
"""

from __future__ import annotations

import logging
import shutil
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from core.env.spec import ToolchainSpec

logger = logging.getLogger(__name__)

#: Toolchain image for containerized builds: the official gcc image
#: carries gcc/g++/make. Callers override per call; no env knob.
#: Digest-pinned (tag kept for readability; the daemon resolves by
#: digest): a mutable tag can be force-repointed upstream, and the
#: build RUN step executes with the repo's code in context — the
#: supply-chain window is not worth the convenience.
DEFAULT_BUILD_IMAGE = (
    "gcc:13@sha256:"
    "056fa682471704249f619f65ccec87d671ad5f1b20878da54d60b0b863486621"
)

#: Ownership label for build-scoped images (mirrors provision()'s
#: exact-scope cleanup convention).
BUILD_LABEL = "raptor-env-build.id"

#: Canonical mitigation-matrix postures (design: exactly three — the
#: realistic extremes plus whatever the plain build produces).
HARDENED_TOOLCHAIN = ToolchainSpec(
    cflags=("-fstack-protector-strong", "-fPIE", "-D_FORTIFY_SOURCE=2",
            "-O1"),
    ldflags=("-Wl,-z,relro,-z,now", "-pie"),
)
SOFT_TOOLCHAIN = ToolchainSpec(
    cflags=("-fno-stack-protector", "-fno-pie", "-D_FORTIFY_SOURCE=0",
            "-O1"),
    ldflags=("-Wl,-z,norelro,-z,lazy", "-no-pie"),
)

#: AFL++ build image for instrumented fuzz builds (/fuzz env
#: build-on-demand). Pinned release tag: the SAME image supplies the
#: run-time afl-fuzz (its exported rootfs is the campaign substrate),
#: so compile-time and run-time AFL versions agree by construction.
AFL_BUILD_IMAGE = (
    "aflplusplus/aflplusplus:v5.02c@sha256:"
    "7c3c05e8471ac174327c303a3249c77bbe046d4fe2a458918704190fff64f52f"
)

#: Toolchain for AFL-instrumented builds: afl-clang-fast wraps the
#: image's clang and injects coverage instrumentation via CC/CXX —
#: effective for well-behaved make/cmake builds, same caveat as the
#: mitigation postures above.
AFL_TOOLCHAIN = ToolchainSpec(
    cc="afl-clang-fast",
    cxx="afl-clang-fast++",
    instrumentation=("afl",),
)

_ELF_MAGIC = b"\x7fELF"


@dataclass
class BuildProduct:
    """Outcome of one containerized build."""

    ok: bool
    reason: str = ""                 # "" | copy_failed | build_failed |
    #                                  export_failed | no_artifacts
    detail: str = ""
    artifacts: dict[str, Path] = field(default_factory=dict)
    #: relative-in-repo name -> extracted host path
    checksums: dict[str, str] = field(default_factory=dict)
    #: relative-in-repo name -> sha256 of the extracted bytes
    toolchain: ToolchainSpec | None = None
    base_image: str = DEFAULT_BUILD_IMAGE
    build_command: str = ""
    rootfs: Path | None = None
    #: populated only when the caller passed ``keep_rootfs``: the
    #: exported image filesystem (repo at ``/src``, built artifacts in
    #: place, toolchain runtime included) for ``sandbox(rootfs=...)``
    #: consumers. Large (the full flattened image); caller owns cleanup.


def containerized_build(
    repo_dir: Path | str,
    command: str,
    *,
    out_dir: Path | str,
    toolchain: ToolchainSpec | None = None,
    base_image: str = DEFAULT_BUILD_IMAGE,
    timeout_seconds: int = 600,
    keep_rootfs: Path | str | None = None,
) -> BuildProduct:
    """Build *repo_dir* with *command* in a container; extract ELF
    executables produced under the repo tree into ``out_dir``.

    ``keep_rootfs``: when set, the exported image filesystem is written
    there and survives the call (``product.rootfs``) for
    ``sandbox(rootfs=...)`` consumers — in-image fuzzing runs the built
    binary against the exact toolchain runtime that produced it. The
    directory is LARGE (the full flattened image, potentially millions
    of inodes): point it at disk-backed run storage, never a tmpfs,
    and delete it when the run is done. On any failure path the
    partial directory is removed.

    Never raises for build-class failures; see :class:`BuildProduct`.
    """
    try:
        product = _containerized_build(
            repo_dir, command, out_dir=out_dir, toolchain=toolchain,
            base_image=base_image, timeout_seconds=timeout_seconds,
            keep_rootfs=keep_rootfs,
        )
    except BaseException:
        if keep_rootfs:
            shutil.rmtree(keep_rootfs, ignore_errors=True)
        raise
    if keep_rootfs:
        if product.ok:
            product.rootfs = Path(keep_rootfs)
        else:
            # A failed build must not leave a multi-GB partial image
            # tree in the run directory.
            shutil.rmtree(keep_rootfs, ignore_errors=True)
    return product


def _containerized_build(
    repo_dir: Path | str,
    command: str,
    *,
    out_dir: Path | str,
    toolchain: ToolchainSpec | None,
    base_image: str,
    timeout_seconds: int,
    keep_rootfs: Path | str | None,
) -> BuildProduct:
    from core.container.build import build_image
    from core.container.export import export_rootfs
    from core.container.lifecycle import (
        prune_labeled_dangling,
        remove_labeled_images,
    )

    repo = Path(repo_dir)
    out = Path(out_dir)
    build_id = uuid.uuid4().hex[:12]
    tag = f"raptor-env-build:{build_id}"
    product = BuildProduct(ok=False, toolchain=toolchain,
                           base_image=base_image, build_command=command)

    with tempfile.TemporaryDirectory(prefix="raptor-env-build-") as tmp:
        ctx = Path(tmp) / "context"
        try:
            shutil.copytree(
                repo, ctx / "src",
                ignore=shutil.ignore_patterns(".git"),
                symlinks=True,
            )
        except OSError as exc:
            product.reason, product.detail = "copy_failed", str(exc)[:500]
            return product

        # LABEL is the FIRST instruction so every intermediate step
        # image the legacy builder commits inherits it — that is what
        # scopes the dangling-cache prune below to exactly this build.
        dockerfile = (
            f"FROM {base_image}\n"
            f"LABEL {BUILD_LABEL}={build_id}\n"
            f"COPY src /src\n"
            f"WORKDIR /src\n"
            f"RUN {_flag_prefix(toolchain)}{command}\n"
        )
        try:
            built = build_image(
                context_dir=str(ctx), tag=tag, dockerfile_text=dockerfile,
                timeout_seconds=timeout_seconds,
                labels={BUILD_LABEL: build_id},
                # The RUN step executes the UNTRUSTED build system:
                # consent-to-build is not consent to egress (metadata
                # credential theft, bridge pivot, exfiltration).
                # Dependency-fetching builds fail here and take the
                # documented degrade path.
                network="none",
                force_rm=True,
            )
            if not built.ok:
                product.reason = "build_failed"
                product.detail = (built.stderr_tail or "")[-1000:]
                return product

            rootfs = Path(keep_rootfs) if keep_rootfs else Path(tmp) / "rootfs"
            exported = export_rootfs(tag, rootfs)
            if not getattr(exported, "ok", True):
                product.reason = "export_failed"
                product.detail = str(
                    getattr(exported, "detail", ""))[:500]
                return product

            out.mkdir(parents=True, exist_ok=True)
            for rel, src in _elf_executables(rootfs / "src").items():
                dest = out / _dest_name(rel, out)
                shutil.copy2(src, dest)
                # Strip execute/setuid/setgid: the bytes came from the
                # attacker's build; analysis needs content, never an
                # executable (let alone setuid) file in the run dir.
                dest.chmod(0o444)
                product.artifacts[rel] = dest
                product.checksums[rel] = _sha256(dest)
        except OSError as exc:
            product.reason, product.detail = "export_failed", str(exc)[:500]
            return product
        finally:
            # Exact-scope cleanup on EVERY path (a failed or timed-out
            # client can still leave a daemon-side tagged image; the
            # tag kill-path covers label-less leftovers). The image is
            # a means, not a product.
            remove_labeled_images(BUILD_LABEL, build_id,
                                  tag_repo="raptor-env-build",
                                  tag_value=build_id)
            # Then the dangling residue: failed/superseded step layers
            # are untagged cache images (label-inherited via the
            # LABEL-first Dockerfile) that remove_labeled_images
            # deliberately skips. Scoped prune — a hostile build's
            # disk burst is reclaimed at run end; the burst DURING the
            # 600s build window remains unbounded (daemon-level quota
            # territory, documented).
            prune_labeled_dangling(BUILD_LABEL, build_id)

    if not product.artifacts:
        product.reason = "no_artifacts"
        product.detail = "build succeeded but produced no ELF executables"
        return product
    product.ok = True
    return product


def _sha256(path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _dest_name(rel: str, out: Path) -> str:
    """Flatten a repo-relative path into a unique extraction file name.

    ``a/b`` and a literal ``a__b`` must not collide (an attacker-
    authored tree could otherwise steer which binary survives to be
    analysed): suffix an index until the name is free.
    """
    base = rel.replace("/", "__")
    name, i = base, 1
    while (out / name).exists():
        name = f"{base}.{i}"
        i += 1
    return name


def _flag_prefix(toolchain: ToolchainSpec | None) -> str:
    """Ambient-flag env prefix for the RUN line (empty when None)."""
    if toolchain is None:
        return ""
    cflag_list = list(toolchain.cflags)
    if toolchain.debug and "-g" not in cflag_list:
        cflag_list.append("-g")
    cflags = " ".join(cflag_list)
    ldflags = " ".join(toolchain.ldflags)
    parts = []
    if toolchain.cc:
        parts.append(f"CC='{toolchain.cc}'")
    if toolchain.cxx:
        parts.append(f"CXX='{toolchain.cxx}'")
    if cflags:
        parts.append(f"CFLAGS='{cflags}' CXXFLAGS='{cflags}'")
    if ldflags:
        parts.append(f"LDFLAGS='{ldflags}'")
    return (" ".join(parts) + " ") if parts else ""


def _elf_executables(root: Path) -> dict[str, Path]:
    """ELF executables under *root*, keyed by repo-relative path."""
    found: dict[str, Path] = {}
    if not root.is_dir():
        return found
    for path in sorted(root.rglob("*")):
        try:
            if not path.is_file() or path.is_symlink():
                continue
            if not path.stat().st_mode & 0o111:
                continue
            with path.open("rb") as fh:
                if fh.read(4) != _ELF_MAGIC:
                    continue
        except OSError:
            continue
        found[str(path.relative_to(root))] = path
    return found
