"""Wrapper for Ghidra's ``analyzeHeadless`` command."""

from __future__ import annotations

import getpass
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from .detect import get_project_dir, get_project_name
from .export_script_java import EXPORT_SCRIPT_JAVA
from .project_util import prepare_working_copy

logger = logging.getLogger(__name__)


class GhidraError(Exception):
    """Raised when a Ghidra headless operation fails."""


def _find_headless() -> str:
    """Locate ``analyzeHeadless`` on PATH.  Raises GhidraError if absent."""
    binary = shutil.which("analyzeHeadless")
    if not binary:
        raise GhidraError(
            "analyzeHeadless not found on PATH — install Ghidra and "
            "ensure analyzeHeadless is accessible"
        )
    return binary


def _safe_env() -> dict:
    """Build a sanitised environment for the analyzeHeadless subprocess.

    Sets ``GHIDRA_HEADLESS_MAXMEM`` to 4G if not already set — the
    default 2G is tight for large binaries with decompilation.
    Falls back to ``os.environ.copy()`` if ``RaptorConfig`` isn't available.
    """
    try:
        from core.config import RaptorConfig
        env = RaptorConfig.get_safe_env()
    except Exception:
        # Fail closed: a minimal PATH-only environment. Passing the
        # full caller environment here would hand API keys to a JVM
        # that parses attacker-controlled data (and would falsify the
        # env_caller_filtered=True assertion at the sandbox call).
        import os
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    env.setdefault("GHIDRA_HEADLESS_MAXMEM", "4G")
    return env


def _install_read_paths(headless: str) -> list:
    """Read-allowlist extras for the sandboxed JVM.

    With ``restrict_reads`` the sandbox allows system dirs, /tmp,
    target, and output only — the Ghidra install tree (often under
    $HOME) must be granted explicitly. Resolves through the
    ``analyzeHeadless`` symlink to the install root (the wrapper
    lives in ``<install>/support/``).
    """
    real = Path(headless).resolve()
    paths = [str(real.parent.parent)]
    import os
    install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if install_dir and str(Path(install_dir).resolve()) not in paths:
        paths.append(str(Path(install_dir).resolve()))
    return paths


def export_project(
    gpr_path: Path,
    output_path: Path,
    *,
    program_name: Optional[str] = None,
    decompile: bool = False,
    timeout: int = 300,
) -> Path:
    """Export a Ghidra project to RAPTOR's JSON format.

    Runs ``analyzeHeadless`` with the Java export script against the
    specified project.  Writes the result to *output_path*.

    Args:
        gpr_path: Path to the ``.gpr`` file.
        output_path: Where to write the exported JSON.
        program_name: Specific program within the project to export.
            If None, processes the default (first) program.
        decompile: If True, decompile every function (slow).
            Default False — import metadata only.
        timeout: Maximum seconds for the headless process.

    Returns:
        The output path (same as *output_path*).

    Raises:
        GhidraError: If Ghidra is not installed or the export fails.
    """
    headless = _find_headless()
    project_name_str = get_project_name(gpr_path)

    process_args = ["-process", program_name] if program_name else ["-process"]

    env = _safe_env()

    with tempfile.TemporaryDirectory(prefix="raptor-ghidra-") as work_dir:
        work_path = Path(work_dir)

        work_gpr = prepare_working_copy(gpr_path, work_path)
        work_project_dir = str(get_project_dir(work_gpr))
        # Ghidra's launcher demands a writable user home (launch
        # prefs, JDK detection cache). $HOME alone is not enough: the
        # JDK derives user.home from the passwd entry, and inside the
        # sandbox user namespace the uid maps to nobody (Debian home
        # /nonexistent). JAVA_TOOL_OPTIONS reaches every JVM the
        # launcher spawns.
        env = dict(
            env,
            HOME=str(work_path),
            XDG_CONFIG_HOME=str(work_path / ".config"),
            XDG_CACHE_HOME=str(work_path / ".cache"),
            JAVA_TOOL_OPTIONS=(
                env.get("JAVA_TOOL_OPTIONS", "")
                + f" -Duser.home={work_path}"
                # prepare_working_copy stamps the project OWNER to
                # the invoking OS user; inside the sandbox user
                # namespace the JVM's passwd-derived user.name is
                # nobody, so force it back to the stamped owner or
                # Ghidra refuses the project (NotOwnerException).
                + f" -Duser.name={getpass.getuser()}"
            ).strip(),
        )

        script_dir = work_path / "scripts"
        script_dir.mkdir()
        (script_dir / "ExportRaptor.java").write_text(EXPORT_SCRIPT_JAVA, encoding="utf-8")

        script_args = [str(output_path)]
        if decompile:
            script_args.append("decomp")

        cmd = [
            headless,
            work_project_dir,
            project_name_str,
            *process_args,
            "-noanalysis",
            "-scriptPath", str(script_dir),
            "-postScript", "ExportRaptor.java", *script_args,
        ]

        logger.info("running: %s", " ".join(cmd))

        try:
            # Repo convention for binary-touching tools (see the
            # binary-oracle's r2/binutils invocations): the JVM
            # analyses an ATTACKER-SUPPLIED binary, so it runs
            # sandboxed — network denied, writes scoped to the
            # working copy + export output.
            from core.sandbox import run as _sandbox_run
            result = _sandbox_run(
                cmd,
                block_network=True,
                target=str(work_path),
                output=str(output_path.parent),
                # The JVM parses attacker-controlled project data —
                # deny reads outside system dirs + the working copy +
                # the Ghidra install tree ($HOME stays invisible).
                restrict_reads=True,
                readable_paths=_install_read_paths(headless),
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                # env comes from RaptorConfig.get_safe_env() above —
                # already allowlist-filtered upstream.
                env_caller_filtered=True,
            )
        except subprocess.TimeoutExpired:
            raise GhidraError(
                f"analyzeHeadless timed out after {timeout}s — "
                f"consider increasing timeout for large projects"
            )
        except OSError as e:
            raise GhidraError(f"failed to run analyzeHeadless: {e}")

    if result.returncode != 0:
        stderr_tail = result.stderr[-500:] if result.stderr else "(no stderr)"
        stdout_tail = result.stdout[-1000:] if result.stdout else ""
        raise GhidraError(
            f"analyzeHeadless exited {result.returncode}:\n{stderr_tail}"
            + (f"\n--- stdout ---\n{stdout_tail}" if stdout_tail else "")
        )

    if not output_path.exists():
        raise GhidraError(
            f"analyzeHeadless completed but output file not created at "
            f"{output_path} — check Ghidra script output:\n"
            f"{result.stdout[-500:]}"
        )

    return output_path


def import_enrichments(
    gpr_path: Path,
    enrichments_path: Path,
    output_gpr: Path,
    *,
    program_name: Optional[str] = None,
    copy_prepared: bool = False,
    timeout: int = 300,
) -> Path:
    """Apply RAPTOR enrichments back to a Ghidra project.

    Copies the original project to *output_gpr* and runs
    ``analyzeHeadless`` with the import script to apply findings.

    Args:
        gpr_path: Path to the original ``.gpr`` file.
        enrichments_path: JSON file with RAPTOR findings to import.
        output_gpr: Where to write the enriched ``.gpr`` copy.
        timeout: Maximum seconds for the headless process.

    Returns:
        The output ``.gpr`` path.

    Raises:
        GhidraError: If Ghidra is not installed or the import fails.
    """
    if output_gpr.name != gpr_path.name:
        raise GhidraError(
            f"output_gpr must keep the source project name "
            f"({gpr_path.name!r}); analyzeHeadless opens the project "
            f"by its on-disk name and would not find "
            f"{output_gpr.name!r}"
        )

    dst_dir = output_gpr.parent
    dst_name = output_gpr.stem

    # Explicit contract instead of inferring from destination
    # existence (a pre-placed copy would otherwise be silently
    # trusted): the bridge sets copy_prepared=True after preparing
    # the copy itself; standalone callers get a fresh copy here and
    # a refusal if something already occupies the destination.
    if copy_prepared:
        if not output_gpr.exists():
            raise GhidraError(
                f"copy_prepared=True but no working copy at "
                f"{output_gpr}"
            )
    else:
        if output_gpr.exists():
            raise GhidraError(
                f"destination already exists: {output_gpr} — remove "
                "it or pass copy_prepared=True if it is a working "
                "copy you just prepared"
            )
        prepare_working_copy(gpr_path, dst_dir)

    headless = _find_headless()
    env = _safe_env()

    from .import_script_java import IMPORT_SCRIPT_JAVA
    with tempfile.TemporaryDirectory(prefix="raptor-ghidra-import-") as script_dir:
        script_path = Path(script_dir) / "ImportRaptor.java"
        script_path.write_text(IMPORT_SCRIPT_JAVA, encoding="utf-8")
        # Writable user home for the JVM launcher (see export_project
        # for the passwd-derivation rationale).
        env = dict(
            env,
            HOME=str(script_dir),
            XDG_CONFIG_HOME=str(Path(script_dir) / ".config"),
            XDG_CACHE_HOME=str(Path(script_dir) / ".cache"),
            JAVA_TOOL_OPTIONS=(
                env.get("JAVA_TOOL_OPTIONS", "")
                + f" -Duser.home={script_dir}"
                + f" -Duser.name={getpass.getuser()}"
            ).strip(),
        )

        process_args = (
            ["-process", program_name] if program_name else ["-process"]
        )
        cmd = [
            headless,
            str(dst_dir),
            dst_name,
            *process_args,
            "-noanalysis",
            "-scriptPath", script_dir,
            "-postScript", "ImportRaptor.java", str(enrichments_path),
        ]

        logger.info("running: %s", " ".join(cmd))

        try:
            # Same sandbox posture as export_project: the JVM opens
            # attacker-influenced project data — network denied,
            # writes scoped to the destination copy + script dir.
            from core.sandbox import run as _sandbox_run
            result = _sandbox_run(
                cmd,
                block_network=True,
                target=str(dst_dir),
                # The destination copy is what analyzeHeadless saves
                # the enriched program into (plus its lock file) — it
                # must be the writable scope. The script dir is a
                # tempdir under /tmp, which is in the sandbox's
                # writable baseline.
                output=str(dst_dir),
                # Same read posture as export_project; the
                # enrichments JSON sits in dst_dir (bridge flow) or
                # must be readable via these scopes.
                restrict_reads=True,
                readable_paths=_install_read_paths(headless)
                + [str(enrichments_path.parent.resolve())],
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                # env comes from RaptorConfig.get_safe_env() above —
                # already allowlist-filtered upstream.
                env_caller_filtered=True,
            )
        except subprocess.TimeoutExpired:
            raise GhidraError(
                f"analyzeHeadless import timed out after {timeout}s"
            )
        except OSError as e:
            raise GhidraError(f"failed to run analyzeHeadless: {e}")

    if result.returncode != 0:
        stderr_tail = result.stderr[-500:] if result.stderr else "(no stderr)"
        raise GhidraError(
            f"analyzeHeadless import exited {result.returncode}:\n{stderr_tail}"
        )

    # Name-keyed entries resolve inside the script, so applied counts
    # can be lower than submitted — surface the script's own tally.
    for line in (result.stdout or "").splitlines():
        if "RAPTOR import:" in line:
            logger.info("%s", line.strip())
            break

    return output_gpr
