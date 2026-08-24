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
    headless = _find_headless()

    if output_gpr.name != gpr_path.name:
        raise GhidraError(
            f"output_gpr must keep the source project name "
            f"({gpr_path.name!r}); analyzeHeadless opens the project "
            f"by its on-disk name and would not find "
            f"{output_gpr.name!r}"
        )

    dst_dir = output_gpr.parent
    dst_name = output_gpr.stem

    # The bridge's export_enrichments prepares the copy itself before
    # writing the enrichments JSON next to it — only copy here when
    # called standalone.
    if not output_gpr.exists():
        prepare_working_copy(gpr_path, dst_dir)

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
