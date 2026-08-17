"""Build-ID-keyed binary analysis cache.

Caches binary analysis artifacts by ELF build-ID so a binary need not
be analysed twice across /understand, /audit, and /validate runs.
Build-ID change automatically invalidates.

NOTE: not yet wired into any production flow — binary_bridge's
load_binary_bridge accepts a ``build_id_cache`` parameter that no
caller currently passes, so nothing reads or populates this cache
outside tests. Wire it up (or consume load_build_id_cache() directly)
before relying on the no-reanalysis behaviour.

Cache structure:
    {cache_dir}/{build_id}/
        metadata.json       — ELF headers, security posture
        symbols.json        — imports, exports
        strings.json        — classified strings
        dwarf.json          — types, signatures (if present)
        layer0-findings.json — vulnerability patterns
        feasibility.json    — analyze_binary() output
        edges.json          — call-graph edges
        oracle-verdicts.json — per-function verdicts
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DEFAULT_CACHE_DIR = ".cache/binary"

def _valid_build_id(build_id: str) -> bool:
    """Hex-only build IDs — anything else could escape cache_dir when
    joined into an on-disk path (e.g. ``../../``)."""
    return bool(re.match(r"^[0-9a-fA-F]+$", build_id or ""))


_KNOWN_ARTIFACTS = frozenset({
    "metadata",
    "symbols",
    "strings",
    "dwarf",
    "layer0-findings",
    "feasibility",
    "edges",
    "oracle-verdicts",
})


@dataclass
class CacheEntry:
    """A cached binary analysis artifact."""

    build_id: str
    artifact: str
    data: Dict[str, Any]
    source_command: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "build_id": self.build_id,
            "artifact": self.artifact,
            "source_command": self.source_command,
            "data": self.data,
        }


@dataclass
class BuildIDCache:
    """Persistent binary analysis cache keyed by build-ID."""

    cache_dir: Path
    _index: Dict[str, Dict[str, Path]] = field(default_factory=dict)

    def has(self, build_id: str, artifact: str) -> bool:
        if not _valid_build_id(build_id):
            return False
        path = self._artifact_path(build_id, artifact)
        return path.is_file()

    def get(self, build_id: str, artifact: str) -> Optional[Dict[str, Any]]:
        """Read a cached entry.

        Returns the on-disk envelope written by put() — the dict
        ``{"build_id", "artifact", "source_command", "data"}`` — NOT
        the bare artifact payload. Consumers read ``entry["data"]``.
        """
        if not _valid_build_id(build_id):
            return None
        path = self._artifact_path(build_id, artifact)
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text())
        except Exception:
            logger.debug("failed to read cache %s", path, exc_info=True)
            return None

    def put(
        self,
        build_id: str,
        artifact: str,
        data: Dict[str, Any],
        source_command: str = "",
    ) -> Optional[Path]:
        """Write an artifact envelope; returns the path, or None when
        the build_id is rejected (non-hex — could otherwise traverse
        outside cache_dir via a crafted id)."""
        if not _valid_build_id(build_id):
            logger.warning(
                "build-ID cache: rejected invalid build_id %r (artifact %s)",
                build_id, artifact,
            )
            return None
        entry_dir = self.cache_dir / build_id
        entry_dir.mkdir(parents=True, exist_ok=True)

        path = entry_dir / f"{artifact}.json"
        wrapped = {
            "build_id": build_id,
            "artifact": artifact,
            "source_command": source_command,
            "data": data,
        }

        fd, tmp = tempfile.mkstemp(dir=str(entry_dir), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(wrapped, f, indent=2)
            os.replace(tmp, str(path))
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

        return path

    def available_artifacts(self, build_id: str) -> List[str]:
        entry_dir = self.cache_dir / build_id
        if not entry_dir.is_dir():
            return []
        artifacts = []
        for path in entry_dir.iterdir():
            if path.suffix == ".json":
                artifacts.append(path.stem)
        return sorted(artifacts)

    def evict(self, build_id: str) -> int:
        entry_dir = self.cache_dir / build_id
        if not entry_dir.is_dir():
            return 0
        count = 0
        for path in entry_dir.iterdir():
            try:
                path.unlink()
                count += 1
            except OSError:
                pass
        try:
            entry_dir.rmdir()
        except OSError:
            pass
        return count

    def summary(self) -> str:
        if not self.cache_dir.is_dir():
            return "Build-ID cache: empty"
        build_ids = [
            d.name for d in self.cache_dir.iterdir()
            if d.is_dir()
        ]
        if not build_ids:
            return "Build-ID cache: empty"
        total_artifacts = sum(
            len(self.available_artifacts(bid)) for bid in build_ids
        )
        return (
            f"Build-ID cache: {len(build_ids)} binaries, "
            f"{total_artifacts} artifacts"
        )

    def _artifact_path(self, build_id: str, artifact: str) -> Path:
        return self.cache_dir / build_id / f"{artifact}.json"


def load_build_id_cache(
    cache_dir: Optional[Path] = None,
) -> BuildIDCache:
    if cache_dir is None:
        cache_dir = Path(os.environ["RAPTOR_DIR"]) / _DEFAULT_CACHE_DIR
    return BuildIDCache(cache_dir=cache_dir)


def extract_build_id(binary_path: Path) -> Optional[str]:
    """Extract ELF build-ID from a binary using readelf (sandboxed)."""
    if not binary_path.is_file():
        return None
    try:
        from core.sandbox.context import run_trusted
        result = run_trusted(
            ["readelf", "-n", str(binary_path)],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            if "Build ID:" in line:
                return line.split("Build ID:")[-1].strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ImportError):
        pass
    return None


def import_validate_evidence(
    cache: BuildIDCache,
    build_id: str,
) -> Optional[Dict[str, Any]]:
    """Import /validate Stage E feasibility results from the cache.

    Returns the cache envelope (see BuildIDCache.get — feasibility
    payload under ``["data"]``) if cached, None otherwise.
    """
    return cache.get(build_id, "feasibility")


def import_layer0_findings(
    cache: BuildIDCache,
    build_id: str,
) -> Optional[Dict[str, Any]]:
    """Import Layer 0 findings from the cache.

    Returns the cache envelope (findings payload under ``["data"]``)
    if cached, None otherwise.
    """
    return cache.get(build_id, "layer0-findings")
