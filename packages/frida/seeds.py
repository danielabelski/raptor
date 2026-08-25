"""Distill seed-harvest events into a fuzz-ready seed corpus.

The ``seed-harvest`` template emits one ``category=ingest`` event per
unique input buffer the target received, with the bytes hex-encoded in
``args.data_hex``. This module decodes those events into individual
seed files that ``raptor fuzz --corpus <dir>`` (and any other AFL++
consumer) can use directly: one regular file per unique payload, no
non-seed files inside the corpus directory.

The manifest is written NEXT TO the seeds directory, never inside it -
AFL++ treats every top-level regular file in an input directory as a
seed, and a stray ``manifest.json`` would enter the fuzz corpus.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from . import parse_events

__all__ = ["extract_seeds"]

# Single-seed cap after hex-decode. The template already caps captures
# at 8 KiB; this guards against oversized payloads in hand-written
# scripts that reuse the data_hex convention.
_MAX_SEED_BYTES = 1 << 20


def extract_seeds(
    run_dir: Path | str,
    out_dir: Path | str | None = None,
    *,
    max_seeds: int = 512,
) -> dict[str, Any]:
    """Extract unique ingest payloads from a frida run into seed files.

    Reads ``<run_dir>/events.jsonl``, decodes every ``args.data_hex``
    payload, deduplicates by sha256, and writes up to *max_seeds* files
    named ``seed-<sha256[:12]>`` into *out_dir* (default:
    ``<run_dir>/seeds``). A ``<out_dir name>-manifest.json`` sibling
    records counts per hooked function plus how many payloads were
    duplicates, dropped over the cap, malformed, or oversized -
    no class of drop is silent.

    Returns the manifest dict. When the run has no decodable payloads,
    returns ``{"seed_count": 0, ...}`` without creating any files.
    """
    run_dir = Path(run_dir)
    out = Path(out_dir) if out_dir else run_dir / "seeds"
    # events.jsonl content is attacker-influenced; never write seeds
    # through a pre-planted symlink.
    if out.is_symlink():
        msg = f"refusing to write seeds through a symlinked directory: {out}"
        raise ValueError(msg)

    seen: set[str] = set()
    by_fn: dict[str, int] = {}
    duplicates = 0
    dropped_over_cap = 0
    skipped_malformed = 0
    skipped_oversized = 0
    written = 0

    for record in parse_events(run_dir / "events.jsonl"):
        if record.get("type") != "send":
            continue
        payload = record.get("payload")
        if not isinstance(payload, dict):
            continue
        args = payload.get("args")
        if not isinstance(args, dict):
            continue
        data_hex = args.get("data_hex")
        if not isinstance(data_hex, str) or not data_hex:
            continue
        # Size gate BEFORE decoding: events are attacker-influenced,
        # and hex-decoding a multi-GB line would spike host memory.
        if len(data_hex) > 2 * _MAX_SEED_BYTES:
            skipped_oversized += 1
            continue
        try:
            data = bytes.fromhex(data_hex)
        except ValueError:
            skipped_malformed += 1
            continue
        if not data:
            skipped_malformed += 1
            continue

        digest = hashlib.sha256(data).hexdigest()
        if digest in seen:
            duplicates += 1
            continue
        seen.add(digest)
        if written >= max_seeds:
            dropped_over_cap += 1
            continue

        out.mkdir(parents=True, exist_ok=True)
        (out / f"seed-{digest[:12]}").write_bytes(data)
        written += 1
        fn = payload.get("fn")
        if isinstance(fn, str) and fn:
            by_fn[fn] = by_fn.get(fn, 0) + 1

    manifest: dict[str, Any] = {
        "seed_count": written,
        "duplicates": duplicates,
        "dropped_over_cap": dropped_over_cap,
        "skipped_malformed": skipped_malformed,
        "skipped_oversized": skipped_oversized,
        "by_fn": by_fn,
        "out_dir": str(out),
    }
    if written:
        from core.json import save_json

        save_json(out.parent / f"{out.name}-manifest.json", manifest)
    return manifest
