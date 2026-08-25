"""Tests for the seed-harvest pipeline: template rendering, event
distillation into seed files, and the CLI auto-harvest hook."""

from __future__ import annotations

import json
from pathlib import Path

from packages.frida import cli
from packages.frida.runner import load_script_source
from packages.frida.seeds import extract_seeds


def _write_events(run_dir: Path, payloads: list[dict]) -> None:
    lines = [
        json.dumps({"ts": 1.0, "type": "send", "payload": p})
        for p in payloads
    ]
    (run_dir / "events.jsonl").write_text(
        "\n".join(lines) + "\n", encoding="utf-8")


def _ingest(fn: str, data: bytes) -> dict:
    return {
        "category": "ingest",
        "fn": fn,
        "args": {"len": len(data), "captured": len(data),
                 "data_hex": data.hex()},
        "tid": 1,
    }


class TestSeedHarvestTemplate:
    def test_template_renders_taxonomy_slot(self):
        source, origin = load_script_source("seed-harvest", None)
        assert origin == "template:seed-harvest"
        # The slot must be rendered away and carry taxonomy vocabulary.
        assert "/*__INGEST_HOOKS__*/ []" not in source
        assert '"recv"' in source
        assert '"SSL_read"' in source

    def test_unrendered_template_is_self_contained(self):
        tpl = (Path(__file__).resolve().parents[1]
               / "templates" / "seed-harvest.js")
        text = tpl.read_text(encoding="utf-8")
        # Unrendered slot stays valid JS (empty list), and the ubiquitous
        # input paths are hooked locally rather than via the taxonomy.
        assert "/*__INGEST_HOOKS__*/ []" in text
        assert "'read'" in text
        assert "'fread'" in text


class TestExtractSeeds:
    def test_writes_unique_seeds_and_manifest_outside_corpus(self, tmp_path):
        _write_events(tmp_path, [
            _ingest("read", b"GET / HTTP/1.0\r\n\r\n"),
            _ingest("recv", b"\x00\x01\x02\x03"),
            _ingest("recv", b"GET / HTTP/1.0\r\n\r\n"),   # duplicate content
        ])
        manifest = extract_seeds(tmp_path)
        assert manifest["seed_count"] == 2
        assert manifest["duplicates"] == 1

        seeds_dir = tmp_path / "seeds"
        seed_files = sorted(p.name for p in seeds_dir.iterdir())
        assert len(seed_files) == 2
        # Every file inside the corpus dir must be a seed - AFL treats
        # all top-level regular files as inputs.
        assert all(name.startswith("seed-") for name in seed_files)
        assert (tmp_path / "seeds-manifest.json").is_file()

        contents = {p.read_bytes() for p in seeds_dir.iterdir()}
        assert contents == {b"GET / HTTP/1.0\r\n\r\n", b"\x00\x01\x02\x03"}

    def test_cap_is_recorded_not_silent(self, tmp_path):
        _write_events(tmp_path, [
            _ingest("read", bytes([i])) for i in range(5)
        ])
        manifest = extract_seeds(tmp_path, max_seeds=3)
        assert manifest["seed_count"] == 3
        assert manifest["dropped_over_cap"] == 2

    def test_by_fn_breakdown(self, tmp_path):
        _write_events(tmp_path, [
            _ingest("read", b"a"),
            _ingest("read", b"b"),
            _ingest("recv", b"c"),
        ])
        manifest = extract_seeds(tmp_path)
        assert manifest["by_fn"] == {"read": 2, "recv": 1}

    def test_malformed_and_oversized_payloads_skipped(self, tmp_path):
        big = b"A" * ((1 << 20) + 1)
        _write_events(tmp_path, [
            {"fn": "read", "args": {"data_hex": "zz-not-hex"}},
            {"fn": "read", "args": {"data_hex": ""}},
            {"fn": "read", "args": {"data_hex": big.hex()}},
            {"fn": "read", "args": "not-a-dict"},
            _ingest("read", b"ok"),
        ])
        manifest = extract_seeds(tmp_path)
        assert manifest["seed_count"] == 1

    def test_empty_run_creates_nothing(self, tmp_path):
        _write_events(tmp_path, [
            {"category": "file", "fn": "open", "args": {"path": "/etc/hosts"}},
        ])
        manifest = extract_seeds(tmp_path)
        assert manifest["seed_count"] == 0
        assert not (tmp_path / "seeds").exists()
        assert not (tmp_path / "seeds-manifest.json").exists()

    def test_missing_events_file(self, tmp_path):
        manifest = extract_seeds(tmp_path)
        assert manifest["seed_count"] == 0

    def test_explicit_out_dir(self, tmp_path):
        _write_events(tmp_path, [_ingest("read", b"x")])
        out = tmp_path / "corpus"
        manifest = extract_seeds(tmp_path, out)
        assert manifest["out_dir"] == str(out)
        assert (tmp_path / "corpus-manifest.json").is_file()
        assert len(list(out.iterdir())) == 1


class TestCliAutoHarvest:
    def test_harvest_prints_summary(self, tmp_path, capsys):
        _write_events(tmp_path, [_ingest("read", b"seed-bytes")])
        cli._maybe_harvest_seeds(tmp_path)
        out = capsys.readouterr().out
        assert "1 unique seeds harvested" in out
        assert "--corpus" in out

    def test_harvest_silent_when_no_data(self, tmp_path, capsys):
        _write_events(tmp_path, [
            {"category": "file", "fn": "read", "args": {"fd": 3}},
        ])
        cli._maybe_harvest_seeds(tmp_path)
        captured = capsys.readouterr()
        assert "harvested" not in captured.out
        assert captured.err == ""


class TestHarvestBounds:
    def test_malformed_and_oversized_are_counted(self, tmp_path):
        # 2 MiB + 2 hex chars: over the pre-decode gate.
        oversized_hex = "41" * ((1 << 20) + 1)
        _write_events(tmp_path, [
            {"fn": "read", "args": {"data_hex": "zz-not-hex"}},
            {"fn": "read", "args": {"data_hex": oversized_hex}},
            _ingest("read", b"ok"),
        ])
        manifest = extract_seeds(tmp_path)
        assert manifest["seed_count"] == 1
        assert manifest["skipped_malformed"] == 1
        assert manifest["skipped_oversized"] == 1

    def test_symlinked_seeds_dir_rejected(self, tmp_path):
        import pytest
        _write_events(tmp_path, [_ingest("read", b"x")])
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (tmp_path / "seeds").symlink_to(elsewhere)
        with pytest.raises(ValueError, match="symlink"):
            extract_seeds(tmp_path)

    def test_template_maps_are_prototype_safe(self):
        tpl = (Path(__file__).resolve().parents[1]
               / "templates" / "seed-harvest.js")
        text = tpl.read_text(encoding="utf-8")
        assert "Object.create(null)" in text
        # Dedup-table growth is bounded.
        assert "MAX_DEDUP_KEYS" in text
