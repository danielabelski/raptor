"""Concurrency and corruption-handling tests for journal appends."""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

from core.coverage.journal import (
    ReviewJournalEntry,
    append_entry,
    load_entries,
    now_iso,
)


def _entry(i: int, body_size: int = 0) -> ReviewJournalEntry:
    return ReviewJournalEntry(
        ts=now_iso(),
        run_id="run-1",
        file=f"src/f{i}.c",
        function=f"fn{i}",
        verdict="clean",
        source_hash="abc123",
        body="x" * body_size,
    )


class TestConcurrentAppend:
    def test_threaded_large_appends_never_interleave(
        self, tmp_path: Path,
    ) -> None:
        """Entries larger than PIPE_BUF appended from many threads must
        land as whole lines — the old buffered f.write through per-
        thread fds could interleave partial writes."""
        n_threads = 8
        per_thread = 5
        body_size = 16 * 1024  # comfortably > PIPE_BUF (4096)

        def worker(t: int) -> None:
            for j in range(per_thread):
                append_entry(tmp_path, _entry(t * 100 + j, body_size))

        threads = [
            threading.Thread(target=worker, args=(t,))
            for t in range(n_threads)
        ]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        raw_lines = (
            (tmp_path / "review-journal.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        )
        assert len(raw_lines) == n_threads * per_thread
        for line in raw_lines:
            parsed = json.loads(line)  # every line is intact JSON
            assert len(parsed["body"]) == body_size

        entries = load_entries(tmp_path)
        assert len(entries) == n_threads * per_thread

    def test_single_append_round_trips(self, tmp_path: Path) -> None:
        append_entry(tmp_path, _entry(1))
        entries = load_entries(tmp_path)
        assert len(entries) == 1
        assert entries[0].function == "fn1"


class TestCorruptLineCounting:
    def test_corrupt_lines_counted_and_warned(
        self, tmp_path: Path, caplog,
    ) -> None:
        append_entry(tmp_path, _entry(1))
        journal = tmp_path / "review-journal.jsonl"
        with open(journal, "a", encoding="utf-8") as f:
            f.write("{truncated\n")
            f.write("also not json\n")
        append_entry(tmp_path, _entry(2))

        with caplog.at_level(logging.WARNING, logger="core.coverage.journal"):
            entries = load_entries(tmp_path)

        assert len(entries) == 2
        agg = [
            r for r in caplog.records
            if "skipped 2 corrupt line(s)" in r.getMessage()
        ]
        assert agg, "aggregate corrupt-line warning expected"
