"""Binary items project onto address ranges in the coverage store."""

import json

from core.coverage.importer import _function_ranges, backfill
from core.coverage.store import CoverageStore, iter_inventory_functions


def _binary_checklist():
    return {
        "target_path": "/x/target",
        "files": [{
            "path": "binary:target",
            "language": "binary",
            "sha256": "ab" * 32,
            "items": [
                {"name": "vuln", "kind": "function",
                 "address": 0x1000, "size": 0x80,
                 "metadata": {"address": 0x1000, "size": 0x80}},
            ],
        }],
        "target_kind": "binary",
    }


class TestBinaryRanges:
    def test_function_ranges_use_addresses(self):
        ranges = _function_ranges(_binary_checklist(), normalise_hi=True)
        assert ranges[("binary:target", "vuln")] == (0x1000, 0x107f)

    def test_iterator_yields_address_span(self):
        rows = list(iter_inventory_functions(_binary_checklist()))
        assert rows == [("binary:target", "vuln", 0x1000, 0x107f, "function")]

    def test_journal_entry_reaches_store_view(self, tmp_path):
        from core.audit.journal import (
            ReviewJournalEntry,
            append_entry,
            merge_into_index,
            now_iso,
        )
        from core.coverage.store_summary import store_view

        cl = _binary_checklist()
        (tmp_path / "checklist.json").write_text(json.dumps(cl))
        entry = ReviewJournalEntry(
            ts=now_iso(), run_id="audit_test", file="binary:target",
            function="vuln", verdict="clean", source_hash="",
        )
        append_entry(tmp_path, entry)
        merge_into_index(tmp_path, tmp_path)

        store = CoverageStore(tmp_path / "coverage.json")
        backfill(store, [tmp_path], cl, project_dir=tmp_path)
        view = store_view(store, cl)
        assert view["functions_reviewed"] == 1
        assert view["functions_covered"] == 1
