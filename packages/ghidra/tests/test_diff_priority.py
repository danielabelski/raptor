"""Tests for Ghidra diff priority filter."""

import json
from unittest.mock import patch

import pytest

from packages.ghidra.diff_priority import (
    _load_changed_names,
    apply_diff_priority,
)


@pytest.fixture()
def version_diff(tmp_path):
    diff = {
        "added": [
            {"name": "new_handler", "address": 0x1000, "size": 100},
            {"name": "FUN_00402000", "address": 0x2000, "size": 50},
        ],
        "changed": [
            {"name": "parse_input", "old_size": 100, "new_size": 120},
        ],
        "removed": [
            {"name": "old_func", "address": 0x3000, "size": 80},
        ],
    }
    path = tmp_path / "version-diff.json"
    path.write_text(json.dumps(diff))
    return path


@pytest.fixture()
def checklist(tmp_path):
    data = {
        "files": [
            {
                "path": "src/main.c",
                "items": [
                    {"function": "parse_input", "name": "parse_input", "priority": "medium"},
                    {"function": "new_handler", "name": "new_handler"},
                    {"function": "unrelated_func", "name": "unrelated_func", "priority": "low"},
                    {"function": "old_func", "name": "old_func"},
                ],
            },
        ],
    }
    path = tmp_path / "checklist.json"
    path.write_text(json.dumps(data))
    return path


class TestLoadChangedNames:
    def test_extracts_added_and_changed(self, version_diff):
        names = _load_changed_names(version_diff)
        assert "new_handler" in names
        assert "FUN_00402000" in names
        assert "parse_input" in names

    def test_excludes_removed(self, version_diff):
        names = _load_changed_names(version_diff)
        assert "old_func" not in names

    def test_empty_diff(self, tmp_path):
        path = tmp_path / "empty.json"
        path.write_text(json.dumps({}))
        names = _load_changed_names(path)
        assert names == set()

    def test_skips_empty_names(self, tmp_path):
        path = tmp_path / "diff.json"
        path.write_text(json.dumps({
            "added": [{"name": ""}, {"name": "real_func"}],
        }))
        names = _load_changed_names(path)
        assert names == {"real_func"}


class TestApplyDiffPriority:
    def test_boosts_changed_functions(self, tmp_path, version_diff, checklist):
        with patch(
            "packages.ghidra.diff_priority._find_version_diff",
            return_value=version_diff,
        ):
            n = apply_diff_priority(tmp_path, checklist)

        assert n == 2

        with open(checklist) as f:
            data = json.load(f)
        items = data["files"][0]["items"]

        parse = next(i for i in items if i["function"] == "parse_input")
        assert parse["priority"] == "high"
        assert "ghidra-diff" in parse.get("priority_reason", "")

        new = next(i for i in items if i["function"] == "new_handler")
        assert new["priority"] == "high"
        assert "ghidra-diff" in new.get("priority_reason", "")

    def test_unrelated_not_boosted(self, tmp_path, version_diff, checklist):
        with patch(
            "packages.ghidra.diff_priority._find_version_diff",
            return_value=version_diff,
        ):
            apply_diff_priority(tmp_path, checklist)

        with open(checklist) as f:
            data = json.load(f)
        items = data["files"][0]["items"]
        unrelated = next(
            i for i in items if i["function"] == "unrelated_func"
        )
        assert unrelated["priority"] == "low"

    def test_already_high_not_double_boosted(self, tmp_path, version_diff):
        data = {
            "files": [{
                "path": "src/main.c",
                "items": [
                    {"function": "parse_input", "name": "parse_input", "priority": "high"},
                ],
            }],
        }
        cl = tmp_path / "checklist.json"
        cl.write_text(json.dumps(data))

        with patch(
            "packages.ghidra.diff_priority._find_version_diff",
            return_value=version_diff,
        ):
            n = apply_diff_priority(tmp_path, cl)

        assert n == 0

    def test_no_diff_returns_zero(self, tmp_path, checklist):
        with patch(
            "packages.ghidra.diff_priority._find_version_diff",
            return_value=None,
        ):
            n = apply_diff_priority(tmp_path, checklist)
        assert n == 0

    def test_empty_diff_returns_zero(self, tmp_path, checklist):
        empty = tmp_path / "empty-diff.json"
        empty.write_text(json.dumps({}))
        with patch(
            "packages.ghidra.diff_priority._find_version_diff",
            return_value=empty,
        ):
            n = apply_diff_priority(tmp_path, checklist)
        assert n == 0

    def test_name_key_fallback(self, tmp_path, version_diff):
        data = {
            "files": [{
                "path": "src/main.c",
                "items": [
                    {"name": "parse_input"},
                ],
            }],
        }
        cl = tmp_path / "checklist.json"
        cl.write_text(json.dumps(data))

        with patch(
            "packages.ghidra.diff_priority._find_version_diff",
            return_value=version_diff,
        ):
            n = apply_diff_priority(tmp_path, cl)

        assert n == 1
        with open(cl) as f:
            result = json.load(f)
        assert result["files"][0]["items"][0]["priority"] == "high"

    def test_appends_to_existing_reason(self, tmp_path, version_diff):
        data = {
            "files": [{
                "path": "src/main.c",
                "items": [
                    {
                        "function": "parse_input",
                        "name": "parse_input",
                        "priority": "low",
                        "priority_reason": "binary-oracle: symbol present",
                    },
                ],
            }],
        }
        cl = tmp_path / "checklist.json"
        cl.write_text(json.dumps(data))

        with patch(
            "packages.ghidra.diff_priority._find_version_diff",
            return_value=version_diff,
        ):
            n = apply_diff_priority(tmp_path, cl)

        assert n == 1
        with open(cl) as f:
            result = json.load(f)
        reason = result["files"][0]["items"][0]["priority_reason"]
        assert "binary-oracle" in reason
        assert "ghidra-diff" in reason
