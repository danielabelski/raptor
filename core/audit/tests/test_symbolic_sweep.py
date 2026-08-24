"""Tests for the audit's symbolic (angr) sweep channel."""

from unittest.mock import patch

from core.audit.sweep import run_symbolic_sweep, symbolic_applicable


class _Info:
    """load_binary stub."""

    def __init__(self, symbols=None, is_pie=False):
        self.symbols = symbols or {"f": 0x1000}
        self.is_pie = is_pie


class TestApplicability:
    def test_source_items_never_applicable(self):
        assert not symbolic_applicable("CWE-121", "src/main.c")

    def test_binary_items_gated_on_angr(self):
        with patch(
            "core.symbolic._availability.angr_available",
            return_value=False,
        ):
            assert not symbolic_applicable("CWE-121", "binary:t")


class TestRunnerErrors:
    def test_source_file_errors(self, tmp_path):
        res = run_symbolic_sweep(
            target_path=tmp_path, file_path="src/a.c",
            function_name="f", out_dir=tmp_path,
        )
        assert res.outcome == "error"
        assert "binary:" in res.errors[0]

    def test_angr_absent_errors_cleanly(self, tmp_path):
        with patch(
            "core.symbolic._availability.angr_available",
            return_value=False,
        ):
            res = run_symbolic_sweep(
                target_path=tmp_path / "b", file_path="binary:b",
                function_name="f", out_dir=tmp_path,
            )
        assert res.outcome == "error"
        assert "angr" in res.errors[0]

    def test_no_witness_is_inconclusive_never_refuted(self, tmp_path):
        binary = tmp_path / "b"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 60)

        class _R:
            succeeded = False
            concrete_input = None
            reason = "budget exhausted"

        with (
            patch(
                "core.symbolic._availability.angr_available",
                return_value=True,
            ),
            patch("core.symbolic.load_binary", return_value=_Info()),
            patch(
                "core.symbolic.find_reaching_input", return_value=_R(),
            ),
        ):
            res = run_symbolic_sweep(
                target_path=binary, file_path="binary:b",
                function_name="f", out_dir=tmp_path,
                address=0x1000, cwe="CWE-79",
            )
        assert res.outcome == "inconclusive"
        assert "not a refutation" in (res.details or {}).get("reason", "")

    def test_witness_confirms(self, tmp_path):
        binary = tmp_path / "b"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 60)

        class _R:
            succeeded = True
            concrete_input = b"A" * 32
            reason = ""
            wall_seconds = 1.0

        with (
            patch(
                "core.symbolic._availability.angr_available",
                return_value=True,
            ),
            patch("core.symbolic.load_binary", return_value=_Info()),
            patch(
                "core.symbolic.find_overflow_reaching_input",
                return_value=_R(),
            ),
        ):
            res = run_symbolic_sweep(
                target_path=binary, file_path="binary:b",
                function_name="f", out_dir=tmp_path,
                address=0x1000, cwe="CWE-121",
            )
        assert res.outcome == "confirmed"
        assert res.rule_id == "symbolic-pc-hijack"
        entry = res.to_log_entry()
        assert entry["key"] == "binary:b:f"
