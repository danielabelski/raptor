"""Tests for audit-trail noise controls — file level + separator filter."""

import logging

from core.logging import _drop_separator_records, _file_log_level


def _record(msg, *args):
    return logging.LogRecord(
        "raptor", logging.INFO, __file__, 1, msg, args, None,
    )


class TestSeparatorFilter:

    def test_equals_banner_dropped(self):
        assert _drop_separator_records(_record("=" * 70)) is False

    def test_dash_banner_dropped(self):
        assert _drop_separator_records(_record("-" * 40)) is False

    def test_mixed_decoration_dropped(self):
        assert _drop_separator_records(_record("== == == == ==")) is False

    def test_real_message_kept(self):
        assert _drop_separator_records(_record("Scan complete: 3 findings"))

    def test_message_containing_equals_kept(self):
        assert _drop_separator_records(_record("threshold = 5, mode = fast"))

    def test_short_decoration_kept(self):
        # Below the length floor — too short to be a banner, and "--"
        # style fragments can be legitimate content.
        assert _drop_separator_records(_record("=="))

    def test_lazy_format_args_expanded(self):
        # The filter must judge the FORMATTED message, not the template.
        assert _drop_separator_records(_record("%s", "=" * 70)) is False


class TestFileLogLevel:

    def test_default_is_info(self, monkeypatch):
        monkeypatch.delenv("RAPTOR_LOG_FILE_LEVEL", raising=False)
        assert _file_log_level() == logging.INFO

    def test_env_debug_restores_firehose(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_LOG_FILE_LEVEL", "DEBUG")
        assert _file_log_level() == logging.DEBUG

    def test_env_is_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_LOG_FILE_LEVEL", "warning")
        assert _file_log_level() == logging.WARNING

    def test_unknown_name_falls_back_to_info(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_LOG_FILE_LEVEL", "VERBOSE")
        assert _file_log_level() == logging.INFO
