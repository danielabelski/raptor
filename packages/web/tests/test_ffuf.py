"""Tests for the narrow ffuf integration."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from packages.web.ffuf import FfufConfig, FfufRunner


def test_build_command_anchors_relative_template_to_base_url(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    output = tmp_path / "ffuf_results.json"

    runner = FfufRunner("https://example.test/app", tmp_path)
    cmd = runner.build_command(
        FfufConfig(wordlist=wordlist, path_template="admin/FUZZ", threads=3, rate=5),
        output,
    )

    assert cmd[:6] == [
        "ffuf",
        "-u",
        "https://example.test/app/admin/FUZZ",
        "-w",
        str(wordlist),
        "-of",
    ]
    assert "-noninteractive" in cmd
    assert cmd[cmd.index("-t") + 1] == "3"
    assert cmd[cmd.index("-rate") + 1] == "5"


def test_build_command_allows_same_origin_absolute_template(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("health\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    url = runner.build_url_template("https://example.test/api/FUZZ")

    assert url == "https://example.test/api/FUZZ"


@pytest.mark.parametrize(
    "template",
    [
        "https://evil.test/FUZZ",
        "//evil.test/FUZZ",
        "https://example.test.evil/FUZZ",
    ],
)
def test_build_url_template_rejects_out_of_scope_templates(tmp_path: Path, template: str):
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match="outside configured target scope"):
        runner.build_url_template(template)


def test_build_command_requires_a_fuzz_keyword_somewhere(tmp_path: Path):
    """A config with no substitution point anywhere is a config error;
    a fixed URL is fine as long as the body or a header carries FUZZ."""
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match="no substitution point"):
        runner.build_command(
            FfufConfig(wordlist=wordlist, path_template="admin"),
            tmp_path / "out.json",
        )

    body_cmd = runner.build_command(
        FfufConfig(
            wordlist=wordlist,
            path_template="api/login",
            method="POST",
            data="FUZZ=1",
        ),
        tmp_path / "out.json",
    )
    assert body_cmd[body_cmd.index("-u") + 1] == "https://example.test/api/login"

    header_cmd = runner.build_command(
        FfufConfig(
            wordlist=wordlist,
            path_template="api/login",
            headers=("X-Forwarded-For: FUZZ",),
        ),
        tmp_path / "out.json",
    )
    assert header_cmd[header_cmd.index("-H") + 1] == "X-Forwarded-For: FUZZ"


def test_build_command_emits_method_and_body(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    cmd = runner.build_command(
        FfufConfig(
            wordlist=wordlist,
            path_template="api/users",
            method="POST",
            data='{"FUZZ": "1"}',
            headers=("Content-Type: application/json",),
        ),
        tmp_path / "out.json",
    )

    assert cmd[cmd.index("-X") + 1] == "POST"
    assert cmd[cmd.index("-d") + 1] == '{"FUZZ": "1"}'


def test_build_command_get_method_omits_x_flag(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    cmd = runner.build_command(FfufConfig(wordlist=wordlist), tmp_path / "out.json")

    assert "-X" not in cmd
    assert "-d" not in cmd


def test_build_command_rejects_unknown_method(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match="method must be one of"):
        runner.build_command(
            FfufConfig(wordlist=wordlist, method="TRACE"),
            tmp_path / "out.json",
        )


def test_redact_body_masks_secret_form_fields_only(tmp_path: Path):
    runner = FfufRunner("https://example.test", tmp_path)

    redacted = runner._redact_body("username=admin&password=hunter2&mode=FUZZ")

    assert "hunter2" not in redacted
    assert "password=[REDACTED]" in redacted
    assert "username=admin" in redacted
    assert "mode=FUZZ" in redacted


def test_run_redacts_body_in_logs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    def fake_run(cmd, **kwargs):
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(json.dumps({"results": []}), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)

    messages: list[str] = []
    monkeypatch.setattr(
        "packages.web.ffuf.logger.info",
        lambda fmt, *args: messages.append(fmt % args if args else fmt),
    )

    runner = FfufRunner("https://example.test", tmp_path)
    runner.run(
        FfufConfig(
            wordlist=wordlist,
            path_template="login",
            method="POST",
            data="user=FUZZ&api_key=sk-verysecretvalue123",
        )
    )

    logs = "\n".join(messages)
    assert "sk-verysecretvalue123" not in logs
    assert "user=FUZZ" in logs


def test_scanner_cli_wires_ffuf_method_and_data(tmp_path: Path):
    from packages.web.scanner import build_arg_parser, build_ffuf_config

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    args = build_arg_parser().parse_args(
        [
            "--url",
            "https://example.test",
            "--ffuf-wordlist",
            str(wordlist),
            "--ffuf-method",
            "POST",
            "--ffuf-data",
            "FUZZ=1",
        ]
    )

    config = build_ffuf_config(args)

    assert config is not None
    assert config.method == "POST"
    assert config.data == "FUZZ=1"


@pytest.mark.parametrize(
    ("config_kwargs", "message"),
    [
        ({"threads": 0}, "threads must be >= 1"),
        ({"rate": 0}, "rate must be >= 1"),
        ({"timeout": 0}, "timeout must be >= 1"),
        ({"max_runtime": 0}, "max runtime must be >= 1"),
        ({"report_limit": -1}, "report limit must be >= 0"),
        ({"filter_size": -1}, "filter size must be >= 0"),
    ],
)
def test_build_command_rejects_invalid_numeric_options(
    tmp_path: Path,
    config_kwargs: dict[str, int],
    message: str,
):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match=message):
        runner.build_command(FfufConfig(wordlist=wordlist, **config_kwargs), tmp_path / "out.json")



def test_build_command_always_caps_runtime_with_maxtime(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    cmd = runner.build_command(
        FfufConfig(wordlist=wordlist, max_runtime=120), tmp_path / "out.json"
    )

    assert cmd[cmd.index("-maxtime") + 1] == "120"


def test_build_command_emits_stop_conditions_only_when_enabled(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)
    output = tmp_path / "out.json"

    default_cmd = runner.build_command(FfufConfig(wordlist=wordlist), output)
    assert "-sf" not in default_cmd
    assert "-se" not in default_cmd
    assert "-sa" not in default_cmd

    full_cmd = runner.build_command(
        FfufConfig(
            wordlist=wordlist,
            stop_on_403=True,
            stop_on_spurious=True,
            stop_on_all_errors=True,
        ),
        output,
    )
    assert "-sf" in full_cmd
    assert "-se" in full_cmd
    assert "-sa" in full_cmd


def test_build_command_threads_matcher_and_filter_family(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    cmd = runner.build_command(
        FfufConfig(
            wordlist=wordlist,
            extensions=(".php", ".bak"),
            filter_words=17,
            filter_lines=3,
            match_regex="AKIA[0-9A-Z]{16}",
            filter_regex="Not Found",
            match_time=">500",
            filter_time="<100",
        ),
        tmp_path / "out.json",
    )

    assert cmd[cmd.index("-e") + 1] == ".php,.bak"
    assert cmd[cmd.index("-fw") + 1] == "17"
    assert cmd[cmd.index("-fl") + 1] == "3"
    assert cmd[cmd.index("-mr") + 1] == "AKIA[0-9A-Z]{16}"
    assert cmd[cmd.index("-fr") + 1] == "Not Found"
    assert cmd[cmd.index("-mt") + 1] == ">500"
    assert cmd[cmd.index("-ft") + 1] == "<100"


@pytest.mark.parametrize(
    ("config_kwargs", "message"),
    [
        ({"extensions": ("php",)}, "leading dot"),
        ({"extensions": (".",)}, "leading dot"),
        ({"extensions": (".php,.bak",)}, "no commas or whitespace"),
        ({"extensions": (".p hp",)}, "no commas or whitespace"),
        ({"filter_words": -1}, "filter words must be >= 0"),
        ({"filter_lines": -1}, "filter lines must be >= 0"),
        ({"match_regex": "a\nb"}, "match regex must not contain newlines"),
        ({"filter_regex": "a\rb"}, "filter regex must not contain newlines"),
        ({"match_time": "500"}, "match time must look like"),
        ({"match_time": ">1x0"}, "match time must look like"),
        ({"filter_time": "=100"}, "filter time must look like"),
    ],
)
def test_build_command_rejects_invalid_matcher_options(
    tmp_path: Path,
    config_kwargs: dict[str, object],
    message: str,
):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match=message):
        runner.build_command(FfufConfig(wordlist=wordlist, **config_kwargs), tmp_path / "out.json")


def test_scanner_cli_wires_ffuf_matcher_family(tmp_path: Path):
    from packages.web.scanner import build_arg_parser, build_ffuf_config

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    args = build_arg_parser().parse_args(
        [
            "--url",
            "https://example.test",
            "--ffuf-wordlist",
            str(wordlist),
            "--ffuf-extensions",
            ".php, .bak",
            "--ffuf-filter-words",
            "17",
            "--ffuf-filter-lines",
            "3",
            "--ffuf-match-regex",
            "secret_[a-z]+",
            "--ffuf-filter-regex",
            "Not Found",
            "--ffuf-match-time",
            ">500",
            "--ffuf-filter-time",
            "<100",
        ]
    )

    config = build_ffuf_config(args)

    assert config is not None
    assert config.extensions == (".php", ".bak")
    assert config.filter_words == 17
    assert config.filter_lines == 3
    assert config.match_regex == "secret_[a-z]+"
    assert config.filter_regex == "Not Found"
    assert config.match_time == ">500"
    assert config.filter_time == "<100"


def test_build_command_recursion_pairs_job_cap_and_default_rate(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    cmd = runner.build_command(
        FfufConfig(wordlist=wordlist, recursion=True, max_runtime=400),
        tmp_path / "out.json",
    )

    assert "-recursion" in cmd
    assert cmd[cmd.index("-recursion-depth") + 1] == "2"
    assert cmd[cmd.index("-recursion-strategy") + 1] == "default"
    # max(60, 400 // 4) = 100
    assert cmd[cmd.index("-maxtime-job") + 1] == "100"
    assert cmd[cmd.index("-rate") + 1] == "50"


def test_build_command_recursion_respects_explicit_rate_and_job_cap(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    cmd = runner.build_command(
        FfufConfig(
            wordlist=wordlist,
            recursion=True,
            recursion_depth=3,
            recursion_strategy="greedy",
            rate=7,
            max_runtime_job=42,
        ),
        tmp_path / "out.json",
    )

    assert cmd[cmd.index("-recursion-depth") + 1] == "3"
    assert cmd[cmd.index("-recursion-strategy") + 1] == "greedy"
    assert cmd[cmd.index("-maxtime-job") + 1] == "42"
    assert cmd[cmd.index("-rate") + 1] == "7"


def test_build_command_without_recursion_adds_no_recursion_or_rate_flags(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    cmd = runner.build_command(FfufConfig(wordlist=wordlist), tmp_path / "out.json")

    assert "-recursion" not in cmd
    assert "-maxtime-job" not in cmd
    assert "-rate" not in cmd


def test_build_command_recursion_requires_fuzz_terminated_template(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match="recursion requires the URL template to end with FUZZ"):
        runner.build_command(
            FfufConfig(wordlist=wordlist, path_template="FUZZ.php", recursion=True),
            tmp_path / "out.json",
        )

    # A trailing slash after FUZZ is fine.
    cmd = runner.build_command(
        FfufConfig(wordlist=wordlist, path_template="api/FUZZ/", recursion=True),
        tmp_path / "out.json",
    )
    assert "-recursion" in cmd


@pytest.mark.parametrize(
    ("config_kwargs", "message"),
    [
        ({"recursion_depth": 0}, "recursion depth must be >= 1"),
        ({"recursion_strategy": "wide"}, "recursion strategy must be"),
        ({"max_runtime_job": 0}, "max runtime per job must be >= 1"),
    ],
)
def test_build_command_rejects_invalid_recursion_options(
    tmp_path: Path,
    config_kwargs: dict[str, object],
    message: str,
):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match=message):
        runner.build_command(FfufConfig(wordlist=wordlist, **config_kwargs), tmp_path / "out.json")


def test_scanner_cli_wires_ffuf_recursion(tmp_path: Path):
    from packages.web.scanner import build_arg_parser, build_ffuf_config

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    args = build_arg_parser().parse_args(
        [
            "--url",
            "https://example.test",
            "--ffuf-wordlist",
            str(wordlist),
            "--ffuf-recursion",
            "--ffuf-recursion-depth",
            "3",
            "--ffuf-recursion-strategy",
            "greedy",
            "--ffuf-maxtime-job",
            "90",
        ]
    )

    config = build_ffuf_config(args)

    assert config is not None
    assert config.recursion is True
    assert config.recursion_depth == 3
    assert config.recursion_strategy == "greedy"
    assert config.max_runtime_job == 90


def test_run_grants_grace_beyond_ffuf_maxtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The subprocess timeout must exceed -maxtime so ffuf's own clean
    shutdown (which flushes the JSON report) always wins the race."""
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(json.dumps({"results": []}), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)

    runner = FfufRunner("https://example.test", tmp_path)
    result = runner.run(FfufConfig(wordlist=wordlist, max_runtime=200))

    assert captured["cmd"][captured["cmd"].index("-maxtime") + 1] == "200"
    # grace = min(30, max(5, 200 // 10)) = 20
    assert captured["kwargs"]["timeout"] == 220
    assert result["timed_out"] is False
    assert result["returncode"] == 0


def test_run_survives_backstop_timeout_and_keeps_partial_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """A wedged ffuf killed by the backstop must degrade to a partial
    summary instead of aborting the whole scan with TimeoutExpired."""
    import subprocess

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    def fake_run(cmd, **kwargs):
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(
            json.dumps({"results": [{"url": "https://example.test/admin", "status": 200}]}),
            encoding="utf-8",
        )
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs["timeout"], stderr=b"wedged")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)

    runner = FfufRunner("https://example.test", tmp_path)
    result = runner.run(FfufConfig(wordlist=wordlist))

    assert result["timed_out"] is True
    assert result["returncode"] is None
    assert result["result_count"] == 1
    assert result["stderr"] == "wedged"


def test_build_command_threads_authenticated_ffuf_options(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    output = tmp_path / "ffuf_results.json"
    bearer = "Authorization: Bearer " + "a" * 32

    runner = FfufRunner("https://example.test", tmp_path)
    cmd = runner.build_command(
        FfufConfig(
            wordlist=wordlist,
            headers=(bearer, "X-Tenant: test"),
            cookies=("session=" + "b" * 32, "pref=dark"),
        ),
        output,
    )

    assert cmd[cmd.index("-H") + 1] == bearer
    assert [cmd[idx + 1] for idx, value in enumerate(cmd) if value == "-H"] == [
        bearer,
        "X-Tenant: test",
    ]
    assert [cmd[idx + 1] for idx, value in enumerate(cmd) if value == "-b"] == [
        "session=" + "b" * 32,
        "pref=dark",
    ]


@pytest.mark.parametrize(
    ("config_kwargs", "message"),
    [
        ({"headers": ("X-Test: ok\nInjected: yes",)}, "headers must not contain newlines"),
        ({"headers": ("X-Test: ok\rInjected: yes",)}, "headers must not contain newlines"),
        ({"headers": ("Bearer abc123",)}, "headers must be in 'Name: value' form"),
        ({"headers": (": abc123",)}, "headers must be in 'Name: value' form"),
        ({"cookies": ("session=ok\nother=yes",)}, "cookies must not contain newlines"),
        ({"cookies": ("session=ok\rother=yes",)}, "cookies must not contain newlines"),
    ],
)
def test_build_command_rejects_header_cookie_newlines(
    tmp_path: Path,
    config_kwargs: dict[str, tuple[str, ...]],
    message: str,
):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match=message):
        runner.build_command(FfufConfig(wordlist=wordlist, **config_kwargs), tmp_path / "out.json")


def test_run_redacts_authenticated_ffuf_options_from_logs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    def fake_run(cmd, **kwargs):
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(json.dumps({"results": []}), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)
    bearer = "Authorization: Bearer " + "a" * 32
    cookie = "session=" + "b" * 32

    messages: list[str] = []
    monkeypatch.setattr(
        "packages.web.ffuf.logger.info",
        lambda fmt, *args: messages.append(fmt % args if args else fmt),
    )

    runner = FfufRunner("https://example.test", tmp_path)
    runner.run(FfufConfig(wordlist=wordlist, headers=(bearer,), cookies=(cookie,)))

    logs = "\n".join(messages)
    assert "Authorization: [REDACTED]" in logs
    assert "session=[REDACTED]" in logs
    assert "a" * 32 not in logs
    assert "b" * 32 not in logs


@pytest.mark.parametrize(
    "header",
    [
        "Authorization: Token abc123",
        "Authorization: ApiKey short",
        'Authorization: Digest username="u", nonce="n"',
        "Proxy-Authorization: Negotiate abc",
    ],
)
def test_redacts_authorization_headers_without_relying_on_token_shape(
    tmp_path: Path,
    header: str,
):
    runner = FfufRunner("https://example.test", tmp_path)

    assert runner._redact_header_value(header) == f"{header.split(':', 1)[0]}: [REDACTED]"


def test_cookie_redaction_preserves_separator_spacing(tmp_path: Path):
    runner = FfufRunner("https://example.test", tmp_path)

    assert (
        runner._redact_cookie_value("session=abc123; pref=dark")
        == "session=[REDACTED]; pref=[REDACTED]"
    )


def test_run_requires_explicit_ffuf_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: None)

    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(FileNotFoundError, match="ffuf binary not found"):
        runner.run(FfufConfig(wordlist=wordlist))


def test_run_uses_subprocess_argv_and_summarizes_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(
            json.dumps(
                {
                    "results": [
                        {
                            "url": "https://example.test/admin?" + "tok" + "en=abc123",
                            "status": 200,
                            "length": 42,
                            "words": 3,
                            "lines": 1,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stderr=None)

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)

    runner = FfufRunner("https://example.test", tmp_path)
    result = runner.run(FfufConfig(wordlist=wordlist, path_template="FUZZ"))

    # cmd[0] is the resolved real path (exec-via-realpath), not the
    # operator-facing name.
    assert captured["cmd"][0] == "/usr/bin/ffuf"
    assert captured["kwargs"]["capture_output"] is True
    assert captured["kwargs"]["text"] is True
    assert captured["kwargs"]["proxy_hosts"] == ["example.test"]
    assert captured["kwargs"]["caller_label"] == "web-ffuf"
    assert result["returncode"] == 0
    assert result["stderr"] == ""
    assert result["result_count"] == 1
    assert result["reported_result_count"] == 1
    assert result["omitted_result_count"] == 0
    assert result["results"] == [
        {
            "url": "https://example.test/admin?" + "tok" + "en=[REDACTED]",
            "status": 200,
            "length": 42,
            "words": 3,
            "lines": 1,
        }
    ]


def test_run_limits_embedded_report_results_but_keeps_raw_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    def fake_run(cmd, **kwargs):
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(
            json.dumps(
                {
                    "results": [
                        {"url": f"https://example.test/{idx}", "status": 200}
                        for idx in range(3)
                    ]
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)

    runner = FfufRunner("https://example.test", tmp_path)
    result = runner.run(FfufConfig(wordlist=wordlist, report_limit=2))

    assert result["result_count"] == 3
    assert result["reported_result_count"] == 2
    assert result["omitted_result_count"] == 1
    assert [entry["url"] for entry in result["results"]] == [
        "https://example.test/0",
        "https://example.test/1",
    ]


def test_scanner_cli_wires_all_ffuf_options(tmp_path: Path):
    from packages.web.scanner import build_arg_parser, build_ffuf_config

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    auth_header = "Authorization: Bearer " + "a" * 32
    session_cookie = "session=" + "b" * 32
    args = build_arg_parser().parse_args(
        [
            "--url",
            "https://example.test",
            "--ffuf-wordlist",
            str(wordlist),
            "--ffuf-path",
            "admin/FUZZ",
            "--ffuf-bin",
            "custom-ffuf",
            "--ffuf-threads",
            "7",
            "--ffuf-rate",
            "11",
            "--ffuf-timeout",
            "12",
            "--ffuf-report-limit",
            "13",
            "--ffuf-max-runtime",
            "14",
            "--ffuf-no-auto-calibration",
            "--ffuf-match-status",
            "200,401",
            "--ffuf-filter-status",
            "403,404",
            "--ffuf-filter-size",
            "1234",
            "--ffuf-header",
            auth_header,
            "--ffuf-header",
            "X-Tenant: test",
            "--ffuf-cookie",
            session_cookie,
            "--ffuf-cookie",
            "pref=dark",
        ]
    )

    config = build_ffuf_config(args)

    assert config is not None
    assert config.wordlist == wordlist
    assert config.path_template == "admin/FUZZ"
    assert config.binary == "custom-ffuf"
    assert config.threads == 7
    assert config.rate == 11
    assert config.timeout == 12
    assert config.report_limit == 13
    assert config.max_runtime == 14
    assert config.auto_calibration is False
    assert config.match_status == "200,401"
    assert config.filter_status == "403,404"
    assert config.filter_size == 1234
    assert config.headers == (auth_header, "X-Tenant: test")
    assert config.cookies == (session_cookie, "pref=dark")


def test_scanner_cli_wires_ffuf_stop_conditions(tmp_path: Path):
    from packages.web.scanner import build_arg_parser, build_ffuf_config

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    args = build_arg_parser().parse_args(
        [
            "--url",
            "https://example.test",
            "--ffuf-wordlist",
            str(wordlist),
            "--ffuf-stop-on-403",
            "--ffuf-stop-on-spurious-errors",
            "--ffuf-stop-on-all-errors",
        ]
    )

    config = build_ffuf_config(args)

    assert config is not None
    assert config.stop_on_403 is True
    assert config.stop_on_spurious is True
    assert config.stop_on_all_errors is True

    defaults = build_ffuf_config(
        build_arg_parser().parse_args(
            ["--url", "https://example.test", "--ffuf-wordlist", str(wordlist)]
        )
    )
    assert defaults is not None
    assert defaults.stop_on_403 is False
    assert defaults.stop_on_spurious is False
    assert defaults.stop_on_all_errors is False


def test_scanner_cli_can_omit_optional_ffuf_match_and_filter_status(tmp_path: Path):
    from packages.web.scanner import build_arg_parser, build_ffuf_config

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    args = build_arg_parser().parse_args(
        [
            "--url",
            "https://example.test",
            "--ffuf-wordlist",
            str(wordlist),
            "--ffuf-match-status",
            "",
            "--ffuf-filter-status",
            "",
        ]
    )

    config = build_ffuf_config(args)

    assert config is not None
    assert config.match_status is None
    assert config.filter_status is None


def test_run_execs_realpath_and_binds_resolved_tool_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """Symlinked installs (go install / package manager shims): the
    mount-ns visibility check realpaths cmd[0], so the exec must use
    the REAL binary path and tool_paths must carry the RESOLVED
    parent — otherwise the run silently drops to Landlock-only."""
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    real = tmp_path / "opt" / "ffuf" / "ffuf"
    real.parent.mkdir(parents=True)
    real.write_text("#!/bin/sh\n")
    link = tmp_path / "bin" / "ffuf"
    link.parent.mkdir()
    link.symlink_to(real)
    monkeypatch.setattr(
        "packages.web.ffuf.shutil.which", lambda _binary: str(link))

    seen: dict = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = list(cmd)
        seen["kwargs"] = dict(kwargs)
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(json.dumps({"results": []}), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)
    runner = FfufRunner("https://example.test", tmp_path)
    runner.run(FfufConfig(wordlist=wordlist))

    assert seen["cmd"][0] == str(real.resolve())
    assert seen["kwargs"]["tool_paths"] == [str(real.resolve().parent)]


def test_run_refuses_oversize_results_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A results file over the byte budget is refused before the read
    — the run degrades to zero results like any unparseable output."""
    import os

    from packages.web import ffuf as ffuf_mod

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr(
        "packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf",
    )

    def fake_run(cmd, **kwargs):
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(
            json.dumps({"results": [{"url": "https://example.test/a",
                                     "status": 200}]}),
            encoding="utf-8",
        )
        # Sparse-extend past the cap: the stat gate fires before any
        # read, so no data is materialised.
        os.truncate(output_path, ffuf_mod._MAX_FFUF_OUTPUT_BYTES + 1)
        return SimpleNamespace(returncode=0, stderr=None)

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)

    runner = FfufRunner("https://example.test", tmp_path)
    result = runner.run(FfufConfig(wordlist=wordlist, path_template="FUZZ"))
    assert result["returncode"] == 0
    assert result["result_count"] == 0
    assert result["results"] == []
