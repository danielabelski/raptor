"""Live ffuf verification against a loopback fixture server.

These tests exercise the REAL ffuf binary: argv acceptance, -config
TOML consumption, request shaping on the wire, and JSON report shape.
They skip when ffuf is not on PATH, so CI without ffuf degrades to the
mocked unit suite in test_ffuf.py.

The sandbox layer is bypassed here (direct subprocess with a
proxy-scrubbed env): its plumbing has its own E2E coverage, and the
egress proxy deliberately rejects loopback CONNECTs, so a sandboxed
loopback fixture cannot work by design.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from packages.web.ffuf import FfufConfig, FfufRunner

pytestmark = pytest.mark.skipif(
    shutil.which("ffuf") is None, reason="ffuf binary not on PATH"
)


class _RecordingHandler(BaseHTTPRequestHandler):
    """Serves a tiny deterministic site and records every request."""

    records: list[dict[str, Any]] = []

    def _record(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        record = {
            "method": self.command,
            "path": self.path,
            "host": self.headers.get("Host", ""),
            "authorization": self.headers.get("Authorization", ""),
            "cookie": self.headers.get("Cookie", ""),
            "body": body,
        }
        type(self).records.append(record)
        return record

    def _respond(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve(self) -> None:
        record = self._record()
        if record["host"].startswith("dev."):
            self._respond(200, b"vhost dev backend")
            return
        path = record["path"].split("?", 1)[0]
        if path == "/admin":
            self._respond(200, b"admin panel, quite boring honestly")
            return
        if path == "/backup":
            self._respond(200, b"backup archive index")
            return
        if path == "/login":
            self._respond(200, b"login ok")
            return
        self._respond(404, b"nope")

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._serve()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._serve()

    def log_message(self, *_args: object) -> None:
        pass


@pytest.fixture()
def fixture_server():
    _RecordingHandler.records = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", _RecordingHandler.records
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture()
def direct_ffuf(monkeypatch: pytest.MonkeyPatch):
    """Route run() through a direct subprocess with a proxy-scrubbed env."""
    captured: dict[str, Any] = {}

    def _run(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        env = {
            key: value
            for key, value in os.environ.items()
            if key.lower() not in {"http_proxy", "https_proxy", "all_proxy"}
        }
        env["NO_PROXY"] = "127.0.0.1,localhost"
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=kwargs.get("timeout"),
            env=env,
        )

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", _run)
    return captured


def _wordlist(tmp_path: Path, name: str, words: list[str]) -> Path:
    path = tmp_path / name
    path.write_text("\n".join(words) + "\n", encoding="utf-8")
    return path


def test_live_basic_discovery_finds_planted_paths(
    tmp_path: Path, fixture_server, direct_ffuf
):
    base_url, _records = fixture_server
    wordlist = _wordlist(tmp_path, "dirs.txt", ["admin", "backup", "nosuchpath"])

    runner = FfufRunner(base_url, tmp_path)
    result = runner.run(
        FfufConfig(wordlist=wordlist, threads=2, timeout=5, max_runtime=30)
    )

    assert result["returncode"] == 0, result["stderr"]
    assert result["timed_out"] is False
    hits = {entry["url"].rsplit("/", 1)[-1] for entry in result["results"]}
    assert {"admin", "backup"} <= hits
    assert "nosuchpath" not in hits


def test_live_config_file_credentials_reach_the_wire(
    tmp_path: Path, fixture_server, direct_ffuf
):
    """The -config TOML (which replaced argv -H/-b/-d) must actually be
    parsed and applied by real ffuf: header, cookie, and body arrive on
    the wire while the argv stays credential-free."""
    base_url, records = fixture_server
    wordlist = _wordlist(tmp_path, "params.txt", ["user"])

    runner = FfufRunner(base_url, tmp_path)
    result = runner.run(
        FfufConfig(
            wordlist=wordlist,
            path_template="login",
            method="POST",
            data="name=FUZZ&api_key=live-cred-42",
            headers=("Authorization: Bearer live-tok-42",),
            cookies=("session=live-sess-42",),
            auto_calibration=False,
            threads=1,
            timeout=5,
            max_runtime=30,
        )
    )

    assert result["returncode"] == 0, result["stderr"]
    cmd = direct_ffuf["cmd"]
    assert "-config" in cmd
    assert "-H" not in cmd and "-b" not in cmd and "-d" not in cmd
    posts = [record for record in records if record["method"] == "POST"]
    assert posts, records
    assert any(record["authorization"] == "Bearer live-tok-42" for record in posts)
    assert any("session=live-sess-42" in record["cookie"] for record in posts)
    assert any(
        "name=user" in record["body"] and "api_key=live-cred-42" in record["body"]
        for record in posts
    )


def test_live_clusterbomb_sends_full_product(
    tmp_path: Path, fixture_server, direct_ffuf
):
    base_url, records = fixture_server
    words = _wordlist(tmp_path, "w1.txt", ["alpha", "beta"])
    values = _wordlist(tmp_path, "w2.txt", ["one", "two"])

    runner = FfufRunner(base_url, tmp_path)
    result = runner.run(
        FfufConfig(
            wordlist=words,
            path_template="search?FUZZ=W2",
            extra_wordlists=((values, "W2"),),
            auto_calibration=False,
            threads=1,
            timeout=5,
            max_runtime=30,
        )
    )

    assert result["returncode"] == 0, result["stderr"]
    queries = {
        record["path"].split("?", 1)[1]
        for record in records
        if "?" in record["path"]
    }
    assert queries == {"alpha=one", "alpha=two", "beta=one", "beta=two"}


def test_live_recursion_argv_is_accepted(tmp_path: Path, fixture_server, direct_ffuf):
    """The strict FUZZ-terminated template rule mirrors upstream; the
    emitted -recursion/-maxtime-job/-rate combination must be accepted
    by real ffuf without a config error."""
    base_url, _records = fixture_server
    wordlist = _wordlist(tmp_path, "dirs.txt", ["admin", "nosuchpath"])

    runner = FfufRunner(base_url, tmp_path)
    result = runner.run(
        FfufConfig(
            wordlist=wordlist,
            recursion=True,
            recursion_depth=1,
            auto_calibration=False,
            threads=1,
            timeout=5,
            max_runtime=30,
        )
    )

    assert result["returncode"] == 0, result["stderr"]


def test_live_vhost_reports_matched_host(tmp_path: Path, fixture_server, direct_ffuf):
    base_url, _records = fixture_server
    wordlist = _wordlist(tmp_path, "subs.txt", ["dev", "nosuchsub"])

    runner = FfufRunner(base_url, tmp_path)
    result = runner.run(
        FfufConfig(
            wordlist=wordlist,
            vhost=True,
            auto_calibration=False,
            match_status="200",
            filter_status=None,
            threads=1,
            timeout=5,
            max_runtime=30,
        )
    )

    assert result["returncode"] == 0, result["stderr"]
    hosts = {entry.get("host", "") for entry in result["results"]}
    assert any(host.startswith("dev.") for host in hosts), result["results"]


def test_live_filter_regex_subtracts_matching_bodies(
    tmp_path: Path, fixture_server, direct_ffuf
):
    base_url, _records = fixture_server
    wordlist = _wordlist(tmp_path, "dirs.txt", ["admin", "backup"])

    runner = FfufRunner(base_url, tmp_path)
    result = runner.run(
        FfufConfig(
            wordlist=wordlist,
            filter_regex="quite boring",
            auto_calibration=False,
            threads=1,
            timeout=5,
            max_runtime=30,
        )
    )

    assert result["returncode"] == 0, result["stderr"]
    hits = {entry["url"].rsplit("/", 1)[-1] for entry in result["results"]}
    assert "backup" in hits
    assert "admin" not in hits  # its body matches the filter regex
