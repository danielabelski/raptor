#!/usr/bin/env python3
"""Narrow ffuf integration for RAPTOR web scans.

The runner is intentionally small and opt-in: operators must provide a
wordlist, and RAPTOR constrains the ffuf URL template to the configured target
origin before spawning the external binary.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from core.json.bounded import load_json_bounded
from core.logging import get_logger
from core.sandbox import run_untrusted_networked
from core.security.redaction import is_secret_field_name, redact_secrets

logger = get_logger()

# Byte ceiling for the ffuf results file. ffuf writes it from
# responses served by the attacker-controlled web target, so its
# size is adversary-influenced. Each result row is a small dict —
# even saturated wordlist runs stay far under this cap.
_MAX_FFUF_OUTPUT_BYTES = 64 * 1024 * 1024

# Applied when a request-multiplying mode (recursion, clusterbomb) is
# enabled without an explicit -rate: unbounded fan-out against a live
# target is an operational hazard, not a scanner feature.
DEFAULT_GUARDED_RATE = 50

# Methods ffuf may send. Write methods are permitted here because the
# operator opted in explicitly; policy layers above the engine decide
# whether a run may use them at all.
ALLOWED_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")

# Keyword shape for additional wordlists (-w path:KEYWORD).
WORDLIST_KEYWORD_RE = re.compile(r"^[A-Z][A-Z0-9]*$")

ALLOWED_MODES = ("clusterbomb", "pitchfork")


def parse_wordlist_args(
    raw: tuple[str, ...] | list[str],
) -> tuple[Path, tuple[tuple[Path, str], ...]]:
    """Split repeatable ``--ffuf-wordlist`` values into primary + extras.

    The first entry is the primary wordlist and uses ffuf's implicit
    ``FUZZ`` keyword; every additional entry must carry a
    ``path:KEYWORD`` suffix naming its substitution keyword.
    """
    if not raw:
        msg = "at least one ffuf wordlist is required"
        raise ValueError(msg)

    def split(entry: str) -> tuple[str, str | None]:
        path, sep, suffix = entry.rpartition(":")
        if sep and WORDLIST_KEYWORD_RE.match(suffix):
            return path, suffix
        return entry, None

    primary_path, primary_keyword = split(raw[0])
    if primary_keyword is not None:
        msg = (
            "the first ffuf wordlist uses the implicit FUZZ keyword; "
            "only additional wordlists take a :KEYWORD suffix"
        )
        raise ValueError(msg)

    extras: list[tuple[Path, str]] = []
    for entry in raw[1:]:
        path, keyword = split(entry)
        if keyword is None:
            msg = (
                f"additional ffuf wordlists need a :KEYWORD suffix "
                f"(got {entry!r}); keywords look like W2 or PARAM"
            )
            raise ValueError(msg)
        extras.append((Path(path), keyword))
    return Path(primary_path), tuple(extras)


@dataclass(frozen=True)
class FfufConfig:
    """Configuration for an explicit ffuf content-discovery run."""

    wordlist: Path
    path_template: str = "FUZZ"
    threads: int = 10
    rate: int | None = None
    timeout: int = 30
    max_runtime: int = 300
    report_limit: int = 50
    binary: str = "ffuf"
    auto_calibration: bool = True
    match_status: str | None = "200,204,301,302,307,401,403,405,500"
    filter_status: str | None = "404"
    filter_size: int | None = None
    headers: tuple[str, ...] = ()
    cookies: tuple[str, ...] = ()
    method: str = "GET"
    data: str | None = None
    extra_wordlists: tuple[tuple[Path, str], ...] = ()
    mode: str | None = None
    vhost: bool = False
    vhost_host_template: str | None = None
    stop_on_403: bool = False
    stop_on_spurious: bool = False
    stop_on_all_errors: bool = False
    extensions: tuple[str, ...] = ()
    recursion: bool = False
    recursion_depth: int = 2
    recursion_strategy: str = "default"
    max_runtime_job: int | None = None
    filter_words: int | None = None
    filter_lines: int | None = None
    match_regex: str | None = None
    filter_regex: str | None = None
    match_time: str | None = None
    filter_time: str | None = None


class FfufRunner:
    """Run ffuf against a single in-scope target origin."""

    def __init__(self, base_url: str, out_dir: Path, reveal_secrets: bool = False) -> None:
        self.base_url = base_url.rstrip("/")
        self.out_dir = out_dir
        self.reveal_secrets = reveal_secrets

    def _origin(self, url: str) -> tuple[str, str, int]:
        parsed = urlparse(url)
        default_port = 443 if parsed.scheme == "https" else 80
        return (
            parsed.scheme.lower(),
            (parsed.hostname or "").lower(),
            parsed.port or default_port,
        )

    def _redact(self, value: object) -> str:
        return redact_secrets(value, reveal_secrets=self.reveal_secrets)

    def _redact_cookie_value(self, cookie: str) -> str:
        if self.reveal_secrets:
            return cookie
        parts = []
        for segment in cookie.split(";"):
            prefix = segment[: len(segment) - len(segment.lstrip())]
            stripped = segment.strip()
            if "=" not in stripped:
                parts.append(segment)
                continue
            name, _value = stripped.split("=", 1)
            parts.append(f"{prefix}{name}=[REDACTED]")
        return ";".join(parts)

    def _redact_header_value(self, header: str) -> str:
        if self.reveal_secrets or ":" not in header:
            return self._redact(header)
        name, value = header.split(":", 1)
        normalized = name.strip().lower()
        if normalized in {"authorization", "proxy-authorization"}:
            return f"{name}: [REDACTED]"
        if normalized in {"cookie", "set-cookie"}:
            return f"{name}: {self._redact_cookie_value(value.strip())}"
        if is_secret_field_name(normalized) or normalized in {
            "x-api-key",
            "x-auth-token",
            "x-csrf-token",
        }:
            return f"{name}: [REDACTED]"
        return self._redact(header)

    def _redact_body(self, body: str) -> str:
        """Redact secret-named fields from a form-encoded request body.

        JSON and other non-form bodies fall through to the generic
        pattern-based redactor.
        """
        if self.reveal_secrets:
            return body
        if "=" not in body or body.lstrip().startswith(("{", "[")):
            return self._redact(body)
        segments = []
        for segment in body.split("&"):
            name, sep, _value = segment.partition("=")
            if sep and is_secret_field_name(name.strip().lower()):
                segments.append(f"{name}=[REDACTED]")
            else:
                segments.append(self._redact(segment))
        return "&".join(segments)

    def _redact_command(self, cmd: list[str]) -> list[str]:
        redacted: list[str] = []
        redact_next_cookie = False
        redact_next_body = False
        for part in cmd:
            if redact_next_cookie:
                redacted.append(self._redact_cookie_value(part))
                redact_next_cookie = False
                continue
            if redact_next_body:
                redacted.append(self._redact_body(part))
                redact_next_body = False
                continue
            if part == "-b":
                redacted.append(part)
                redact_next_cookie = True
                continue
            if part == "-d":
                redacted.append(part)
                redact_next_body = True
                continue
            if part == "-H":
                redacted.append(part)
                continue
            if redacted and redacted[-1] == "-H":
                redacted.append(self._redact_header_value(part))
                continue
            redacted.append(self._redact(part))
        return redacted

    def build_url_template(self, path_template: str) -> str:
        """Build and scope-check the ffuf URL template.

        Accepting a raw URL from the CLI without checking it would let a
        saved RAPTOR config or copied command accidentally aim ffuf at a
        different host. Treat the template like WebClient paths: relative
        paths are anchored to ``base_url``; absolute URLs are allowed only
        when their normalized origin matches.

        The URL itself does not have to carry a fuzz keyword — request-body
        and header fuzzing keep the URL fixed. ``build_command`` enforces
        that at least one keyword appears somewhere in the request.

        ``urljoin`` intentionally normalizes ``..`` segments before the origin
        check. That can move a relative template outside the base path while
        staying on the same origin; this integration scopes ffuf to the target
        host/origin rather than to a specific subpath.
        """
        url_template = urljoin(self.base_url + "/", path_template)
        probe_url = url_template.replace("FUZZ", "raptor-scope-probe")
        if self._origin(probe_url) != self._origin(self.base_url):
            msg = (
                "ffuf path template is outside configured target scope: "
                f"{self._redact(probe_url)}"
            )
            raise ValueError(msg)
        return url_template

    @staticmethod
    def _fuzz_keywords(config: FfufConfig) -> tuple[str, ...]:
        """Keywords ffuf will substitute for this configuration."""
        return ("FUZZ", *(keyword for _path, keyword in config.extra_wordlists))

    def _build_vhost_header(self, config: FfufConfig) -> str | None:
        """Synthesize and scope-check the fuzzed Host header for vhost mode.

        The TCP destination stays pinned to the target host by the egress
        proxy regardless — the Host header only selects virtual hosts on
        that same server — but the template is still constrained to
        subdomains of the target so a saved config cannot quietly probe a
        sibling engagement's namespace.
        """
        if not config.vhost:
            return None
        target_host = (urlparse(self.base_url).hostname or "").lower()
        template = config.vhost_host_template or f"FUZZ.{target_host}"
        if "\n" in template or "\r" in template:
            msg = "ffuf vhost host template must not contain newlines"
            raise ValueError(msg)
        keywords = self._fuzz_keywords(config)
        if not any(kw in template for kw in keywords):
            msg = (
                "ffuf vhost host template must contain a wordlist keyword "
                f"(got {template!r})"
            )
            raise ValueError(msg)
        if not template.lower().endswith("." + target_host):
            msg = (
                "ffuf vhost host template must stay under the target host "
                f"(expected a template ending in .{target_host}, "
                f"got {self._redact(template)})"
            )
            raise ValueError(msg)
        return f"Host: {template}"

    @classmethod
    def _require_fuzz_keyword(
        cls,
        config: FfufConfig,
        url_template: str,
        extra_haystacks: tuple[str, ...] = (),
    ) -> None:
        """Every keyword needs a substitution point; a dead wordlist is a
        config error, not a silent no-op."""
        keywords = cls._fuzz_keywords(config)
        haystacks = [url_template, config.data or "", *config.headers, *extra_haystacks]
        missing = [
            kw for kw in keywords
            if not any(kw in haystack for haystack in haystacks)
        ]
        if len(missing) == len(keywords):
            msg = (
                "ffuf configuration has no substitution point: put FUZZ in "
                "the URL template, request body, or a header value"
            )
            raise ValueError(msg)
        if missing:
            msg = (
                f"ffuf wordlist keyword(s) never used: {', '.join(missing)}; "
                "place each keyword in the URL template, request body, or a "
                "header value"
            )
            raise ValueError(msg)

    _TIME_MATCHER_RE = re.compile(r"^[<>]\d+$")

    @staticmethod
    def _validate_config(config: FfufConfig) -> None:
        """Reject configurations that cannot form a safe ffuf argv."""
        if not config.wordlist.is_file():
            msg = f"ffuf wordlist not found: {config.wordlist}"
            raise FileNotFoundError(msg)
        if config.threads < 1:
            msg = "ffuf threads must be >= 1"
            raise ValueError(msg)
        if config.rate is not None and config.rate < 1:
            msg = "ffuf rate must be >= 1 when set"
            raise ValueError(msg)
        if config.timeout < 1:
            msg = "ffuf timeout must be >= 1"
            raise ValueError(msg)
        if config.max_runtime < 1:
            msg = "ffuf max runtime must be >= 1"
            raise ValueError(msg)
        if config.report_limit < 0:
            msg = "ffuf report limit must be >= 0"
            raise ValueError(msg)
        if config.filter_size is not None and config.filter_size < 0:
            msg = "ffuf filter size must be >= 0 when set"
            raise ValueError(msg)
        if config.method.upper() not in ALLOWED_METHODS:
            msg = f"ffuf method must be one of {', '.join(ALLOWED_METHODS)}"
            raise ValueError(msg)
        if config.vhost_host_template is not None and not config.vhost:
            msg = "ffuf vhost host template requires vhost mode"
            raise ValueError(msg)
        if config.vhost and config.recursion:
            msg = (
                "ffuf vhost mode fuzzes the Host header against a fixed URL "
                "and cannot be combined with recursion"
            )
            raise ValueError(msg)
        if config.vhost and any(
            header.split(":", 1)[0].strip().lower() == "host"
            for header in config.headers
            if ":" in header
        ):
            msg = (
                "ffuf vhost mode synthesizes the Host header; remove the "
                "explicit Host header or drop vhost mode"
            )
            raise ValueError(msg)
        if config.mode is not None and config.mode not in ALLOWED_MODES:
            msg = f"ffuf mode must be one of {', '.join(ALLOWED_MODES)}"
            raise ValueError(msg)
        if config.mode is not None and not config.extra_wordlists:
            msg = "ffuf mode requires additional wordlists (-w path:KEYWORD)"
            raise ValueError(msg)
        keywords = ["FUZZ"]
        for path, keyword in config.extra_wordlists:
            if not path.is_file():
                msg = f"ffuf wordlist not found: {path}"
                raise FileNotFoundError(msg)
            if not WORDLIST_KEYWORD_RE.match(keyword):
                msg = (
                    f"ffuf wordlist keyword {keyword!r} must be uppercase "
                    "alphanumeric starting with a letter (e.g. W2, PARAM)"
                )
                raise ValueError(msg)
            keywords.append(keyword)
        if len(set(keywords)) != len(keywords):
            msg = "ffuf wordlist keywords must be unique (FUZZ is reserved for the primary)"
            raise ValueError(msg)
        for kw in keywords:
            for other in keywords:
                if kw != other and kw in other:
                    # ffuf substitutes keywords as raw strings; FUZZ inside
                    # FUZZ2 would corrupt the other keyword's placeholder.
                    msg = (
                        f"ffuf wordlist keyword {kw!r} is a substring of "
                        f"{other!r}; keywords must not contain each other"
                    )
                    raise ValueError(msg)
        if config.recursion_depth < 1:
            msg = "ffuf recursion depth must be >= 1"
            raise ValueError(msg)
        if config.recursion_strategy not in ("default", "greedy"):
            msg = "ffuf recursion strategy must be 'default' or 'greedy'"
            raise ValueError(msg)
        if config.max_runtime_job is not None and config.max_runtime_job < 1:
            msg = "ffuf max runtime per job must be >= 1 when set"
            raise ValueError(msg)
        if config.filter_words is not None and config.filter_words < 0:
            msg = "ffuf filter words must be >= 0 when set"
            raise ValueError(msg)
        if config.filter_lines is not None and config.filter_lines < 0:
            msg = "ffuf filter lines must be >= 0 when set"
            raise ValueError(msg)
        for label, ext in (("extension", e) for e in config.extensions):
            if (
                len(ext) < 2
                or not ext.startswith(".")
                or any(c in ext for c in ",\n\r\t ")
            ):
                msg = (
                    f"ffuf {label} must look like '.php' "
                    f"(got {ext!r}): leading dot, no commas or whitespace"
                )
                raise ValueError(msg)
        for label, value in (
            ("match regex", config.match_regex),
            ("filter regex", config.filter_regex),
        ):
            # Deliberately not compiled here: ffuf uses Go regexp, and
            # Python acceptance is neither necessary nor sufficient.
            # ffuf's own config error surfaces through the returncode.
            if value is not None and ("\n" in value or "\r" in value):
                msg = f"ffuf {label} must not contain newlines"
                raise ValueError(msg)
        for label, value in (
            ("match time", config.match_time),
            ("filter time", config.filter_time),
        ):
            if value is not None and not FfufRunner._TIME_MATCHER_RE.match(value):
                msg = f"ffuf {label} must look like '>100' or '<100' (milliseconds)"
                raise ValueError(msg)
        if any("\n" in header or "\r" in header for header in config.headers):
            msg = "ffuf headers must not contain newlines"
            raise ValueError(msg)
        if any("\n" in cookie or "\r" in cookie for cookie in config.cookies):
            msg = "ffuf cookies must not contain newlines"
            raise ValueError(msg)
        if any(
            ":" not in header or not header.split(":", 1)[0].strip()
            for header in config.headers
        ):
            msg = "ffuf headers must be in 'Name: value' form"
            raise ValueError(msg)

    def build_command(self, config: FfufConfig, output_file: Path) -> list[str]:
        """Return argv for a safe, non-shell ffuf invocation."""
        self._validate_config(config)

        # In vhost mode the URL is fixed and the Host header carries the
        # keyword; the dataclass default path template of "FUZZ" would
        # otherwise force a URL substitution point that vhost mode forbids.
        path_template = config.path_template
        if config.vhost and path_template == "FUZZ":
            path_template = ""
        url_template = self.build_url_template(path_template)
        vhost_header = self._build_vhost_header(config)
        if config.vhost and any(
            kw in url_template for kw in self._fuzz_keywords(config)
        ):
            msg = (
                "ffuf vhost mode fuzzes the Host header; remove wordlist "
                "keywords from the URL template or drop vhost mode"
            )
            raise ValueError(msg)
        self._require_fuzz_keyword(
            config,
            url_template,
            extra_haystacks=(vhost_header,) if vhost_header else (),
        )
        if config.recursion and not url_template.rstrip("/").endswith("FUZZ"):
            # ffuf constraint: recursion re-queues discovered directories
            # by substituting the FUZZ keyword at the end of the URL path.
            msg = (
                "ffuf recursion requires the URL template to end with FUZZ "
                f"(got {self._redact(url_template)})"
            )
            raise ValueError(msg)
        cmd = [
            config.binary,
            "-u",
            url_template,
            "-w",
            str(config.wordlist),
            "-of",
            "json",
            "-o",
            str(output_file),
            "-noninteractive",
            "-t",
            str(config.threads),
            "-timeout",
            str(config.timeout),
            # ffuf-side runtime cap: ffuf exits cleanly at -maxtime and
            # flushes its JSON report. The Python-side subprocess timeout
            # (see run()) is only a backstop with a grace window — if it
            # fired first, the kill would discard the report.
            "-maxtime",
            str(config.max_runtime),
        ]
        if config.stop_on_403:
            cmd.append("-sf")
        if config.stop_on_spurious:
            cmd.append("-se")
        if config.stop_on_all_errors:
            cmd.append("-sa")
        if config.auto_calibration:
            cmd.append("-ac")
        if config.match_status:
            cmd.extend(["-mc", config.match_status])
        if config.filter_status:
            cmd.extend(["-fc", config.filter_status])
        if config.filter_size is not None:
            cmd.extend(["-fs", str(config.filter_size)])
        if config.filter_words is not None:
            cmd.extend(["-fw", str(config.filter_words)])
        if config.filter_lines is not None:
            cmd.extend(["-fl", str(config.filter_lines)])
        if config.match_regex is not None:
            cmd.extend(["-mr", config.match_regex])
        if config.filter_regex is not None:
            cmd.extend(["-fr", config.filter_regex])
        if config.match_time is not None:
            cmd.extend(["-mt", config.match_time])
        if config.filter_time is not None:
            cmd.extend(["-ft", config.filter_time])
        if config.extensions:
            cmd.extend(["-e", ",".join(config.extensions)])
        if config.method.upper() != "GET":
            cmd.extend(["-X", config.method.upper()])
        if config.data:
            cmd.extend(["-d", config.data])
        for header in config.headers:
            cmd.extend(["-H", header])
        if vhost_header is not None:
            cmd.extend(["-H", vhost_header])
        for cookie in config.cookies:
            cmd.extend(["-b", cookie])
        for extra_path, keyword in config.extra_wordlists:
            cmd.extend(["-w", f"{extra_path}:{keyword}"])
        if config.extra_wordlists:
            # Emit the mode explicitly (ffuf would default to clusterbomb)
            # so the argv in logs and audit trails is self-describing.
            cmd.extend(["-mode", config.mode or "clusterbomb"])
        if config.recursion:
            cmd.append("-recursion")
            cmd.extend(["-recursion-depth", str(config.recursion_depth)])
            cmd.extend(["-recursion-strategy", config.recursion_strategy])
        max_runtime_job = config.max_runtime_job
        if max_runtime_job is None and config.recursion:
            # One hot directory must not consume the whole -maxtime budget.
            max_runtime_job = max(60, config.max_runtime // 4)
        if max_runtime_job is not None:
            cmd.extend(["-maxtime-job", str(max_runtime_job)])
        rate = config.rate
        if rate is None:
            # Pitchfork iterates wordlists in lockstep and does not
            # multiply request counts; clusterbomb and recursion do.
            if config.recursion:
                guard_reason = "recursion"
            elif config.extra_wordlists and (config.mode or "clusterbomb") == "clusterbomb":
                guard_reason = "clusterbomb multi-wordlist mode"
            else:
                guard_reason = None
            if guard_reason is not None:
                rate = DEFAULT_GUARDED_RATE
                logger.info(
                    "ffuf %s enabled with no explicit rate limit; applying "
                    "default -rate %d req/s (pass --ffuf-rate to override)",
                    guard_reason,
                    rate,
                )
        if rate is not None:
            cmd.extend(["-rate", str(rate)])
        return cmd

    def run(self, config: FfufConfig) -> dict[str, Any]:
        """Run ffuf in RAPTOR's sandbox and return a compact result summary.

        ffuf exits non-zero for several operational conditions (no matches,
        interrupted run, config error). RAPTOR keeps the raw JSON artifact when
        present and reports the return code instead of treating every non-zero
        as a scanner crash.
        """
        binary_path = shutil.which(config.binary)
        if binary_path is None:
            msg = (
                f"ffuf binary not found on PATH: {config.binary}. "
                "Install ffuf or pass --ffuf-bin."
            )
            raise FileNotFoundError(msg)
        # Exec via the REAL path: go-install / package-manager setups
        # put a symlink on PATH; the mount-ns visibility check
        # realpaths cmd[0] and the tool_paths bind must carry the
        # RESOLVED parent, or the run silently drops to the
        # Landlock-only fallback tier (selftest-05 scanner precedent).
        binary_path = os.path.realpath(binary_path)

        target_host = (urlparse(self.base_url).hostname or "").lower()
        if not target_host:
            msg = "ffuf base URL must include a hostname"
            raise ValueError(msg)

        self.out_dir.mkdir(parents=True, exist_ok=True)
        output_file = self.out_dir / "ffuf_results.json"
        cmd = self.build_command(config, output_file)
        # build_command uses the operator-facing name; swap in the
        # resolved real path for the exec.
        cmd[0] = binary_path
        redacted_cmd = self._redact_command(cmd)
        logger.info("Running sandboxed ffuf: %s", ' '.join(redacted_cmd))

        # ffuf's own -maxtime (== max_runtime) is the real cap; the
        # subprocess timeout is a backstop for a wedged process. It gets
        # a grace window so ffuf can exit cleanly and flush its report —
        # a backstop kill loses whatever ffuf had not yet written.
        grace = min(30, max(5, config.max_runtime // 10))
        timed_out = False
        returncode: int | None = None
        stderr_text = ""
        try:
            wordlist_dirs = list(dict.fromkeys(
                [str(config.wordlist.parent)]
                + [str(path.parent) for path, _keyword in config.extra_wordlists]
            ))
            completed = run_untrusted_networked(
                cmd,
                target=str(config.wordlist.parent),
                output=str(self.out_dir),
                readable_paths=wordlist_dirs,
                proxy_hosts=[target_host],
                fake_home=True,
                tool_paths=[str(Path(binary_path).parent)],
                caller_label="web-ffuf",
                timeout=config.max_runtime + grace,
                capture_output=True,
                text=True,
            )
            returncode = completed.returncode
            stderr_text = completed.stderr or ""
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stderr_raw = exc.stderr
            if isinstance(stderr_raw, bytes):
                stderr_text = stderr_raw.decode("utf-8", errors="replace")
            else:
                stderr_text = stderr_raw or ""
            logger.warning(
                "ffuf did not exit at -maxtime %ds; killed after %ds grace, "
                "keeping any partial results",
                config.max_runtime,
                grace,
            )

        results: list[dict[str, Any]] = []
        if output_file.exists():
            try:
                # Size-gated BEFORE the read: an over-budget results
                # file raises with the observed size and is reported
                # below like any other unparseable output.
                parsed = load_json_bounded(
                    output_file, max_bytes=_MAX_FFUF_OUTPUT_BYTES,
                )
                if isinstance(parsed, dict):
                    raw_results = parsed.get("results") or []
                    if isinstance(raw_results, list):
                        results = [r for r in raw_results if isinstance(r, dict)]
            except ValueError as exc:
                # Malformed JSON, undecodable bytes, or over budget.
                logger.warning("Could not parse ffuf JSON output: %s", exc)

        summarized_results = [self._summarize_result(r) for r in results[: config.report_limit]]
        return {
            "tool": "ffuf",
            "returncode": returncode,
            "timed_out": timed_out,
            "output_file": str(output_file),
            "result_count": len(results),
            "reported_result_count": len(summarized_results),
            "omitted_result_count": max(0, len(results) - len(summarized_results)),
            "results": summarized_results,
            "stderr": self._redact(stderr_text.strip()),
        }

    def _summarize_result(self, result: dict[str, Any]) -> dict[str, Any]:
        """Keep ffuf report entries compact and secret-redacted."""
        summary = {
            "url": self._redact(result.get("url", "")),
            "status": result.get("status"),
            "length": result.get("length"),
            "words": result.get("words"),
            "lines": result.get("lines"),
        }
        # vhost runs answer "which Host matched", not "which URL": ffuf
        # reports the substituted Host value in the per-result host field.
        host = result.get("host")
        if host:
            summary["host"] = self._redact(host)
        return summary
