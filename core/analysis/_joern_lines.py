"""Transport-tolerant parsing of Joern ``MARKER:{json}`` record lines.

Joern queries emit one ``MARKER:{json}`` record per line, println'd for
the ``joern --script`` subprocess transport AND carried in the final
expression's string echo for the server transport (``/query-sync``
returns the final-expression echo but not println output).  The echo
framing varies by REPL version and string shape:

* multi-line strings echo triple-quoted: the FIRST line is prefixed
  ``val resN: String = \"\"\"`` (record content raw) and the LAST line
  carries a trailing ``\"\"\"``;
* short strings echo single-quoted on ONE line with Java-escaped
  content (``val resN: String = "MARKER:{\\"k\\":...}"``) — quotes
  escaped, embedded newlines rendered as ``\\n`` sequences;
* INTERMEDIATE binders echo too: a top-level
  ``val flowLines = ...`` statement echoes as
  ``val flowLines: List[String] = List(`` followed by one Java-escaped
  ``"MARKER:...",`` element per line (or the whole List inline for a
  single short element), closed by ``)`` framing lines;
* subprocess transcripts can carry BOTH the println copy and a value
  echo of the same records;
* ANSI colour codes may wrap any of it.

``startswith(marker)`` parsers missed the first echoed record and
raised "Extra data" on the last; this module is the one place that
knows the echo shapes, shared by every marker-record parser
(reachability gates, hunt call-site enumeration, the flow parser in
``packages.joern.runner``).
"""

from __future__ import annotations

import json
import re
from typing import Any

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Scala REPL value-echo prefix, anchored to the exact echo shape
# (binder ``resN``, declared type String, opening quote). Scanned-repo
# text inside a record payload can only reach echo handling when the
# record ALSO fails strict JSON parsing, which the emit-side jsonEsc
# discipline prevents for genuinely printed records.
_ECHO_PREFIX_RE = re.compile(r'\bval res\d+: String = "')

# List-binder value echo framing. An element line of a multi-line List
# echo is optional indentation followed by the element's OPENING quote
# (genuinely printed records start AT the marker, never behind a
# quote); the inline form starts with the binder declaration itself
# (``val flowLines: List[String] = List("...")``). Payload text inside
# a printed record cannot reach this branch without ALSO failing
# strict JSON parsing first, same as the resN prefix rule above.
_LIST_ECHO_LINE_RE = re.compile(r'^\s*"|^val \w+: \S+ = \w+\(')


def strip_ansi(text: str) -> str:
    """Remove ANSI colour codes."""
    return _ANSI_RE.sub("", text)


def _unescape_echo_body(body: str) -> str | None:
    """One unescape round of an echoed string-literal body.

    The echo body is Java-escaped — JSON string escaping is a
    compatible subset, so one loads round undoes it.  ``None`` when the
    body does not decode (width-truncated echo, dangling backslash).
    """
    try:
        text = json.loads('"' + body + '"')
    except ValueError:
        return None
    return text if isinstance(text, str) else None


def _marker_records_in_text(text: str, marker: str) -> list[Any]:
    """Strict-parse every marker record in already-unescaped text.

    Segments that fail to parse are skipped: by the time text reaches
    here the line is established echo, and unrecoverable echo is noise
    (a RE-print of records), never an error.
    """
    records: list[Any] = []
    for segment in text.splitlines():
        idx = segment.find(marker)
        if idx < 0:
            continue
        try:
            records.append(json.loads(segment[idx + len(marker):].strip()))
        except ValueError:
            continue
    return records


def _recover_echo_records(
    plain_line: str,
    marker_idx: int,
    marker: str,
) -> list[Any] | None:
    """Recover records from a single-line Java-escaped value echo.

    Returns ``None`` when the line is not echo-shaped (no
    ``val resN: String = "`` before the marker); otherwise the records
    recovered after one unescape round — possibly empty.  An echo that
    stays unrecoverable is expected noise, never an error: it is a
    RE-print of records, not the printing of new ones.
    """
    m = _ECHO_PREFIX_RE.search(plain_line[:marker_idx])
    if m is None:
        return None
    interior = plain_line[m.end():].rstrip().rstrip('"')
    text = _unescape_echo_body(interior)
    if text is None:
        return []
    return _marker_records_in_text(text, marker)


def _scan_string_literal_bodies(line: str) -> list[str]:
    """Bodies of double-quote-delimited literals in *line*, escape-aware.

    A backslash escapes the next character, so ``\\"`` inside a body
    never terminates it.  An unterminated trailing literal (a
    width-truncated echo) is returned as-is — its recovery attempt then
    fails, silently.
    """
    bodies: list[str] = []
    start: int | None = None
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if start is None:
            if ch == '"':
                start = i + 1
        elif ch == "\\":
            i += 1
        elif ch == '"':
            bodies.append(line[start:i])
            start = None
        i += 1
    if start is not None:
        bodies.append(line[start:])
    return bodies


def _recover_list_echo_records(
    plain_line: str,
    marker: str,
) -> list[Any] | None:
    """Recover records from a List-binder value echo line.

    Returns ``None`` when the line is not binder-echo shaped
    (:data:`_LIST_ECHO_LINE_RE`); otherwise the records recovered from
    every marker-bearing string literal on the line — possibly empty.
    Recovery requires each literal body to survive one unescape round
    AND yield strictly-parsing marker JSON; a genuinely printed record
    carries raw quote delimiters and no binder framing, so it can never
    read as this shape.
    """
    if _LIST_ECHO_LINE_RE.match(plain_line) is None:
        return None
    records: list[Any] = []
    for body in _scan_string_literal_bodies(plain_line):
        if marker not in body:
            continue
        text = _unescape_echo_body(body)
        if text is None:
            continue
        records.extend(_marker_records_in_text(text, marker))
    return records


def parse_marker_line(line: str, marker: str) -> tuple[list[Any], str | None]:
    """Parse one stdout line for *marker* records.

    Returns ``(records, error)``.  ``records`` is empty when the line
    carries no marker or is unrecoverable echo noise; ``error``
    describes a genuinely printed record that failed to decode — a
    dropped record the caller must surface.  Echo lines never error.
    """
    plain = strip_ansi(line)
    idx = plain.find(marker)
    if idx < 0:
        return [], None
    # A record payload always ends at '}' / ']' — trailing quotes are
    # REPL echo framing (the closing \"\"\" of a multi-line value echo).
    payload = plain[idx + len(marker):].strip().rstrip('"')
    try:
        return [json.loads(payload)], None
    except ValueError as exc:
        recovered = _recover_echo_records(plain, idx, marker)
        if recovered is None:
            recovered = _recover_list_echo_records(plain, marker)
        if recovered is not None:
            return recovered, None
        return [], f"unparseable {marker} payload {payload[:200]!r}: {exc}"


def parse_marker_records(
    raw_output: str,
    marker: str,
) -> tuple[list[Any], list[str]]:
    """Parse every *marker* record in *raw_output*, deduplicated.

    Dedup is by canonical JSON: a transcript carrying both the println
    copy and a recovered echo copy of the same record must yield it
    once.  Returns ``(records, errors)`` — errors only for genuinely
    printed records that failed to decode.
    """
    records: list[Any] = []
    errors: list[str] = []
    seen: set[str] = set()
    for line in (raw_output or "").splitlines():
        recs, err = parse_marker_line(line, marker)
        if err is not None:
            errors.append(err)
        for rec in recs:
            key = json.dumps(rec, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            records.append(rec)
    return records, errors
