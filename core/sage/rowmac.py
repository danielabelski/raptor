"""HMAC authentication for SAGE rows consumed mechanically.

Every mechanical hook in ``core/sage/hooks.py`` turns recalled free text
into a hard machine decision (skip an LLM call, suppress a finding,
append argv flags, replay a build command). Memory content is written by
multiple flows — including reflection of LLM output and federated peers
— so a poisoned row would otherwise become machine behaviour. Rows
intended for mechanical consumption therefore carry an HMAC token only
this install can mint; rows without a valid token demote to
human-visible hints.

Key
    ``$XDG_DATA_HOME/raptor/rowmac.key`` (default
    ``~/.local/share/raptor/rowmac.key``). 32 random bytes, file mode
    0600, directory 0700. Created by ``libexec/raptor-sage-setup`` on
    install and ALSO lazily (``O_EXCL``, race-tolerant) on first use, so
    non-setup installs work regardless of ordering. The key deliberately
    lives OUTSIDE the repo tree: several sandbox profiles grant children
    repo-root read, and a sandboxed target that could read an in-repo
    key could mint valid tokens for poisoned rows — defeating the
    mechanism. The per-user XDG data dir is outside every
    sandbox-readable target tree. There is no rotation: deleting the
    key simply makes every existing token fail verification, demoting
    old rows to hints until new outcomes are stored — that IS the reset
    semantics.

Token transport
    SAGE rows are free text (typed metadata may not round-trip
    faithfully across server versions), so the token is embedded in the
    content as a trailing `` [mac:<64 hex>]``. Consumers call
    :func:`strip` before any regex parsing, re-derive the decision
    fields from the parsed values, and :func:`verify` them against the
    token.

What is MAC'd
    The MAC covers a canonical, injective, length-prefixed encoding of
    the DECISION FIELDS only — the exact values the consumer acts on —
    never the surrounding prose. Recall may re-wrap the row or drift its
    metadata; prose is not what the machine consumes.

Legacy rows
    Rows stored before this mechanism existed carry no token and
    therefore lose mechanical effect the day it lands; they re-earn it
    as new outcomes are stored. That transition is deliberate — memories
    decay anyway, and nothing breaks: the hooks behave exactly as if no
    memory existed.

Federated / foreign rows can never verify (different key) — correct by
default; SAGE's inbox contract already declares federated content
untrusted.
"""

import hashlib
import hmac
import os
import re
import secrets
import time
from collections.abc import Mapping
from pathlib import Path

_KEY_LEN = 32

# Trailing token appended by stamp(); strip() removes it (and any
# whitespace immediately before it) from the end of the content.
_TOKEN_RE = re.compile(r"\s*\[mac:([0-9a-f]{64})\]\s*$")


def _key_path() -> Path:
    """Location of the per-install row-MAC key.

    ``$XDG_DATA_HOME/raptor/rowmac.key`` (default
    ``~/.local/share/raptor/rowmac.key``). Deliberately NOT anchored to
    the repo tree: sandboxed children hold repo-root read in several
    profiles, and the key must stay outside every sandbox-readable
    tree or a scanned target could mint valid row MACs.
    """
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "raptor" / "rowmac.key"


def _load_or_create_key() -> bytes:
    """Read the key, lazily creating it (0700 dir, 0600 file) if absent.

    Creation uses ``O_EXCL`` so concurrent first-users race safely: the
    loser re-reads whatever the winner wrote. A briefly-empty file (the
    winner is between ``open`` and ``write``) is retried a few times;
    after that whatever is on disk is used as-is — a short or corrupt
    key is still used consistently by both mint and verify, so the
    worst case is that tokens minted before repair stop verifying
    (the demote path, never an error).
    """
    path = _key_path()
    try:
        data = path.read_bytes()
    except OSError:
        data = b""
    if len(data) == _KEY_LEN:
        return data

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = secrets.token_bytes(_KEY_LEN)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Lost the creation race — re-read the winner's key.
        for _ in range(20):
            try:
                data = path.read_bytes()
            except OSError:
                data = b""
            if data:
                return data
            time.sleep(0.01)
        return data
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key


def _canonical(fields: Mapping[str, object]) -> bytes:
    """Injective canonical encoding of the decision fields.

    Key-sorted so insertion order never matters, and every key and
    value is length-prefixed so no combination of embedded separators
    or moved characters can collide with a different field map.
    """
    items = sorted((str(k), str(v)) for k, v in fields.items())
    out = bytearray()
    out += len(items).to_bytes(4, "big")
    for key, value in items:
        for part in (key.encode("utf-8"), value.encode("utf-8")):
            out += len(part).to_bytes(4, "big")
            out += part
    return bytes(out)


def mint(fields: Mapping[str, object]) -> str:
    """Return the hex HMAC-SHA256 token over the decision *fields*.

    Recreates the key lazily if it is missing (so a deleted key means
    old tokens fail verification while new stores keep working).
    """
    key = _load_or_create_key()
    return hmac.new(key, _canonical(fields), hashlib.sha256).hexdigest()


def verify(fields: Mapping[str, object], token: str | None) -> bool:
    """Whether *token* is a valid MAC over *fields* under this install's key.

    Constant-time comparison. Never raises: any failure (missing token,
    unreadable key, malformed input) returns False — the caller's
    demote path.
    """
    if not token:
        return False
    try:
        expected = mint(fields)
        return hmac.compare_digest(expected, str(token).strip().lower())
    except Exception:  # noqa: BLE001 — verification failure is the demote path, never an error
        return False


def stamp(content: str, fields: Mapping[str, object]) -> str:
    """Append `` [mac:<hex>]`` for *fields* to *content*."""
    return f"{content} [mac:{mint(fields)}]"


def strip(content: str) -> tuple[str, str | None]:
    """Split *content* into (clean text, token or None).

    Idempotent: text without a trailing token comes back unchanged with
    ``None``. Only the trailing token is consumed, so a quoted token in
    the middle of prose stays part of the text (and can never verify as
    that row's own token unless the fields genuinely match).
    """
    text = content or ""
    match = _TOKEN_RE.search(text)
    if not match:
        return (text, None)
    return (text[: match.start()], match.group(1))
