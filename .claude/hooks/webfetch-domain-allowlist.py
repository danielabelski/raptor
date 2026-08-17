#!/usr/bin/env python3
"""PreToolUse hook: enforce a per-agent WebFetch domain allowlist.

Wired via the ``hooks:`` frontmatter of individual agent definitions
(.claude/agents/*.md) so the restriction is scoped to one agent, not
the whole session. The harness's declarative ``WebFetch(domain:...)``
permission rules are settings-scope (session-wide) only; per-agent
``PreToolUse`` hooks are the documented mechanism for per-agent tool
narrowing.

Usage (in agent frontmatter):

    hooks:
      PreToolUse:
        - matcher: WebFetch
          hooks:
            - type: command
              command: "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/webfetch-domain-allowlist.py github.com api.github.com"

Arguments are the allowed hostnames (case-insensitive exact match).
With ``--https-any`` instead of a hostname list, any host is allowed
but the scheme must be https (used by agents that fetch
operator-supplied URLs on arbitrary vendor domains).

Contract (Claude Code PreToolUse hooks):
  stdin  — JSON with ``tool_name`` and ``tool_input`` (``url`` key).
  exit 0 — allow the call.
  exit 2 — block the call; stderr is fed back to the agent.

Fail-closed: unparseable input or a missing/relative URL is blocked.
"""

import json
import sys
from urllib.parse import urlsplit


def main(argv: list[str]) -> int:
    https_any = "--https-any" in argv
    allowed = {a.lower() for a in argv if not a.startswith("--")}

    try:
        payload = json.load(sys.stdin)
    except ValueError:
        sys.stderr.write(
            "webfetch-domain-allowlist: unparseable hook input; "
            "blocking the WebFetch call (fail-closed).\n"
        )
        return 2

    tool_input = payload.get("tool_input")
    url = tool_input.get("url") if isinstance(tool_input, dict) else None
    if not isinstance(url, str) or not url.strip():
        sys.stderr.write(
            "webfetch-domain-allowlist: no url in tool input; "
            "blocking the WebFetch call (fail-closed).\n"
        )
        return 2

    try:
        parts = urlsplit(url.strip())
    except ValueError:
        sys.stderr.write(
            f"webfetch-domain-allowlist: unparseable url {url!r}; "
            "blocking the WebFetch call (fail-closed).\n"
        )
        return 2

    if parts.scheme.lower() != "https":
        sys.stderr.write(
            f"webfetch-domain-allowlist: scheme {parts.scheme!r} denied — "
            "this agent may only fetch https:// URLs.\n"
        )
        return 2

    if https_any:
        return 0

    host = (parts.hostname or "").lower().rstrip(".")
    if host in allowed:
        return 0

    sys.stderr.write(
        f"webfetch-domain-allowlist: host {host!r} is not in this agent's "
        f"allowlist ({', '.join(sorted(allowed))}). The fetch was blocked. "
        "If the investigation genuinely requires this host, report that to "
        "the orchestrator/operator instead of retrying.\n"
    )
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
