"""Mechanical semgrep rules from derived source-wrapper summaries.

CodeQL consumes source-wrapper summaries as models-as-data rows, but
some sink classes never fire on buildless Java databases (measured:
``java/xss`` finds nothing on the corpus where the semgrep taint rule
finds hundreds). For those classes the wrapper-source knowledge must
reach semgrep: this module projects each derived summary into a
typed-receiver taint SOURCE pattern and pairs it with the sink and
sanitizer blocks of RAPTOR's own in-repo rules.

Strictly mechanical and additive: the sources come from
``core.analysis.java_source_summaries`` proofs, the sink/sanitizer
blocks are fixed data mirroring ``engine/semgrep/rules`` content (a
sync test pins each pattern to the origin rule file so drift breaks
the build), and the generated YAML is written under the RUN OUTPUT
DIRECTORY — never into the rules tree, never registry content.
"""

from __future__ import annotations

import json
from typing import Iterable, List, Sequence

#: Sink/sanitizer blocks mirrored from in-repo rules. Origin:
#: engine/semgrep/rules/injection/xss.yaml (raptor.injection.xss.taint.java)
#: — the sync test asserts every pattern below appears there verbatim.
XSS_SINKS: Sequence[str] = (
    "(HttpServletResponse $RESP).getWriter().write($X)",
    "(HttpServletResponse $RESP).getWriter().write($X, ...)",
    "(HttpServletResponse $RESP).getWriter().println($X)",
    "(HttpServletResponse $RESP).getWriter().print($X)",
    "(HttpServletResponse $RESP).getOutputStream().write(...)",
    "(HttpServletResponse $RESP).getWriter().format(...)",
    "(PrintWriter $PW).format(...)",
    "(PrintWriter $PW).write($X)",
    "(PrintWriter $PW).println($X)",
    "(PrintWriter $PW).print($X)",
)

XSS_SANITIZERS: Sequence[str] = (
    "StringEscapeUtils.escapeHtml4(...)",
    "HtmlUtils.htmlEscape(...)",
    "Encode.forHtml(...)",
    "Encode.forHtmlContent(...)",
    "Encode.forHtmlAttribute(...)",
    "org.owasp.encoder.Encode.forHtml(...)",
    "ESAPI.encoder().encodeForHTML(...)",
    "org.owasp.esapi.ESAPI.encoder().encodeForHTML(...)",
    "(Encoder $ENC).encodeForHTML(...)",
)

#: Collection round-trip propagators mirrored from the origin java
#: taint rules (engine/semgrep/rules/injection/xss.yaml et al.) —
#: the sync test pins each against its origin.
COLLECTION_PROPAGATORS: Sequence[dict] = (
    {"pattern": "$M.put($K, $V)", "from": "$V", "to": "$M"},
    {"pattern": "$M.add($V)", "from": "$V", "to": "$M"},
)

#: Origin: engine/semgrep/rules/java/trust-boundary.yaml
#: (raptor.java.trust-boundary-session-write).
TRUST_BOUNDARY_SINKS: Sequence[str] = (
    "(HttpSession $SESS).setAttribute(...)",
    "(HttpSession $SESS).putValue(...)",
    "(HttpServletRequest $REQ).getSession().setAttribute(...)",
    "(HttpServletRequest $REQ).getSession(...).setAttribute(...)",
    "(HttpServletRequest $REQ).getSession().putValue(...)",
    "(HttpServletRequest $REQ).getSession(...).putValue(...)",
    "(ServletContext $CTX).setAttribute(...)",
)


def _source_patterns(summaries) -> List[str]:
    out: List[str] = []
    seen = set()
    for s in summaries:
        # Both typed-receiver spellings: semgrep's type matching is
        # syntactic against the DECLARED type text, so a call site
        # declaring the helper by its fully-qualified name only
        # matches the FQN form (verified live on the corpus), while
        # an imported simple-name declaration needs the simple form.
        variants = [f"({s.owner} $W).{s.name}(...)"]
        if s.package:
            variants.append(f"({s.package}.{s.owner} $W).{s.name}(...)")
        for pat in variants:
            if pat not in seen:
                seen.add(pat)
                out.append(pat)
    return out


def _taint_rule(rule_id: str, message: str, cwe: str,
                sources: Sequence[str], sinks: Sequence[str],
                sanitizers: Sequence[str]) -> dict:
    rule = {
        "id": rule_id,
        "message": message,
        "languages": ["java"],
        "severity": "WARNING",
        "mode": "taint",
        "pattern-sources": [
            {"pattern-either": [{"pattern": p} for p in sources]},
        ],
        "pattern-sinks": [
            {"pattern-either": [{"pattern": p} for p in sinks]},
        ],
        "metadata": {
            "cwe": [cwe],
            "provenance": "mechanical-source-summary",
            "tags": ["security", "taint", "source-wrapper"],
        },
    }
    if sanitizers:
        rule["pattern-sanitizers"] = [{"pattern": p} for p in sanitizers]
    rule["pattern-propagators"] = [dict(p) for p in COLLECTION_PROPAGATORS]
    return rule


def generate_rules_yaml(summaries: Iterable) -> str | None:
    """Semgrep rules YAML for the derived summaries, or ``None`` when
    there is nothing to project. Emitted as JSON (a YAML subset) so no
    YAML-emitter quoting surprises can reshape learned identifiers."""
    summaries = list(summaries)
    if not summaries:
        return None
    sources = _source_patterns(summaries)
    doc = {"rules": [
        _taint_rule(
            "raptor.generated.source-wrapper.xss",
            "Untrusted data from a project source-wrapper flows into an "
            "HTML response without escaping (wrapper source derived "
            "mechanically; see core/analysis/java_source_summaries).",
            "CWE-79", sources, XSS_SINKS, XSS_SANITIZERS,
        ),
        _taint_rule(
            "raptor.generated.source-wrapper.trust-boundary",
            "Untrusted data from a project source-wrapper is stored into "
            "a trusted context (session/servlet context).",
            "CWE-501", sources, TRUST_BOUNDARY_SINKS, (),
        ),
    ]}
    return json.dumps(doc, indent=1)
