"""Static security-audit purpose framing for auxiliary LLM call classes.

The final comparison audit lost two whole call classes to provider
content-policy refusals: every ``summary`` (18/18) and every
``spec_inference`` (19/19) call was rejected with "can't help with
this", while all 36 ``review`` calls succeeded in the same run.

Diffing the prompts explains the split: the review system prompt opens
with the auditor role and walks a full audit methodology ("You are a
security auditor reviewing code", hypothesis steps, tool-evidence
demotion, verdict discipline) — an unmistakable defensive code-review
context. The refused classes presented bare target code plus a
security-flavoured extraction ask ("extract taint flows to
security-sensitive callees", "infer the security specification") with
NO stated purpose or authorization context — the exact shape a
provider's safety layer reads as attack-surface mapping for its own
sake.

:data:`SECURITY_AUDIT_FRAMING` is the distilled context the review
class carries and the auxiliary classes lacked. It is STATIC text —
never interpolated with target-derived content — and is prepended to
the (trusted) system prompt of every auxiliary /audit call class via
:func:`with_audit_framing`, upstream of the prompt envelope: the
envelope discipline (untrusted content in ``UntrustedBlock``/slots,
instructions in system) is unchanged.
"""

from __future__ import annotations

SECURITY_AUDIT_FRAMING = (
    "You are part of RAPTOR's authorized, hypothesis-driven security "
    "audit of a codebase the operator owns or is explicitly authorized "
    "to review. This call is one step of that audit's code-review "
    "pipeline: your structured output feeds deterministic verification "
    "tools (Semgrep, Coccinelle, CodeQL, Joern, SMT) and human triage, "
    "and is used to confirm, refute, and fix potential vulnerabilities "
    "in the reviewed code — standard defensive security-audit work."
)


def with_audit_framing(system: str) -> str:
    """Prepend the audit-purpose framing to *system* (idempotent).

    Idempotence matters because some system prompts are composed from
    already-framed bases (engine-grammar suffixes, correction
    appendices); double framing would waste cached-prefix tokens and
    read as prompt noise.
    """
    if system.startswith(SECURITY_AUDIT_FRAMING):
        return system
    return SECURITY_AUDIT_FRAMING + "\n\n" + system
