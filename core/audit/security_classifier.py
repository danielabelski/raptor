"""Phase 2: security impact classification for bug-first mode.

After Phase 1 finds all defects (mode-agnostic), Phase 2 classifies
which defects have security impact.  Each finding/suspicious outcome
is evaluated against the domain model's security context — privilege
level, attack surface, trust boundaries, isolation.

The classifier adds ``security_impact`` to the outcome's review_result.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from core.llm.coerce import structured_result

logger = logging.getLogger(__name__)


CLASSIFICATION_SCHEMA = {
    "type": "object",
    "properties": {
        "rationale": {
            "type": "string",
            "description": "Why this is or is not security-impacting.",
        },
        "primitive": {
            "type": "string",
            "enum": [
                "read", "write", "execute", "auth_bypass",
                "dos", "info_leak", "none",
            ],
            "description": (
                "The attacker primitive this defect provides, if "
                "security-impacting.  'none' for quality findings."
            ),
        },
        "classification": {
            "type": "string",
            "enum": ["security_finding", "quality_finding"],
            "description": (
                "security_finding = the defect is security-impacting. "
                "quality_finding = the defect is a correctness issue "
                "without security implications."
            ),
        },
        "is_security": {
            "type": "boolean",
            "description": (
                "true if this defect has security implications — it "
                "crosses a trust boundary, is reachable by an "
                "unprivileged user, or affects confidentiality, "
                "integrity, or availability."
            ),
        },
    },
    "required": ["rationale", "classification", "is_security"],
}


def _load_security_context(out_dir: Path) -> str:
    """Load security context from the domain model for classification."""
    try:
        from core.concepts.audit_bridge import domain_security_context
        ctx = domain_security_context(out_dir)
        return ctx or ""
    except Exception:
        logger.debug("security context load failed", exc_info=True)
        return ""


_CLASSIFICATION_SYSTEM = (
    "You are a security impact classifier.  Given a "
    "verified code defect, decide whether it has security "
    "implications or is purely a quality issue.\n\n"
    "The defect's hypothesis, description, and any domain-model "
    "security context arrive as untrusted blocks; the file, "
    "function, bug class, and CWE are in the slots.\n\n"
    "Is this defect security-impacting?  Consider:\n"
    "- Can an unprivileged user reach this code path?\n"
    "- Does the defect cross a trust boundary?\n"
    "- Does the defect affect confidentiality, integrity, "
    "or availability?\n"
    "- Could an attacker exploit this to gain unauthorized "
    "access, escalate privileges, or cause denial of service?\n\n"
    "A defect that only affects correctness (wrong output, "
    "resource leak with no security consequence, cosmetic error) "
    "is a quality_finding.  A defect that an attacker can use "
    "to violate a security property is a security_finding."
)


def _build_classification_prompt(
    outcome: Any,
    security_context: str,
    *,
    model_id: str = "",
) -> tuple[str, str]:
    """Build the enveloped prompt for security impact classification.
    Returns ``(user, system)``."""
    from core.security.prompt_envelope import TaintedString, UntrustedBlock

    from ._util import envelope_prompt

    review = outcome.review_result or {}
    bug_class = review.get("bug_class", "unknown")
    cwe = review.get("cwe", "")
    key = f"{outcome.file}:{outcome.function}"

    blocks = [
        UntrustedBlock(
            content=outcome.hypothesis or "",
            kind="defect-hypothesis",
            origin=key,
        ),
        UntrustedBlock(
            content=outcome.body or "",
            kind="defect-description",
            origin=key,
        ),
    ]
    if security_context:
        blocks.append(UntrustedBlock(
            content=security_context,
            kind="domain-security-context",
            origin="domain-model",
        ))

    slots = {
        "file": TaintedString(value=outcome.file or "", trust="untrusted"),
        "function": TaintedString(value=outcome.function or "", trust="untrusted"),
        "bug_class": TaintedString(value=str(bug_class), trust="untrusted"),
    }
    if cwe:
        slots["cwe"] = TaintedString(value=str(cwe), trust="untrusted")

    return envelope_prompt(
        _CLASSIFICATION_SYSTEM, blocks, slots, model_id=model_id,
    )


def classify_security_impact(
    outcomes: list[Any],
    out_dir: Path,
    llm_client: Any,
    *,
    model_name: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Classify findings/suspicious outcomes for security impact.

    Returns a dict mapping ``file:function`` to the classification result.
    Only processes outcomes with status in (finding, suspicious).
    """
    candidates = [
        o for o in outcomes
        if o.status in ("finding", "suspicious")
    ]
    if not candidates:
        return {}

    security_context = _load_security_context(out_dir)

    results: dict[str, dict[str, Any]] = {}
    kwargs: dict[str, Any] = {"task_type": "audit"}
    if model_name:
        try:
            mc = llm_client.config.config_for_model(model_name)
            kwargs = {"model_config": mc}
        except (ValueError, AttributeError):
            pass

    total_cost = 0.0
    for outcome in candidates:
        key = f"{outcome.file}:{outcome.function}"
        prompt, system_prompt = _build_classification_prompt(
            outcome, security_context,
            model_id=model_name or getattr(llm_client, "model_name", "") or "",
        )

        try:
            response = llm_client.generate_structured(
                prompt,
                CLASSIFICATION_SCHEMA,
                system_prompt=system_prompt,
                **kwargs,
            )
            result = structured_result(response)
            cost = response.cost if hasattr(response, "cost") else 0.0
            total_cost += cost
        except Exception:
            logger.warning(
                "security classification failed for %s — defaulting to quality",
                key, exc_info=True,
            )
            result = {
                "is_security": False,
                "classification": "quality_finding",
                "rationale": "classification failed — defaulted to quality",
            }

        results[key] = result

        if outcome.review_result is not None:
            outcome.review_result["security_impact"] = result

        logger.info(
            "Phase 2: %s → %s (%s)",
            key,
            result.get("classification", "?"),
            result.get("primitive", "none"),
        )

    logger.info(
        "Phase 2 complete: %d classified (%.2f USD), %d security, %d quality",
        len(results),
        total_cost,
        sum(1 for r in results.values() if r.get("is_security")),
        sum(1 for r in results.values() if not r.get("is_security")),
    )
    return results
