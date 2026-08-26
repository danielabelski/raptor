"""Refutation verdicts carry the evidence class of the refuting fact.

``refuter_grade`` distinguishes proof-grade refuting facts
(mechanically true regardless of interpretation — the return-range
table) from heuristic ones (keyword/lookup matching, partial call
graphs, unverified model claims). Consumers that weigh a refuter
against other evidence read the grade instead of trusting every gate
equally.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from core.audit.refutation import (
    RefutationVerdict,
    _refute_by_architecture,
    _refute_by_contract,
    _refute_by_callee_inheritance,
    _refute_by_known_return_type,
    _refute_by_lifecycle,
)


@dataclass
class _Outcome:
    file: str = "src/net.c"
    function: str = "handle_packet"
    status: str = "clean"
    body: str = ""
    hypothesis: str = ""
    hypotheses: Optional[list] = None
    evidence_tool: str = ""
    review_result: Optional[Dict[str, Any]] = None
    line: int = 42


@dataclass
class _Config:
    target_path: Path = field(default_factory=lambda: Path("/nonexistent"))
    out_dir: Optional[Path] = None


# ---------------------------------------------------------------------------
# Per-gate refuter grades
# ---------------------------------------------------------------------------


class TestRefuterGrades:
    """Each gate's verdict declares the evidence class of its refuting
    fact; only the return-range table is interpretation-free."""

    def test_default_grade_is_heuristic(self):
        v = RefutationVerdict(gate="g", reason="r", demote_to="clean")
        assert v.refuter_grade == "heuristic"

    def test_known_return_type_is_proof(self):
        o = _Outcome(
            status="finding",
            hypothesis=(
                "integer overflow: the ntohs() length wraps the "
                "accumulator"
            ),
            review_result={"cwe": "CWE-190"},
        )
        v = _refute_by_known_return_type(o, None)
        assert v is not None
        assert v.demote_to == "clean"
        assert v.refuter_grade == "proof"

    def test_architecture_is_heuristic(self):
        o = _Outcome(
            status="finding",
            hypothesis="race between reader and writer",
            review_result={"cwe": "CWE-362"},
        )
        dm = {"architecture": {"threading_model": "single_threaded"}}
        v = _refute_by_architecture(o, dm, None, _Config())
        assert v is not None
        assert v.refuter_grade == "heuristic"

    def test_lifecycle_is_heuristic(self):
        checklist = {
            "files": [{
                "path": "src/main.c",
                "items": [],
                "call_graph": {"calls": [
                    {"caller": "main", "chain": ["setup_config"],
                     "line": 5},
                    {"caller": "main", "chain": ["epoll_wait"],
                     "line": 20},
                ]},
            }],
        }
        o = _Outcome(
            status="finding",
            function="setup_config",
            hypothesis="the config fd is leaked, never closed",
            review_result={"cwe": "CWE-772"},
        )
        v = _refute_by_lifecycle(o, checklist)
        assert v is not None
        assert v.refuter_grade == "heuristic"

    def test_contract_is_heuristic(self):
        o = _Outcome(
            status="finding",
            hypothesis="attacker-controlled input reaches the parser",
        )
        dm = {"contracts": [{
            "function": "handle_packet",
            "input_semantics": "locally generated cache copy",
        }]}
        v = _refute_by_contract(o, dm)
        assert v is not None
        assert v.demote_to == "suspicious"
        assert v.refuter_grade == "heuristic"

    def test_callee_inheritance_is_heuristic(self):
        o = _Outcome(
            status="finding",
            hypothesis=(
                "the function parse_inner has a buffer overflow in "
                "its length handling"
            ),
        )
        source = (
            "int handle_packet(struct pkt *p)\n"
            "{\n"
            "\treturn parse_inner(p);\n"
            "}\n"
        )
        v = _refute_by_callee_inheritance(o, source, ["parse_inner"])
        assert v is not None
        assert v.refuter_grade == "heuristic"
