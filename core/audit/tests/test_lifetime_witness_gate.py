"""Gate tests: C lifetime-witness discharge in rescue_self_refuted.

The anti-self-refutation gate floors lifetime (CWE-415/416)
self-refutations to suspicious.  On C sources, a dismissal whose
mechanism the lifetime witness proves impossible is instead ACCEPTED
(with a suppressions.jsonl record, ``dropped: false``).  These tests
pin the discharge, its record, and — most importantly — every shape
that must keep flooring: real use-after-free / shared-path double-free
fixtures, retaining-co-argument escapes (the rxkad shape), untrusted
repos, structural-receipt functions, non-C sources, missing record
sinks, and the detector-receipt lane's precedence.

Module-level imports here deliberately avoid
``core.audit.lifetime_witness`` so the floor-stands regressions in
this file also run against trees that predate the witness.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_c")

from core.audit.refutation import rescue_self_refuted

REL = "fs/thaw.c"

_THAW_C = """
static int drop_last(struct sb *sb, int who)
{
\tint error = -EINVAL;

\tif (sb->frozen != 2)
\t\tgoto out_unlock;
\tif (freeze_dec(sb, who))
\t\tgoto out_unlock;
\tsb->frozen = 0;
\twake_all(&sb->waiters);
\tdeactivate_locked_super(sb);
\treturn 0;

out_unlock:
\tsuper_unlock(sb);
\treturn error;
}
"""

_UAF_REAL_C = """
static int drop_last(struct sb *sb, int who)
{
\tkfree(sb);
\treturn sb->frozen;
}
"""

# The rxkad shape in miniature: the pointer escapes into a call that
# also takes a co-argument, and the co-argument is used after the
# release — the witness must refuse by construction.
_COARG_C = """
static int verify(struct skb *skb, int n)
{
\tstruct sg *sg;
\tsg = kmalloc(n, GFP_NOIO);
\tif (!sg)
\t\treturn -ENOMEM;
\tskb_to_sgvec(skb, sg, n);
\tkfree(sg);
\treturn skb_copy_bits(skb, 0);
}
"""

_UAF_CLAIM = (
    "Use-after-free: deactivate_locked_super(sb) may free sb (drops "
    "the last reference); sb is dereferenced after "
    "deactivate_locked_super"
)

_COUNTER = (
    "deactivate_locked_super is immediately followed by return 0; no "
    "use of sb on any path after it"
)


@dataclass
class _Outcome:
    file: str = REL
    function: str = "drop_last"
    status: str = "clean"
    line: int = 2
    hypothesis: str = ""
    hypotheses: Optional[list] = None
    evidence_tool: str = ""
    review_result: Optional[Dict[str, Any]] = None


@dataclass
class _Receipt:
    check_type: str = "shared_writer_race"
    function: str = "drop_last"
    file: str = REL


@dataclass
class _Config:
    """Minimal OrchestratorConfig stand-in (base-compatible plumbing:
    the gate reads target_path/out_dir/repo_trusted off *config* when
    the explicit kwargs are not passed)."""

    target_path: Optional[Path] = None
    out_dir: Optional[Path] = None
    repo_trusted: bool = True


def _tree(tmp_path: Path, source: str, rel: str = REL) -> Path:
    f = tmp_path / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(source)
    return tmp_path


def _hyp(mechanism: str, counter: str = _COUNTER,
         confidence: str = "refuted") -> dict:
    return {
        "mechanism": mechanism,
        "confidence": confidence,
        "counter": counter,
    }


def _records(out_dir: Path) -> list[dict]:
    supp = out_dir / "suppressions.jsonl"
    if not supp.exists():
        return []
    return [
        json.loads(line)
        for line in supp.read_text().splitlines() if line.strip()
    ]


class TestLifetimeDischarge:
    def test_provable_dismissal_discharges(self, tmp_path):
        root = _tree(tmp_path, _THAW_C)
        out = tmp_path / "out"
        out.mkdir()
        rv = rescue_self_refuted(
            _Outcome(hypotheses=[_hyp(_UAF_CLAIM)]),
            source=_THAW_C, target_path=root, out_dir=out,
            repo_trusted=True,
        )
        assert rv is None

    def test_discharge_writes_accept_record(self, tmp_path):
        root = _tree(tmp_path, _THAW_C)
        out = tmp_path / "out"
        out.mkdir()
        rescue_self_refuted(
            _Outcome(hypotheses=[_hyp(_UAF_CLAIM)]),
            source=_THAW_C, target_path=root, out_dir=out,
            repo_trusted=True,
        )
        rows = _records(out)
        assert len(rows) == 1
        row = rows[0]
        assert row["verdict"] == "lifetime_witness_corroborates_dismissal"
        assert row["dropped"] is False
        assert row["witness"] == "lifetime"
        assert row["floor_gate"] == "cwe_allowlist"
        assert row["arms"] == ["nouse"]
        assert row["pointers"] == ["sb"]
        assert row["function"] == "drop_last"
        assert "CWE-416" in row["covered_cwes"]

    def test_pure_double_free_claim_discharges_via_freepath(
        self, tmp_path,
    ):
        src = """
static void h(char *p, int a)
{
\tif (a)
\t\tgoto bad;
\tkfree(p);
\treturn;
bad:
\tkfree(p);
}
"""
        root = _tree(tmp_path, src)
        out = tmp_path / "out"
        out.mkdir()
        rv = rescue_self_refuted(
            _Outcome(function="h", hypotheses=[_hyp(
                "Double-free of p: typestate claims p freed at line 5 "
                "then again at line 8",
                "the two kfree sites are on mutually exclusive paths",
            )]),
            source=src, target_path=root, out_dir=out,
            repo_trusted=True,
        )
        assert rv is None
        rows = _records(out)
        assert rows and rows[0]["arms"] == ["freepath"]


class TestFloorStands:
    def test_real_uaf_floors(self, tmp_path):
        root = _tree(tmp_path, _UAF_REAL_C)
        out = tmp_path / "out"
        out.mkdir()
        rv = rescue_self_refuted(
            _Outcome(hypotheses=[_hyp(
                "Use-after-free: sb freed by kfree at line 3 and then "
                "used at line 4",
                "the read happens before the compiler reorders",
            )]),
            source=_UAF_REAL_C, target_path=root, out_dir=out,
            repo_trusted=True,
        )
        assert rv is not None
        assert rv.gate == "anti_self_refutation"
        assert rv.demote_to == "suspicious"
        assert not _records(out)

    def test_retaining_co_argument_floors(self, tmp_path):
        root = _tree(tmp_path, _COARG_C)
        out = tmp_path / "out"
        out.mkdir()
        rv = rescue_self_refuted(
            _Outcome(function="verify", hypotheses=[_hyp(
                "Use-after-free: sg freed at line 8 and then used "
                "later in the function",
                "sg is not touched after the kfree",
            )]),
            source=_COARG_C, target_path=root, out_dir=out,
            repo_trusted=True,
        )
        assert rv is not None and rv.demote_to == "suspicious"
        assert not _records(out)

    def test_untrusted_repo_floors_without_probe(self, tmp_path):
        root = _tree(tmp_path, _THAW_C)
        out = tmp_path / "out"
        out.mkdir()
        rv = rescue_self_refuted(
            _Outcome(hypotheses=[_hyp(_UAF_CLAIM)]),
            source=_THAW_C, target_path=root, out_dir=out,
            repo_trusted=False,
        )
        assert rv is not None and rv.demote_to == "suspicious"
        assert not _records(out)

    def test_explicit_untrusted_overrides_config_trust(self, tmp_path):
        root = _tree(tmp_path, _THAW_C)
        out = tmp_path / "out"
        out.mkdir()
        rv = rescue_self_refuted(
            _Outcome(hypotheses=[_hyp(_UAF_CLAIM)]),
            config=_Config(
                target_path=root, out_dir=out, repo_trusted=True,
            ),
            source=_THAW_C,
            repo_trusted=False,
        )
        assert rv is not None and rv.demote_to == "suspicious"

    def test_structural_receipt_blocks_discharge(self, tmp_path):
        root = _tree(tmp_path, _THAW_C)
        out = tmp_path / "out"
        out.mkdir()
        rv = rescue_self_refuted(
            _Outcome(hypotheses=[_hyp(_UAF_CLAIM)]),
            negative_space=[_Receipt()],
            source=_THAW_C, target_path=root, out_dir=out,
            repo_trusted=True,
        )
        assert rv is not None and rv.demote_to == "suspicious"
        assert not _records(out)

    def test_non_c_source_never_consults_witness(self, tmp_path):
        root = _tree(tmp_path, _THAW_C, rel="pkg/thaw.go")
        out = tmp_path / "out"
        out.mkdir()
        rv = rescue_self_refuted(
            _Outcome(file="pkg/thaw.go", hypotheses=[_hyp(_UAF_CLAIM)]),
            source=_THAW_C, target_path=root, out_dir=out,
            repo_trusted=True,
        )
        assert rv is not None and rv.demote_to == "suspicious"
        assert not _records(out)

    def test_unrecordable_discharge_refused(self, tmp_path):
        root = _tree(tmp_path, _THAW_C)
        rv = rescue_self_refuted(
            _Outcome(hypotheses=[_hyp(_UAF_CLAIM)]),
            source=_THAW_C, target_path=root, out_dir=None,
            repo_trusted=True,
        )
        assert rv is not None and rv.demote_to == "suspicious"

    def test_mixed_race_lifetime_claim_floors(self, tmp_path):
        root = _tree(tmp_path, _THAW_C)
        out = tmp_path / "out"
        out.mkdir()
        rv = rescue_self_refuted(
            _Outcome(hypotheses=[_hyp(
                "CWE-362 CWE-416: sb could be freed by a concurrent "
                "thaw while this function dereferences it after "
                "deactivate_locked_super",
                "the umount lock serialises the two paths",
            )]),
            source=_THAW_C, target_path=root, out_dir=out,
            repo_trusted=True,
        )
        assert rv is not None and rv.demote_to == "suspicious"
        assert not _records(out)

    def test_missing_target_path_floors(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        rv = rescue_self_refuted(
            _Outcome(hypotheses=[_hyp(_UAF_CLAIM)]),
            source=_THAW_C, target_path=None, out_dir=out,
            repo_trusted=True,
        )
        assert rv is not None and rv.demote_to == "suspicious"

    def test_detector_receipt_lane_outranks_witness(self, tmp_path):
        """A dismissed hypothesis matching an active detector receipt
        floors via the detector lane BEFORE the CWE loop runs — a
        dischargeable lifetime dismissal on the same outcome must not
        pre-empt it."""
        root = _tree(tmp_path, _THAW_C)
        out = tmp_path / "out"
        out.mkdir()
        rv = rescue_self_refuted(
            _Outcome(hypotheses=[
                {
                    "mechanism": (
                        "Out-of-bounds: the scatterlist table is "
                        "undersized for a fragmented skb"
                    ),
                    "confidence": "low",
                    "counter": "",
                },
                _hyp(_UAF_CLAIM),
            ]),
            detector_findings=[{
                "detector": "cocci:scatterlist_frag_undersize",
                "description": "sg table sized from bare frag count",
            }],
            source=_THAW_C, target_path=root, out_dir=out,
            repo_trusted=True,
        )
        assert rv is not None
        assert "scatterlist_frag_undersize" in rv.reason


class TestGateLaunderingFloors:
    def test_real_double_free_dismissal_floors_end_to_end(self, tmp_path):
        """A genuine double free whose second site hides behind a
        ternary copy must floor even with repo trust asserted and a
        record sink present — the witness refuses laundered release
        arguments, so the gate has nothing to accept."""
        src = (
            "static int drop_filter(struct sock *sk, int flag)\n"
            "{\n"
            "\tstruct filt *p;\n"
            "\tstruct filt *q;\n"
            "\n"
            "\tp = kmalloc(64, GFP_KERNEL);\n"
            "\tif (!p)\n"
            "\t\treturn -ENOMEM;\n"
            "\tq = flag ? p : p;\n"
            "\tif (flag) {\n"
            "\t\tkfree(p);\n"
            "\t\treturn 0;\n"
            "\t}\n"
            "\tkfree(q);\n"
            "\tkfree(p);\n"
            "\treturn 1;\n"
            "}\n"
        )
        root = _tree(tmp_path, src)
        out = tmp_path / "out"
        out.mkdir()
        rv = rescue_self_refuted(
            _Outcome(function="drop_filter", hypotheses=[_hyp(
                "CWE-415 double-free of p: p freed at line 11 then "
                "again at line 15",
                "the two sites are on exclusive branches",
            )]),
            source=src, target_path=root, out_dir=out,
            repo_trusted=True,
        )
        assert rv is not None
        assert rv.demote_to == "suspicious"
        assert not _records(out)
