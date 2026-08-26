"""Gate tests: Go internal-concurrency discharge in rescue_self_refuted.

The anti-self-refutation gate floors race-family self-refutations to
suspicious.  On Go sources, a dismissal whose operative claim is
package-internal concurrency is instead ACCEPTED (with a
suppressions.jsonl record, ``dropped: false``) when the witness proves
no package-internal goroutine reaches the claimed state.  These tests
pin the discharge, its record, and — most importantly — every shape
that must keep flooring: internal spawns that DO reach the receiver,
external-caller claims, structural-receipt functions, parse failures,
and non-Go sources.

Module-level imports here deliberately avoid ``core.audit.goconc`` so
the floor-stands regressions in this file also run against trees that
predate the witness.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

from core.audit.refutation import rescue_self_refuted


@dataclass
class _Outcome:
    file: str = "pkg/store/record.go"
    function: str = "Scan"
    status: str = "clean"
    line: int = 7
    body: str = ""
    hypothesis: str = ""
    hypotheses: Optional[list] = None
    evidence_tool: str = ""
    review_result: Optional[Dict[str, Any]] = None


@dataclass
class _Receipt:
    check_type: str = "shared_writer_race"
    function: str = "Scan"
    file: str = "pkg/store/record.go"


@dataclass
class _Config:
    """Minimal OrchestratorConfig stand-in (base-compatible plumbing:
    the gate reads target_path/out_dir/repo_trusted off *config* when
    the explicit kwargs are not passed)."""

    target_path: Optional[Path] = None
    out_dir: Optional[Path] = None
    repo_trusted: bool = True


# ---------------------------------------------------------------------------
# Synthetic Go fixtures written to disk
# ---------------------------------------------------------------------------

_RECORD_GO = """package store

type Record struct {
\tVal   string
\tValid bool
}

func (r *Record) Scan(v string) error {
\tr.Valid = true
\tr.Val = v
\treturn nil
}
"""

_POOL_GO = """package store

type Pool struct {
\tch chan int
}

func (p *Pool) opener() {
\tfor range p.ch {
\t}
}

func NewPool() *Pool {
\tp := &Pool{ch: make(chan int)}
\tgo p.opener()
\treturn p
}
"""

# Variant where the spawned goroutine is born inside a Record method.
_RECORD_SPAWNER_GO = """package store

type Record struct {
\tVal   string
\tValid bool
\tdone  chan struct{}
}

func (r *Record) awaitDone() {
\t<-r.done
}

func (r *Record) Scan(v string) error {
\tgo r.awaitDone()
\tr.Valid = true
\tr.Val = v
\treturn nil
}
"""

_RECORD_SCAN_SRC = (
    "func (r *Record) Scan(v string) error {\n"
    "\tr.Valid = true\n"
    "\tr.Val = v\n"
    "\treturn nil\n"
    "}\n"
)

_RECORD_SPAWNER_SCAN_SRC = (
    "func (r *Record) Scan(v string) error {\n"
    "\tgo r.awaitDone()\n"
    "\tr.Valid = true\n"
    "\tr.Val = v\n"
    "\treturn nil\n"
    "}\n"
)

_INTERNAL_MECH = (
    "Data race (CWE-362): a package-internal goroutine could write "
    "r.Val/r.Valid concurrently with Scan, torn reads possible"
)
_CALLER_MECH = (
    "Unsynchronized field writes (CWE-362): two goroutines calling "
    "Scan on the same *Record could produce a torn write"
)
_NEUTRAL_MECH = (
    "Unsynchronized field writes (CWE-362): concurrent Scan "
    "invocations on the same receiver could produce a torn write"
)
_INTERNAL_COUNTER = (
    "No internal goroutine in the package accesses scan receivers; "
    "sharing a receiver across goroutines violates the API contract"
)
_EXTERNAL_MECH = (
    "Two unsynchronized writes (CWE-362) allow concurrent callers to "
    "interleave fragments on the shared writer"
)


def _write_pkg(tmp_path: Path, files: Dict[str, str]) -> Path:
    pkg = tmp_path / "target" / "pkg" / "store"
    pkg.mkdir(parents=True)
    for name, text in files.items():
        (pkg / name).write_text(text)
    return tmp_path / "target"


def _hyp(mechanism: str, counter: str = _INTERNAL_COUNTER) -> dict:
    return {"confidence": "refuted", "mechanism": mechanism,
            "counter": counter}


def _records(out_dir: Path) -> list:
    p = out_dir / "suppressions.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line]


def _has_ts_go() -> bool:
    # Deliberately keyed on the GRAMMAR, not on the witness module: a
    # tree without the witness must run these tests and fail them red,
    # while an environment without the optional Go grammar skips them
    # (the witness refuses without it — conservative, but the
    # discharge assertions cannot hold).
    try:
        import tree_sitter
        import tree_sitter_go

        tree_sitter.Parser(tree_sitter.Language(tree_sitter_go.language()))
        return True
    except Exception:
        return False


needs_witness = pytest.mark.skipif(
    not _has_ts_go(),
    reason="goconc witness needs the tree-sitter Go grammar",
)


# ---------------------------------------------------------------------------
# Discharge (red on trees without the witness)
# ---------------------------------------------------------------------------


@needs_witness
class TestDischarge:
    def test_isolated_package_discharges_internal_race_dismissal(
        self, tmp_path,
    ):
        target = _write_pkg(
            tmp_path, {"record.go": _RECORD_GO, "pool.go": _POOL_GO},
        )
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(_INTERNAL_MECH)])
        rv = rescue_self_refuted(
            o, source=_RECORD_SCAN_SRC, target_path=target, out_dir=out,
            repo_trusted=True,
        )
        assert rv is None

    def test_discharge_writes_accept_record(self, tmp_path):
        target = _write_pkg(
            tmp_path, {"record.go": _RECORD_GO, "pool.go": _POOL_GO},
        )
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(_INTERNAL_MECH)])
        rescue_self_refuted(
            o, source=_RECORD_SCAN_SRC,
            config=_Config(target_path=target, out_dir=out),
        )
        recs = _records(out)
        assert len(recs) == 1
        rec = recs[0]
        assert rec["verdict"] == "goconc_witness_corroborates_dismissal"
        assert rec["dropped"] is False
        assert rec["rule_id"] == "audit:goconc-witness"
        assert rec["file_path"] == "pkg/store/record.go"
        assert rec["function"] == "Scan"
        assert rec["witness"] == "goconc"
        assert rec["floor_gate"] == "cwe_allowlist"
        assert rec["claimed_types"] == ["Record"]
        assert rec["spawn_count"] == 1

    def test_actor_neutral_mechanism_with_internal_counter_discharges(
        self, tmp_path,
    ):
        # The reviewer's counter carries the operative internal-
        # concurrency refutation; the mechanism names no actor at all.
        # The witness corroborates the counter.  (A mechanism that
        # EXPLICITLY attributes the race to callers/clients/other
        # packages stays out of family whatever the counter says —
        # see TestClaimFence.)
        target = _write_pkg(
            tmp_path, {"record.go": _RECORD_GO, "pool.go": _POOL_GO},
        )
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(_NEUTRAL_MECH, _INTERNAL_COUNTER)])
        rv = rescue_self_refuted(
            o, source=_RECORD_SCAN_SRC,
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is None
        assert len(_records(out)) == 1

    def test_zero_spawn_package_discharges_opts_shaped_claim(
        self, tmp_path,
    ):
        opts_go = (
            "package opts\n\n"
            "type Manifest struct {\n\tGids []uint32\n}\n\n"
            "func ensureGids(m *Manifest, gid uint32) {\n"
            "\tm.Gids = append([]uint32{gid}, m.Gids...)\n"
            "}\n"
        )
        pkg = tmp_path / "target" / "pkg" / "opts"
        pkg.mkdir(parents=True)
        (pkg / "opts.go").write_text(opts_go)
        out = tmp_path / "out"
        o = _Outcome(
            file="pkg/opts/opts.go", function="ensureGids",
            hypotheses=[_hyp(
                "Race condition: multiple BuildOpts (WithUser, "
                "WithGids) mutating *Manifest concurrently could "
                "corrupt Gids (CWE-362)",
                "Opts are applied by a sequential in-package loop",
            )],
        )
        rv = rescue_self_refuted(
            o,
            source=(
                "func ensureGids(m *Manifest, gid uint32) {\n"
                "\tm.Gids = append([]uint32{gid}, m.Gids...)\n"
                "}\n"
            ),
            config=_Config(target_path=tmp_path / "target", out_dir=out),
        )
        assert rv is None
        recs = _records(out)
        assert len(recs) == 1
        assert recs[0]["spawn_count"] == 0


# ---------------------------------------------------------------------------
# Floor stands (must pass on every tree, before and after the witness)
# ---------------------------------------------------------------------------


class TestFloorStands:
    def test_internal_spawn_reaching_receiver_floors(self, tmp_path):
        # go r.awaitDone() inside a Record method: internal
        # concurrency genuinely reaches the receiver — the floor must
        # hold and no witness record may exist.
        target = _write_pkg(
            tmp_path, {"record.go": _RECORD_SPAWNER_GO},
        )
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(_INTERNAL_MECH)])
        rv = rescue_self_refuted(
            o, source=_RECORD_SPAWNER_SCAN_SRC,
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is not None
        assert rv.gate == "anti_self_refutation"
        assert rv.demote_to == "suspicious"
        assert _records(out) == []

    def test_external_caller_claim_floors_even_when_isolated(
        self, tmp_path,
    ):
        # Shared-writer shape: zero spawns in the package, but the
        # dismissal attributes the race to concurrent CALLERS — out
        # of the witness's claim family.  No discharge, no record.
        writer_go = (
            "package fmtout\n\n"
            "type Writer struct {\n\tn int\n}\n\n"
            "func (w *Writer) WriteTwice(b []byte) {\n"
            "\tw.n += len(b)\n\tw.n += len(b)\n}\n"
        )
        pkg = tmp_path / "target" / "pkg" / "fmtout"
        pkg.mkdir(parents=True)
        (pkg / "writer.go").write_text(writer_go)
        out = tmp_path / "out"
        o = _Outcome(
            file="pkg/fmtout/writer.go", function="WriteTwice",
            hypotheses=[_hyp(
                _EXTERNAL_MECH,
                "The package spawns no goroutines; callers must "
                "serialise access themselves",
            )],
        )
        rv = rescue_self_refuted(
            o,
            source=(
                "func (w *Writer) WriteTwice(b []byte) {\n"
                "\tw.n += len(b)\n\tw.n += len(b)\n}\n"
            ),
            config=_Config(target_path=tmp_path / "target", out_dir=out),
        )
        assert rv is not None
        assert rv.demote_to == "suspicious"
        assert _records(out) == []

    def test_structural_receipt_blocks_discharge(self, tmp_path):
        # Same in-family dismissal and isolated package as the
        # discharge case — but the function carries a structural
        # negative-space receipt.  The structural lane outranks the
        # witness: floor stands, no witness record.
        target = _write_pkg(
            tmp_path, {"record.go": _RECORD_GO, "pool.go": _POOL_GO},
        )
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(_INTERNAL_MECH)])
        rv = rescue_self_refuted(
            o, source=_RECORD_SCAN_SRC,
            config=_Config(target_path=target, out_dir=out),
            negative_space=[_Receipt()],
        )
        assert rv is not None
        assert _records(out) == []

    def test_package_parse_failure_floors(self, tmp_path):
        target = _write_pkg(
            tmp_path,
            {"record.go": _RECORD_GO, "broken.go": "package store\n\nfunc ( {\n"},
        )
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(_INTERNAL_MECH)])
        rv = rescue_self_refuted(
            o, source=_RECORD_SCAN_SRC,
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is not None
        assert _records(out) == []

    def test_c_source_never_consults_witness(self, tmp_path):
        out = tmp_path / "out"
        o = _Outcome(
            file="drivers/net/foo.c", function="foo_xmit",
            hypotheses=[_hyp(
                "Race (CWE-362): a package-internal goroutine — sic — "
                "races foo_xmit against the interrupt handler",
            )],
        )
        rv = rescue_self_refuted(
            o,
            source="static int foo_xmit(struct sk_buff *skb)\n{\n\treturn 0;\n}\n",
            config=_Config(target_path=tmp_path, out_dir=out),
        )
        assert rv is not None
        assert _records(out) == []

    def test_missing_target_path_floors(self, tmp_path):
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(_INTERNAL_MECH)])
        rv = rescue_self_refuted(
            o, source=_RECORD_SCAN_SRC,
            config=_Config(target_path=None, out_dir=out),
        )
        assert rv is not None
        assert _records(out) == []

    def test_mixed_race_and_lifetime_claim_floors(self, tmp_path):
        target = _write_pkg(
            tmp_path, {"record.go": _RECORD_GO, "pool.go": _POOL_GO},
        )
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(
            "Race and lifetime (CWE-362, CWE-416): a package-internal "
            "goroutine frees the record while Scan writes it",
        )])
        rv = rescue_self_refuted(
            o, source=_RECORD_SCAN_SRC,
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is not None
        assert _records(out) == []

    def test_untrusted_repo_floors_without_probe(self, tmp_path):
        # The discharge arm is gated on the operator's repo-trust
        # assertion: without it the floor stands and the witness is
        # never consulted (its soundness bound assumes non-adversarial
        # target code).
        target = _write_pkg(
            tmp_path, {"record.go": _RECORD_GO, "pool.go": _POOL_GO},
        )
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(_INTERNAL_MECH)])
        rv = rescue_self_refuted(
            o, source=_RECORD_SCAN_SRC,
            config=_Config(
                target_path=target, out_dir=out, repo_trusted=False,
            ),
        )
        assert rv is not None
        assert rv.demote_to == "suspicious"
        assert _records(out) == []

    def test_unrecordable_discharge_refused(self, tmp_path):
        # No out_dir → the accept-with-record row cannot be written →
        # the discharge must not happen (never-silent contract).
        target = _write_pkg(
            tmp_path, {"record.go": _RECORD_GO, "pool.go": _POOL_GO},
        )
        o = _Outcome(hypotheses=[_hyp(_INTERNAL_MECH)])
        rv = rescue_self_refuted(
            o, source=_RECORD_SCAN_SRC,
            config=_Config(target_path=target, out_dir=None),
        )
        assert rv is not None
        assert rv.demote_to == "suspicious"

    def test_out_of_family_phrasing_floors_without_probe(self, tmp_path):
        # Non-concurrency mechanism inferred as race by CWE tag only:
        # the fence requires concurrency phrasing, so no discharge.
        target = _write_pkg(
            tmp_path, {"record.go": _RECORD_GO, "pool.go": _POOL_GO},
        )
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(
            "CWE-362: check-then-act on r.Valid between two statements",
            "single-threaded usage",
        )])
        rv = rescue_self_refuted(
            o, source=_RECORD_SCAN_SRC,
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is not None
        assert _records(out) == []


# ---------------------------------------------------------------------------
# Trust-gate precedence (new-kwarg mechanics; red on trees without it)
# ---------------------------------------------------------------------------


class TestTrustGate:
    def test_explicit_untrusted_overrides_config_trust(self, tmp_path):
        target = _write_pkg(
            tmp_path, {"record.go": _RECORD_GO, "pool.go": _POOL_GO},
        )
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(_INTERNAL_MECH)])
        rv = rescue_self_refuted(
            o, source=_RECORD_SCAN_SRC,
            config=_Config(target_path=target, out_dir=out),
            repo_trusted=False,
        )
        assert rv is not None
        assert _records(out) == []


# ---------------------------------------------------------------------------
# Claim-phrasing fence
# ---------------------------------------------------------------------------


class TestClaimFence:
    def _fence(self):
        from core.audit.refutation import _goconc_claim_in_family
        return _goconc_claim_in_family

    def test_package_internal_mechanism_in_family(self):
        fence = self._fence()
        assert fence(
            "Data race on r.Val with a package-internal goroutine", "",
        )

    def test_internal_counter_admits_neutral_mechanism(self):
        fence = self._fence()
        assert fence(_NEUTRAL_MECH, _INTERNAL_COUNTER)

    def test_goroutines_calling_api_out_even_with_internal_counter(self):
        # "Two goroutines calling Scan" attributes the concurrency to
        # callers of the API — out of family whatever the counter says.
        fence = self._fence()
        assert not fence(_CALLER_MECH, _INTERNAL_COUNTER)

    def test_external_actor_phrasings_out_of_family(self):
        fence = self._fence()
        for mech in (
            "Race: multiple goroutines in other packages mutate the "
            "shared registry concurrently (CWE-362)",
            "Data race when multiple goroutines call Reset on the "
            "shared parser (CWE-362)",
            "Race window: client code invoking Write concurrently "
            "corrupts the stream (CWE-362)",
            "The application using this type from several goroutines "
            "races on the counter (CWE-362)",
            "Unsynchronized writes: a caller races the flush path on "
            "the shared buffer (CWE-362)",
            "Race with goroutines outside this package writing the "
            "shared map concurrently (CWE-362)",
        ):
            assert not fence(mech, _INTERNAL_COUNTER), mech

    def test_concurrent_callers_out_of_family(self):
        fence = self._fence()
        assert not fence(_EXTERNAL_MECH, "")

    def test_caller_mechanism_beats_internal_counter(self):
        fence = self._fence()
        assert not fence(
            "Concurrent callers can interleave the two writes",
            "The package spawns no goroutines",
        )

    def test_opts_application_phrasings_in_family(self):
        fence = self._fence()
        assert fence(
            "Race condition: multiple BuildOpts (WithUser, WithGids) "
            "mutating *Manifest concurrently", "",
        )
        assert fence(
            "Lazy initialization of m.Linux without synchronization: "
            "two concurrent BuildOpts applications could both observe "
            "nil", "",
        )
        assert fence(
            "Race condition: concurrent BuildOpts application could "
            "both observe m.Linux == nil", "",
        )

    def test_non_concurrency_claim_out_of_family(self):
        fence = self._fence()
        assert not fence(
            "Integer overflow in length computation", "",
        )

    def test_caller_neutral_mechanism_without_counter_stays_out(self):
        # "Two goroutines calling Scan" names no package-internal
        # actor; without a counter naming one, the witness must not
        # even be consulted.
        fence = self._fence()
        assert not fence(_CALLER_MECH, "")

    def test_external_framework_spawns_out_of_family(self):
        # The concurrency actor is another package's machinery: the
        # witness's package-local scan cannot speak to it.
        fence = self._fence()
        assert not fence(
            "Each request runs on a goroutine spawned by the HTTP "
            "server; concurrent requests race on h.counter", "",
        )
        assert not fence(
            "The runtime spawns goroutines that invoke this handler "
            "simultaneously, racing on shared state", "",
        )

    def test_package_spawns_claim_in_family(self):
        fence = self._fence()
        assert fence(
            "The package spawns a cleaner goroutine that races "
            "with Scan on r.Valid", "",
        )
