# Sanitizer-cut enforcement dossier

Evidence package for the operator decision to flip the sanitizer-cut
witness from record-only to enforcing. The decision itself is the
operator's; this document assembles what the earning protocol
(`core/analysis/reach_witness.py`, binary-oracle precedent) requires
so the flip is one reviewed field change plus a recorded attestation.

## What is being decided

`sanitizer_dominated` verdicts (the value-bound vertex-cut: every
tainted source→sink path crosses a catalog sanitizer whose cleaned
value reaches the sink) are today recorded to `suppressions.jsonl`
with `dropped: false` and never remove a finding. Enforcement would
let the reachability chokepoint hard-suppress findings carrying this
verdict, exactly as `binary_oracle_absent` does.

## Mechanics of the flip

1. `core/analysis/reach_witness.py` — the `sanitizer_dominated`
   `VerdictSpec` carries `earns_suppression=False`; the flip is that
   one field. `STRUCTURALLY_SUPPRESSIBLE_KINDS` then admits
   `WitnessKind.SANITIZER_CUT` automatically; `check_suppress` starts
   firing; producers set `dropped: true` on enforced records
   (`record_sanitizer_cut_suppression(..., enforce=True)`).
2. The attestation: record the clean
   `libexec/raptor-sanitizer-cut-precision` report (path + sha256 +
   toolchain block) alongside the flip commit — the binary-oracle
   protocol's "corpus results recorded with the change" rule.

## Corpus evidence (adversarial precision harness)

- Current corpus: **144 fixtures, 106 must-not-suppress, zero false
  suppressions, zero missed suppressions**; rule-of-three 95% upper
  bound on the false-suppress rate **0.0283**.
- Trajectory as mechanisms were added (each round re-ran the full
  corpus): 33 fixtures / UB 0.115 → 49 / 0.079 → 79 / 0.049 →
  94 / 0.0319 → 116 / 0.034 → 124 / 0.0319 → 144 / 0.028.
- The corpus has caught **five real would-be false-suppression bugs
  before ship** (loop-rebind exclusivity; one-liner enclosure;
  anonymous-subclass dispatch; wrong-branch string folding;
  reaching-defs leak through pruned join edges) — the gate's history
  is that the corpus works.

## Live evidence (production-shape measurement runs)

Fifteen warm-scored OWASP measurement runs across rounds 6–9:
**3,337 suppression records, zero malformed, true-finding damage 0 in
every run** (a damage entry = a suppress verdict mapping onto a found
expected finding; the matcher is CWE-family-discriminating and counts
CWE-less records as damage — the refusal direction). Would-suppress
grew 3 → 88 as mechanisms landed while damage never left zero.

## Guards that stay in force under enforcement

- Exclusive-definer condition (b11), sibling-argument taint guard,
  may_escape conservatism, refusal-first CFG (unmodellable constructs
  refuse the whole build), catalog semantic-honesty rules, CWE-family
  record discrimination.
- Suppression remains per-finding and auditable: every enforced drop
  writes its full evidence record.

## Honest caveats

- The corpus is OWASP-plus-adversarial-fixtures weighted. The Juliet
  warm run HAS now been measured (source-kind locator generalization,
  full manifest, serialized workers): would-suppress 0, true-finding
  damage 0 (vacuously — zero suppression records), 29,749 findings
  examined. The source locator generalizes (11,596 non-servlet
  candidates attributed across console/environment/file/properties/
  database/socket kinds; no-source refusals fell 18,195 -> 15,059) but
  the GATE does not yet fire on Juliet: 11,645 findings refuse at
  resolution (Juliet's source and sink commonly live in different
  methods — the resolver is intra-method) and the 3,045 that resolve
  meet control-flow-shaped guards where the gate's mechanisms are
  call/constant-shaped. Enforcement implication: a flip is supportable
  on OWASP-shaped evidence only; zero-record Juliet behavior means
  enforcement would be a no-op there (it cannot damage what it never
  suppresses). Cross-method resolution and branch-guard mechanisms are
  the pre-conditions for Juliet-positive evidence.
  Historical recommendation (retained): one Juliet
  warm run pre-flip.
- UPDATE (cross-method candidate scoping measured, full Juliet
  manifest): the intra-method resolution blocker is now closed —
  traceless candidates scope to the sink's enclosing method on an
  engine-fact basis (intra-procedural producers cannot have used a
  cross-method source), collapsing resolver refusals 11,645 -> 1,651
  with OWASP byte-identical (same 278 suppress records, damage 0).
  Suppression on Juliet remains honestly ZERO, and the residual is now
  precisely named: 17,161 findings have no intra-method source
  candidate at all — Juliet's traceless findings are dominantly
  PRESENCE-rule findings (weak-crypto/config shapes) with no taint
  question the value-bound gate can adjudicate, an out-of-domain
  class rather than a coverage gap — and 3,236 resolve but meet
  control-flow-shaped guards (branch-guard mechanisms remain the one
  buildable pre-condition). Enforcement implication unchanged and
  sharpened: a flip stays a Juliet no-op, and the flagged pre-flip
  Juliet warm measurement is now DONE (zero records, zero damage,
  twice measured under different locator generations).
- Mechanism maturity differs: encoder cuts and constant-definers have
  the longest live history; conduit summaries are the newest (one
  round). A staged flip (enforce only verdicts whose mechanism
  attribution predates the newest round) is a defensible middle
  option and mechanically easy (the records carry attribution).
- Enforcement converts any future gate bug from an FP-report artifact
  into a false negative. The corpus discipline (fixtures-before-
  relaxation, harness in CI-able form) is the standing mitigation.

## Recommendation shape (not a decision)

Evidence supports enforcement for the mature mechanism classes with
the staged option available; the pre-flip Juliet warm run is the one
outstanding measurement this dossier flags as missing.
