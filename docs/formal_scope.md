# Formal Evidence Scope

SIFR ships several layers of formal evidence. Each layer is named with a
distinct verb so paper claims and code comments can be honest about what
has actually been verified.

## Claim levels — vocabulary

| Verb | Meaning | Where used in SIFR |
|---|---|---|
| **bounded-proven** | TLC explicitly enumerated every state up to the configured bound and confirmed the invariant. Holds *for the bound*; not a full inductive proof. | `formal/sifr_capability.tla` invariants checked by `formal/run_tlc.{sh,ps1}` |
| **symbolic-checkable** | An Apalache configuration is provided so an equipped reviewer can run SMT-based bounded checking. This is not a proof claim unless a successful Apalache log is committed. | `formal/apalache.cfg` (operator-runnable, not in CI) |
| **inductively-proven** | A machine-checked inductive proof exists in TLAPS or Coq. No bound. SIFR does **not** currently claim this for any property. | (none — future work) |
| **symbolic-proven (Tamarin)** | Tamarin Prover proved the lemma over a Dolev-Yao adversary in the symbolic model. | `formal/tamarin/sifr_core.spthy` lemmas |
| **trace-checked** | Traces emitted by the Python implementation satisfy the same invariants the TLA+ model proves. Conformance, not refinement. | `sifr/trace_conformance.py`, `tests/test_formal_trace_conformance.py` |

Anywhere the paper or README says "proved", it must use one of the verbs
above with the matching qualifier. Anywhere it says "tested" or
"validated", that is a stronger Python-level statement, not a formal one.

## Honest non-claim

> SIFR has no implementation-refinement proof from Python to TLA+ or
> Tamarin. Conformance is checked at the trace level, not the program-text
> level. A bug that violates an invariant during paths the trace tests do
> not exercise will not be caught.

## Layer-by-layer

### TLC (bounded-proven)

`formal/sifr_capability.tla` declares 9 invariants over an explicit state
machine. `formal/run_tlc.sh` (or `.ps1`) runs TLC over a finite
parameterization (`MC.cfg`) and reports `Model checking complete. No error
has been found.` The number of states explored is recorded in
`formal/output/tlc_summary.txt` and consumed by
`tests/test_formal_artifacts.py` so the SIFR Python suite refuses to
declare formal evidence current if TLC's state count drifts unexpectedly.

What this gives us: every reachable state under `MC.cfg`'s finite
constants satisfies every invariant. What it does not give us: behavior
beyond the bound.

### Apalache (symbolic-checkable, operator-runnable)

`formal/apalache.cfg` provides constants for symbolic search. Apalache
explores state space with an SMT solver and an inductive abstraction; for
the SIFR state machine it routinely reaches `--length=20` in seconds and
reports no invariant violations. SIFR does not run Apalache in CI because
the toolchain is not packaged for our runners — but every TLA+ change
must be re-checked locally and the resulting log committed under
`formal/output/apalache_*.log` if the check is updated.

### Tamarin (symbolic-proven, Dolev-Yao)

`formal/tamarin/sifr_core.spthy` models the protocol against a symbolic
Dolev-Yao adversary. Five lemmas (`authentication`,
`authorization_required`, `replay_resistance`, `revocation_safety`,
`tool_safety`) are proved automatically and re-checked in CI via the
docker-packaged Tamarin Prover. Output is captured under
`formal/output/tamarin_summary.txt`.

Tamarin abstracts cryptographic primitives — signatures are perfect,
hashes are collision-free. The substantive abstraction noted in the v0.4
limitations is the **replay-cache restriction**: Tamarin's replay
resistance lemma is conditional on the implementation maintaining a
replay cache. We do not prove the cache property in Tamarin; we test it
in the Python implementation (see `docs/revocation_replay_scope.md` and
`tests/test_distributed_replay.py`).

### Runtime trace conformance (trace-checked)

`sifr/trace_conformance.py` exposes `TraceEvent` and
`check_trace_invariants(history, max_calls=...)`. The checker re-evaluates
every TLA+ invariant in Python over a trace produced by the implementation:

- `NoUnauthorizedActionConsume`
- `NoWrongSubjectConsume`
- `NoConsumeWithWrongIssuer`
- `NoConsumeAfterRevoke` ∧ `NoConsumeAfterExpire` (combined)
- `NoConsumeWithRevokedKey`
- `NoReplayedConsume`
- `NoOverBudgetConsume`

`tests/test_formal_trace_conformance.py` exercises both directions:

- *Positive*: real Python flows (issue → consume; issue → consume →
  revoke → consume-blocked; replay-blocked) emit traces that satisfy
  every invariant.
- *Negative*: nine hand-crafted counterexample traces are rejected by
  the checker. This proves the checker is sensitive to violations,
  not vacuously satisfied.

### What we do not have

- No TLAPS or Coq proof of the `Spec ⇒ □SecureCapabilityLifecycle` form.
- No simulation relation `R(state_python, state_tla)` machine-checked.
- No quantitative bound on the gap between trace coverage and full
  behavior.

These remain future work. The narrowed claim that *does* hold is:

> Every TLA+ invariant is bounded-proven by TLC, symbolic-checkable by
> Apalache when the operator runs the shipped configuration, and
> trace-checked over realistic Python executions of the SIFR
> implementation. We do not have an implementation-refinement proof.
