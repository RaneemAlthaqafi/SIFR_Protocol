# SIFR v0.4 Proof Obligations Matrix

A claim is **proven** only if a machine-checkable artifact (TLC, Tamarin, ProVerif, Coq, …) verifies it for an explicit domain. **bounded-proven** means TLC over a finite state space. **symbolic-proven** means Tamarin/ProVerif lemma proved. **tested** means positive + adversarial implementation tests but no formal artifact. **assumed** means a standard cryptographic or systems assumption. **future** means deferred.

| Claim | Formal model | Symbolic model | Code path | Positive tests | Negative tests | Benchmark | Paper section | Status | Residual |
|---|---|---|---|---|---|---|---|---|---|
| **C1 Authorization Safety** | TLC: `NoUnauthorizedActionConsume`, `NoWrongSubjectConsume`, `NoConsumeAfterExpire`, `NoConsumeAfterRevoke`, `NoOverBudgetConsume`, `NoConsumeWithWrongIssuer` | `formal/tamarin/sifr_core.spthy::lemma authorization_required` ✓ symbolic-proven (Tamarin 1.7.1, 5 steps) | `sifr/capabilities.py:authorize_action` | `tests/test_capabilities.py` | `tests/test_v0_3_adversary.py::test_a07/a09/a12/a17/a18/a22`, `tests/test_v0_4_proof_obligations.py::test_C1_*` | `benchmarks/results/v0.3/adversary_rejection.json` | §Formal Security Analysis | **bounded-proven + symbolic-proven** + tested | bounded TLC only; multi-process atomicity assumed |
| **C2 Replay Safety** | TLC: `NoReplayedConsume` | `formal/tamarin/sifr_core.spthy::lemma replay_resistance` ✓ symbolic-proven (Tamarin 1.7.1, 2 steps; requires `accepted_once_per_message` restriction modelling the SIFR `ReplayCache`) | `sifr/replay.py:check_and_record` | `tests/test_replay.py` | `tests/test_v0_3_adversary.py::test_a13/a14/a15/a16/a17`, `tests/test_v0_4_proof_obligations.py::test_C2_*` | `benchmarks/results/v0.3/replay_overhead.csv` | §Formal Security Analysis | **bounded-proven + symbolic-proven** + tested | per-process cache; clock skew assumed bounded |
| **C3 Revocation Safety** | TLC: `NoConsumeAfterRevoke` | `formal/tamarin/sifr_core.spthy::lemma revocation_safety` ✓ symbolic-proven (Tamarin 1.7.1, 2 steps) | `sifr/revocation.py`, `sifr/capabilities.py:authorize_action` | `tests/test_revocation.py` | `tests/test_v0_3_adversary.py::test_a12`, `tests/test_v0_4_proof_obligations.py::test_C3_*` | `benchmarks/results/v0.3/revocation_overhead.csv` | §Formal Security Analysis | **bounded-proven + symbolic-proven** + tested | per-process registry; no distributed gossip |
| **C4 Signature Binding** | TLC: covered by precondition `sub[c]=s, kid binding` | `formal/tamarin/sifr_core.spthy::lemma authentication` ✓ symbolic-proven (Tamarin 1.7.1, 6 steps) | `sifr/crypto.py:verify_message` (kid-DID/sender-id binding added in v0.3) | `tests/test_crypto.py`, `tests/test_did_resolution.py` | `tests/test_v0_3_adversary.py::test_a02/a05/a06/a08`, `tests/test_v0_4_proof_obligations.py::test_C4_*` | n/a | §Formal Security Analysis | **symbolic-proven** + tested | Ed25519 EUF-CMA assumed (Tamarin abstracts the primitive) |
| **C5 Audit DAG Tamper Evidence** | n/a (state machine abstracts wire bytes) | n/a | `sifr/audit_dag.py` | `tests/test_audit_dag.py` | `tests/test_v0_3_adversary.py::test_a20/a21`, `tests/test_v0_4_proof_obligations.py::test_C5_*` | n/a | §Formal Security Analysis | **tested** | SHA-256 collision resistance assumed |
| **C6 No Tool Before Authorization** | n/a (Consume action's preconditions encode the authorization check) | `formal/tamarin/sifr_core.spthy::lemma tool_safety` ✓ symbolic-proven (Tamarin 1.7.1, 3 steps) | `sifr/wasm_runner.py:execute` (via integration helper) | `tests/test_wasm_runner.py` | `tests/test_v0_3_adversary.py::test_a11_wasm_without_grant`, `tests/test_v0_4_proof_obligations.py::test_C6_*` | n/a | §Formal Security Analysis | **symbolic-proven** + tested | runner does not itself enforce; relies on call-site routing |
| **C7 Bounded State-Machine Safety** | TLC: 9 invariants × 11 601 distinct states at depth 7 | n/a | `formal/sifr_capability.tla`, `formal/MC.cfg` | `tests/test_formal_artifacts.py` (fail-closed via `SIFR_TLC_FROZEN=1`) | `tests/test_v0_4_proof_obligations.py::test_C7_*` | n/a | §Formal Security Analysis | **bounded-proven** | bounded constants; no liveness; no refinement |

## Tally

| Status | Count | Claims |
|---|---|---|
| bounded-proven (TLC) | 4 | C1, C2, C3, C7 |
| symbolic-proven (Tamarin 1.7.1) | 5 | C1, C2, C3, C4, C6 |
| tested | 7 | C1-C7 (every claim has positive + adversarial implementation tests) |
| symbolic-modeled but NOT run | 0 | — (was 4 in v0.4-rc1; v0.4.0 ran all lemmas) |

**v0.4.0 Tamarin run (5/5 verified, 0 warnings):**

```
authentication (all-traces): verified (6 steps)
authorization_required (all-traces): verified (5 steps)
replay_resistance (all-traces): verified (2 steps)   [requires accepted_once_per_message restriction]
revocation_safety (all-traces): verified (2 steps)
tool_safety (all-traces): verified (3 steps)
```

Reproduction (Docker; no native Tamarin install required):
```
docker run --rm --entrypoint tamarin-prover \
  -v "$PWD:/work" -w /work aeads/tamarin:latest \
  --prove formal/tamarin/sifr_core.spthy \
  --output=formal/output/tamarin_proof.spthy
```

## Reading the matrix

- A row's **Status** is the strongest level applicable to that claim *given the artifacts checked in this release*.
- "symbolic-proven" in v0.4.0 means Tamarin Prover 1.7.1 verified the lemma using the `aeads/tamarin:latest` Docker image. The reproduction commands and verified counts are listed in this document and in `formal/output/tamarin_metadata.json`.
- Promoting a `tested` row to `proven` requires either a TLC invariant added to `formal/sifr_capability.tla` (for state-machine claims) or running Tamarin / ProVerif (for cryptographic claims).
- Promoting a `bounded-proven` row to `proven` requires lifting the bounded constants — typically by inductive proof in a tool like TLAPS or Coq.

## What this matrix does NOT claim

- Full cryptographic security. Ed25519, Argon2id, AES-GCM, SHA-256 are all **assumed** under their standard hardness conditions.
- Implementation refinement. We do not prove that `sifr/capabilities.py` refines `sifr_capability.tla`; we test it via the v0.3 30-case strict adversary suite and the v0.4 proof-obligation suite.
- Liveness or progress.
- Anything outside the seven enumerated claims.
