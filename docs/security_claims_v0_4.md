# SIFR v0.4 Formal Security Claims

Each claim has: a **natural-language** form, a **formal** form (predicate over execution traces), an **adversary model**, **trusted assumptions**, the **proof mechanism** by which the claim is checked, **code locations**, **tests**, and **limitations**. A claim is marked **proven** only if a machine-checkable artifact validates the formal form for the bounded domain stated.

The framing follows the convention of separating *what is proven* from *what is tested*, *what is assumed*, and *what is out of scope*. We do not claim full cryptographic security, production-deployment readiness, or arbitrary-untrusted-code WASM safety.

---

## C1 Authorization Safety

- **Natural-language statement.** A SIFR action is accepted only if the verifier possesses a valid capability whose issuer, subject, action membership, resource scope, expiration, payload-size budget, call-count budget, delegation flag, signature, and revocation status all pass.
- **Formal statement.** For every history `h` produced by the SIFR authorization state machine, and every index `i` such that `h[i].op = "Consume"`, all of the following hold at the moment of consumption:
  - `state[h[i].cap] = "active"`
  - `sub[h[i].cap] = h[i].sub`
  - `iss[h[i].cap] = h[i].iss`
  - `h[i].act ∈ grantedActs[h[i].cap]`
  - `h[i].kid ∉ revokedKids`
  - `used[h[i].cap] < MaxCalls`
  - `(h[i].sub, h[i].msg) ∉ consumedMsg` immediately before the action.
- **Adversary model.** A passive observer with knowledge of the public state and the ability to attempt arbitrary `Issue`/`Expire`/`Revoke`/`RevokeKey`/`Consume` transitions.
- **Trusted assumptions.** The implementation evaluates `authorize_action` exactly once per action, atomically with respect to the `CapabilityStore`, `RevocationRegistry`, and `ReplayCache` it is given. Process-internal locks and single-process invocation are assumed.
- **Proof mechanism.** TLA+ model checked by TLC against the bounded constants in `formal/MC.cfg`. Invariants `NoUnauthorizedActionConsume`, `NoWrongSubjectConsume`, `NoConsumeAfterExpire`, `NoConsumeAfterRevoke`, `NoOverBudgetConsume`, `NoConsumeWithWrongIssuer`, `NoConsumeWithRevokedKey` jointly enforce the formal statement.
- **Code locations.** `sifr/capabilities.py:authorize_action`, `sifr/capabilities.py:verify_capability_grant`, `sifr/replay.py:ReplayCache.check_and_record`, `sifr/revocation.py:RevocationRegistry.is_revoked`.
- **Tests.** `tests/test_capabilities.py`, `tests/test_v0_3_adversary.py::test_a07/a09/a12/a17/a18/a22`, `tests/test_v0_4_proof_obligations.py::test_C1_*`.
- **Benchmark relevance.** `benchmarks/results/v0.3/adversary_rejection.json` records the per-attack reject latency.
- **Limitations.** Bounded-state TLC verification only (`Caps={c1}`, `Subs={alice,bob}`, `Issuers={alice,bob}`, `Acts={add,multiply}`, `Msgs={m1,m2}`, `Kids={k1,k2}`, `MaxCalls=2`). Multi-process atomicity is *assumed*, not proven. Cryptographic strength of Ed25519 / Argon2id / AES-GCM is *assumed*.

---

## C2 Replay Safety

- **Natural-language statement.** A message identified by `(sender_id, session_id, message_id)` cannot be accepted twice by a single `ReplayCache` within the configured replay window.
- **Formal statement.** For every history `h`, for every `i, j ∈ 1..Len(h)` with `i ≠ j`, if `h[i].op = "Consume"` and `h[j].op = "Consume"` and `h[i].sub = h[j].sub` and `h[i].msg = h[j].msg`, then FALSE.
- **Adversary model.** An attacker who can observe and re-submit any previously-issued signed action.
- **Trusted assumptions.** Process clock is monotonic and accurate to within the configured replay window (default 300 s).
- **Proof mechanism.** TLA+ invariant `NoReplayedConsume` (proven by TLC). Implementation verified by `tests/test_replay.py::test_modified_signature_same_msgid_still_rejected` (the cache key is binding-on-msgid, not on signature value).
- **Code locations.** `sifr/replay.py:ReplayCache.check_and_record`.
- **Tests.** `tests/test_replay.py` (12 tests), `tests/test_v0_3_adversary.py::test_a13/a14/a15/a16/a17`, `tests/test_v0_4_proof_obligations.py::test_C2_*`.
- **Benchmark relevance.** `benchmarks/results/v0.3/replay_overhead.csv` characterizes O(n) GC cost.
- **Limitations.** Single-process cache. Cross-process replay protection requires shared SQLite path. Sliding window does not protect against attackers who can manipulate a verifier's clock.

---

## C3 Revocation Safety

- **Natural-language statement.** If a valid revocation record for capability `cap` is known to the verifier before authorization runs, then no future action using `cap` is accepted.
- **Formal statement.** For every history `h`, for every `i, j ∈ 1..Len(h)`, if `h[i].op = "Revoke"` and `h[j].op = "Consume"` and `h[i].cap = h[j].cap` and `i < j`, then FALSE.
- **Adversary model.** An attacker holding a previously-issued capability after its issuer has revoked it.
- **Trusted assumptions.** The verifier reads the registry strictly before authorization. The registry's signed records authenticate to the issuer's public key.
- **Proof mechanism.** TLA+ invariant `NoConsumeAfterRevoke`. Implementation: `RevocationRegistry._load` re-verifies signatures on rehydration; `authorize_action` consults the registry before any other check.
- **Code locations.** `sifr/revocation.py`, `sifr/capabilities.py:authorize_action`.
- **Tests.** `tests/test_revocation.py` (12 tests), `tests/test_v0_3_adversary.py::test_a12`, `tests/test_v0_4_proof_obligations.py::test_C3_*`.
- **Limitations.** Per-process registry. Distributed propagation (gossip/consensus) is out of scope.

---

## C4 Signature Binding

- **Natural-language statement.** If a message is accepted as having been sent by `sender_id`, then the message's signature verifies under a public key resolved and bound to that `sender_id` (via the kid's DID prefix).
- **Formal statement.** For every accepted message `m`, `m.signature.kid` parses as `did#fragment` with `did = m.sender_id`, AND `verify_message(m, resolver)` returns true with the resolver-resolved key for `m.signature.kid`.
- **Adversary model.** An attacker with valid signing capability under one principal's key trying to sign as another principal.
- **Trusted assumptions.** Ed25519 is EUF-CMA-secure. Resolver returns the correct public key for the published kid (no DID document poisoning).
- **Proof mechanism.** Tested rather than fully proven. `sifr/crypto.py:verify_message` enforces `kid_did = sender_id` when a resolver is in use; cryptographic guarantee is assumed under the EUF-CMA assumption.
- **Code locations.** `sifr/crypto.py:verify_message`.
- **Tests.** `tests/test_crypto.py`, `tests/test_did_resolution.py`, `tests/test_v0_3_adversary.py::test_a02/a05/a06/a08`, `tests/test_v0_4_proof_obligations.py::test_C4_*`.
- **Limitations.** Cryptographic security is **assumed**, not proven. The Tamarin symbolic model `formal/tamarin/sifr_core.spthy` specifies a Dolev-Yao-style lemma but is not run in v0.4 (Tamarin not installed in the reference environment). Promotion from `tested` to `symbolic-proven` requires running Tamarin.

---

## C5 Audit DAG Tamper Evidence

- **Natural-language statement.** If a committed message changes after CID computation, then DAG integrity verification fails.
- **Formal statement.** For every node `n` in `dag.nodes`, `sha256(canonical_bytes(dag.messages[n.cid])) = n.cid`. If any byte of a stored message is altered, this equality fails.
- **Adversary model.** A local attacker with write access to the audit log who attempts to modify a stored message without updating the DAG.
- **Trusted assumptions.** SHA-256 is collision-resistant.
- **Proof mechanism.** Implementation-tested. Not modeled in TLA+ (the state machine abstracts away wire bytes).
- **Code locations.** `sifr/audit_dag.py`.
- **Tests.** `tests/test_audit_dag.py`, `tests/test_v0_3_adversary.py::test_a20/a21`, `tests/test_v0_4_proof_obligations.py::test_C5_*`.
- **Limitations.** SHA-256 collision resistance is **assumed**, not proven. Detection of tampering occurs at `verify_dag_integrity()` call time; an adversary that can revert tampered bytes before verification can hide.

---

## C6 No Tool Before Authorization

- **Natural-language statement.** The tool runner is invoked only after signature, replay, capability, revocation, expiration, budget, and action checks pass.
- **Formal statement.** For every execution trace `e`, for every index `i` where `e[i] = ToolRunner.execute(...)`, there exists `j < i` where the corresponding `authorize_action(...)` returned true.
- **Adversary model.** An attacker who tries to invoke `WasmToolRunner.execute()` directly without going through `authorize_action`.
- **Trusted assumptions.** Application code routes tool invocations through `authorize_action`. Direct invocation of `WasmToolRunner.execute` is a **misuse**, not an attack vector.
- **Proof mechanism.** Tested at the integration boundary by `tests/test_v0_3_adversary.py::test_a11_wasm_without_grant` (attempting tool invocation without a grant raises `CapabilityError` at the integration helper before any WASM work). The TLA+ model does not separate Authorize from Consume — both are folded into the `Consume` action whose preconditions encode the authorization checks; in TLC terms, the `NoToolInvocationBeforeAuthorization` claim is a corollary of the precondition-guarded `Consume` action.
- **Code locations.** `sifr/wasm_runner.py:WasmToolRunner.execute`, integration helpers in `tests/test_v0_4_proof_obligations.py`.
- **Tests.** `tests/test_v0_3_adversary.py::test_a11`, `tests/test_v0_4_proof_obligations.py::test_C6_*`.
- **Limitations.** The runner does NOT itself enforce the authorization gate; the application's call site does. A malicious runtime could call `runner.execute()` directly. Pure structural enforcement (e.g., via a private constructor, capability-based runtime injection) is future work.

---

## C7 Bounded State-Machine Safety

- **Natural-language statement.** The TLA+ model satisfies authorization, replay, revocation, issuer-binding, subject-binding, budget, and revoked-key invariants for the configured bounded domain.
- **Formal statement.** TLC explores every reachable state of `formal/sifr_capability.tla` under the constants in `formal/MC.cfg` and reports no invariant violation. Distinct states explored: 11 601 at depth 7.
- **Adversary model.** Any adversary expressible by valid `Next`-relation transitions over the bounded constants.
- **Trusted assumptions.** TLC's exploration is sound (TLA+ standard semantics). The bounded constants' choice does not artificially exclude attack states; lifting to the unbounded case is a separate proof step.
- **Proof mechanism.** TLA+ model-checked by TLC. Output and metadata: `formal/output/tlc_output.txt`, `formal/output/tlc_metadata.json`, `formal/output/model_hashes.json`.
- **Code locations.** `formal/sifr_capability.tla`, `formal/MC.cfg`, `tests/test_formal_artifacts.py`.
- **Tests.** `tests/test_formal_artifacts.py` (8 tests, fail-closed via `SIFR_TLC_FROZEN=1`).
- **Limitations.** Bounded only. Lifting to unbounded constants is future work. Liveness, fairness, and refinement to the implementation are not proven.

---

## What is *not* claimed

- **Full cryptographic security.** Ed25519, Argon2id, AES-256-GCM, SHA-256 are *assumed* secure. Their guarantees are not proven by SIFR.
- **W3C VC compliance.** Credentials are VC-inspired; no JSON-LD context processing or URDNA2015 RDF normalization.
- **Arbitrary-untrusted-code WASM safety.** WASM isolation is verified for the calculator and two adversarial fixtures. Reasoning about arbitrary modules is out of scope.
- **Production-deployment readiness.** No HSM, no KMS, no enterprise PKI, no distributed gossip.
- **Real-network or Internet-scale QUIC.** Single-host Docker-bridge + NetEm only.
- **Liveness / progress.** Only safety properties.
- **Implementation refinement.** The TLA+ spec models the *protocol*; that the Python code refines it is **not** proven, only tested via the v0.3 30-case strict adversary suite and the v0.4 proof-obligation suite.

---

## Reading guide

| Status | Meaning |
|---|---|
| **proven** | Bounded TLC verification or symbolic-tool verification of the formal statement, machine-checkable. |
| **bounded-proven** | TLC over a finite domain; lifting to unbounded states is future work. |
| **symbolic-proven** | Tamarin/ProVerif lemma proven in the symbolic model. *Reserved for future SIFR releases — Tamarin/ProVerif not run in v0.4.* |
| **tested** | Positive and negative test evidence; no formal artifact. |
| **assumed** | Standard cryptographic or systems assumption (e.g., Ed25519 EUF-CMA, single-process atomicity). |
| **future** | Not in scope for the current release. |
