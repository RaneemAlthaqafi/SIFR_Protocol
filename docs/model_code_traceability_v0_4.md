# SIFR v0.4 Model ↔ Code Traceability

Maps each formal-model variable, action, and invariant to its implementation code path and test. A reviewer can use this table to confirm that the TLA+ model and the Tamarin model are not detached abstractions but concrete views of the running code.

## TLA+ state variables

| TLA+ variable | Type | Implementation | Test |
|---|---|---|---|
| `state[c]` | `Caps -> {unissued, active, expired, revoked}` | `sifr/capabilities.py:CapabilityStore` (active grant present) + grant `expires_at` + `RevocationRegistry.is_revoked` | `tests/test_capabilities.py` |
| `sub[c]` | `Caps -> Subs` | `grant_message["payload"]["subject"]` | `tests/test_capabilities.py` |
| `iss[c]` | `Caps -> Issuers` | `grant_message["payload"]["issuer"]` and grant `signature.kid` prefix | `tests/test_capabilities.py::verify_capability_grant` |
| `grantedActs[c]` | `Caps -> SUBSET Acts` | `grant_message["payload"]["actions"]` | `tests/test_v0_3_adversary.py::test_a22_unauthorized_tool` |
| `used[c]` | `Caps -> 0..MaxCalls` | `CapabilityStore._usage[cap_id]` | `tests/test_capabilities.py` |
| `consumedMsg` | `SUBSET (Subs × Msgs)` | `ReplayCache._mem` (and SQLite-backed `replay` table) | `tests/test_replay.py` |
| `revokedKids` | `SUBSET Kids` | applied at the resolver layer; in v0.3 implementation, the `KeyResolver.resolve` method raises `SignatureError` for revoked kids (see `EncryptedFileKeyStore.revoke`) | `tests/test_v0_3_adversary.py::test_a09_revoked_key` |
| `history` | sequence of records | not directly materialized at runtime; the `AuditDAG` carries the analogous information for accepted messages | `tests/test_audit_dag.py` |

## TLA+ actions

| TLA+ action | Implementation entry point | Code path |
|---|---|---|
| `Issue(c, s, i, A)` | `create_capability_grant` | `sifr/capabilities.py:create_capability_grant` |
| `Expire(c)` | implicit; the verifier checks `now >= expires_at` at authorize time | `sifr/capabilities.py:authorize_action` |
| `Revoke(c)` | `RevocationRegistry.revoke` | `sifr/revocation.py:RevocationRegistry.revoke` |
| `RevokeKey(k)` | `EncryptedFileKeyStore.revoke(kid, reason)` | `sifr/key_management.py:EncryptedFileKeyStore.revoke` |
| `Consume(c, s, i, k, a, m)` | `authorize_action` followed by `WasmToolRunner.execute` | `sifr/capabilities.py:authorize_action` → `sifr/wasm_runner.py:WasmToolRunner.execute` |

## TLA+ invariants

| Invariant | Implementation enforcement | Test |
|---|---|---|
| `TypeInvariant` | structural (Python type hints + runtime validation in `validate_message`) | `tests/test_messages.py` |
| `NoUnauthorizedActionConsume` | `authorize_action` raises `UnauthorizedAction("UNAUTHORIZED_ACTION")` when `action not in grant.actions` | `tests/test_v0_3_adversary.py::test_a22` |
| `NoWrongSubjectConsume` | `authorize_action` raises `UnauthorizedAction("WRONG_SUBJECT")` when `payload.subject != action.sender_id` | `tests/test_v0_3_adversary.py::test_a02` |
| `NoConsumeAfterExpire` | `authorize_action` raises `UnauthorizedAction("EXPIRED_CAPABILITY")` when `now >= expires_at` | `tests/test_v0_3_adversary.py::test_a10` |
| `NoConsumeAfterRevoke` | `authorize_action` raises `UnauthorizedAction("REVOKED_CAPABILITY")` when `revocation_registry.is_revoked(cap_id)` | `tests/test_v0_3_adversary.py::test_a12` |
| `NoOverBudgetConsume` | `authorize_action` raises `UnauthorizedAction("CALL_BUDGET_EXCEEDED")` when `store.usage(cap_id) >= max_calls`; raises `PAYLOAD_BUDGET_EXCEEDED` for size | `tests/test_v0_3_adversary.py::test_a18` |
| `NoReplayedConsume` | `ReplayCache.check_and_record` raises `ReplayError` for duplicate `(sender, session, msgid)` | `tests/test_v0_3_adversary.py::test_a13/a14/a15` |
| `NoConsumeWithWrongIssuer` | `verify_capability_grant` checks `payload.issuer == grant.sender_id` | `tests/test_v0_4_proof_obligations.py::test_C1_wrong_issuer` |
| `NoConsumeWithRevokedKey` | `KeyResolver.resolve` raises `SignatureError` for revoked kids | `tests/test_v0_3_adversary.py::test_a09` |

## Tamarin lemmas (model file: `formal/tamarin/sifr_core.spthy`; Tamarin NOT run in v0.4)

| Lemma | Implementation | Test |
|---|---|---|
| `authentication` | `verify_message` (Ed25519 + kid-DID-sender binding) | `tests/test_v0_4_proof_obligations.py::test_C4_*` |
| `authorization_required` | `authorize_action` | `tests/test_v0_4_proof_obligations.py::test_C1_*` |
| `replay_resistance` | `ReplayCache.check_and_record` | `tests/test_v0_4_proof_obligations.py::test_C2_*` |
| `revocation_safety` | `RevocationRegistry.is_revoked` (registry consulted before any other check) | `tests/test_v0_4_proof_obligations.py::test_C3_*` |
| `tool_safety` | `WasmToolRunner.execute` reached only after `authorize_action` returns true | `tests/test_v0_4_proof_obligations.py::test_C6_*` |

## What is NOT modeled

- Wire-level bytes (signature mutation, frame fragmentation): tested but not modeled.
- Cryptographic primitives' internal structure: assumed under standard hardness conditions.
- Real network paths: out of scope for both TLA+ and Tamarin in v0.4.
- Liveness, progress, fairness: not modeled.
- WASM sandbox internals: out of scope; isolation is empirically tested via the no-WASI-imports policy and adversarial fixtures.
