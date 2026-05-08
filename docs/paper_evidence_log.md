# Paper Evidence Log

Append one paragraph per implemented v0.2 feature, with file paths, test names, and metric values. The Phase-5 paper revision pass consumes this log directly. **Do not summarize from memory** — every claim in `paper/main.tex` must trace back to an entry here.

Template per entry:

```
## <feature> — <YYYY-MM-DD>

**Code:** `<path>` (key functions: `<f1>`, `<f2>`)
**Tests:** `tests/<test_file>::<test_name>` (positive); `tests/<test_file>::<negative_test>` (reject path)
**Demo:** `examples/<demo>.py`
**Benchmark:** `benchmarks/<bench>.py` → `benchmarks/results/<output>` (key metric: <value> ± <stdev>)
**Documentation:** `docs/<doc>.md`
**Claim made in paper:** "<exact claim text>"
**Claim NOT made:** <what we explicitly do not claim and why>
**Trap-acceptance test:** `tests/<file>::<adversarial_test>` — proves implementation is real, not in-name-only
```

---

## Pre-phase refactor — 2026-05-08

**Code:** `sifr/canonical.py` (canonicalization), `sifr/keyring_iface.py` (KeyResolver Protocol), `sifr/crypto.py:verify_message` (resolver overload), `sifr/transport/` (package split)
**Tests:** all 27 v0.1 tests still pass after refactor (`pytest -q`)
**Claim:** none (refactor only). Pre-phase establishes the seams later phases plug into.

## Key management — 2026-05-08

**Code:** `sifr/key_management.py` (`EncryptedFileKeyStore` with Argon2id KDF + AES-256-GCM, kid bound as AAD, atomic write-then-rename, rotation, revocation metadata).
**Tests:** `tests/test_key_management.py` — 14 tests covering creation/reload, wrong-passphrase rejection, unknown kid, duplicate kid, multi-key, rotation, revocation, idempotent revocation, file-does-not-contain-raw-private-key, tampered-ciphertext, kid-AAD-binding-prevents-swap. **Trap-acceptance tests:** `test_keystore_file_does_not_contain_raw_private_key` (proves encryption is real, not a flag) and `test_kid_aad_binding_prevents_ciphertext_swap` (proves AAD binding works).
**Demo:** `examples/demo_key_rotation.py` — generates kid-1, rotates to kid-2, signs and verifies, revokes kid-1.
**Documentation:** `docs/key_management.md` — threat model, file format, cryptographic construction, rotation policy.
**Claim made:** local encrypted key storage and key rotation. Files are encrypted at rest; rotation supports multiple kids per agent.
**Claim NOT made:** HSM-grade storage, FIPS-140-3, enterprise PKI, multi-process concurrent writes, side-channel resistance.

## DID resolution — 2026-05-08

**Code:** `sifr/did/__init__.py` (DidResolver ABC, DidDocument, parse_kid, parse_did_document, MultiMethodResolver), `sifr/did/did_web.py` (DidWebResolver via httpx, percent-encoded port handling per W3C spec), `sifr/did/did_sifr.py` (local-only DID method with path-traversal protection).
**Tests:** `tests/test_did_resolution.py` — 22 tests including positive resolve+verify for both methods, 404, malformed JSON, missing verificationMethod, wrong id in doc, kid-not-in-doc, unsupported vmethod type, controller mismatch, did:web subpath, did:web caching, MultiMethodResolver dispatch, parse_kid invariants. **Trap-acceptance tests:** `test_did_sifr_kid_not_in_doc` (resolver actually inspects vmethod list, not just prefix), `test_did_sifr_controller_mismatch_rejected`, `test_did_sifr_path_traversal_rejected`, `test_did_sifr_wrong_id_in_doc`, `test_did_web_id_mismatch`.
**Fixture:** `tests/fixtures/did_web_server.py` — loopback HTTPServer on ephemeral port; tests proven to actually use HTTP traffic, not mocks.
**Demo:** `examples/demo_did_resolution.py`.
**Benchmark:** `benchmarks/bench_did_resolution.py` -> `benchmarks/results/did_resolution.csv`. On Python 3.14.2 / Windows 11:
- did:sifr cold ~0.07 ms, warm ~0.002 ms (n=5000)
- did:web cold ~280 ms (loopback HTTP RTT, fresh httpx.Client per iteration), warm ~0.002 ms (n=500)
**Documentation:** `docs/did_method.md` — supported schema, did:web URL mapping, did:sifr method spec, explicit non-claims.
**Claim made:** did:web resolution per the W3C method spec, with localhost-fixture-verified HTTP traffic; did:sifr local resolution with documented schema.
**Claim NOT made:** W3C DID ecosystem interoperability, JSON-LD context handling, support for verificationMethod types other than Ed25519, support for did:key/did:ion/etc.

## Phase 1 integration — 2026-05-08

**Code:** `sifr/capabilities.py` — `verify_capability_grant` and `authorize_action` accept `Union[Ed25519PublicKey, KeyResolver]`. Behavior unchanged for direct-key callers.
**Integration demo:** `examples/demo_secure_quic_wasm_did_flow.py` — first line flipped from PENDING to OK (`DID resolution: OK`).
**Tests:** all 63 tests pass (27 v0.1 + 14 key mgmt + 22 DID).

## Replay protection — 2026-05-08

**Code:** `sifr/replay.py` (`ReplayCache` keyed on `(sender_id, session_id, message_id)`, sliding window default 5 minutes, optional SQLite persistence with on-load restore).
**Tests:** `tests/test_replay.py` — 12 tests covering first-accepted, duplicate-rejected, modified-signature-still-rejected (cache keys on msgid not signature), different-session-allowed, different-sender-allowed, stale, future, within-window, missing-fields, persistence-across-restart, gc-with-explicit-now, window-boundary-inclusive. **Trap-acceptance test:** `test_modified_signature_same_msgid_still_rejected` (proves the cache binds to message identity, not signature bytes).
**Demo:** `examples/demo_replay_rejection.py` — first delivery authorized, second rejected with ReplayError before any auth check runs.
**Integration:** `sifr/capabilities.py:authorize_action` accepts `replay_cache` kwarg; replay check runs after signature verify, before existing auth checks.
**Benchmark:** `benchmarks/bench_replay_overhead.py` -> `benchmarks/results/replay_overhead.csv`.
**Claim made:** replay protection within the documented (sender, session, message_id) cache + sliding-window-timestamp model.
**Claim NOT made:** distributed replay protection across multiple verifying nodes (cache is per-process), Byzantine fault tolerance.

## Capability revocation — 2026-05-08

**Code:** `sifr/revocation.py` (`RevocationRegistry` with signed `CapabilityRevocation` SIFR messages, optional JSONL persistence with signature re-verification on load).
**Tests:** `tests/test_revocation.py` — 12 tests covering revoke-returns-signed, idempotent, revoke-without-private-key, persistence-roundtrip, persistence-tampered-rejected, load-without-verifier-fails, add-external-entry-verifies, add-entry-wrong-type-rejected, add-entry-bad-signature-rejected, export. **Trap-acceptance test:** `test_persistence_tampered_record_rejected` (proves the registry verifies signatures on load — tampering with a stored record fails reload).
**Demo:** `examples/demo_revoked_capability.py` — pre-revoke action authorized, post-revoke same cap_id rejected with `UnauthorizedAction("REVOKED_CAPABILITY")`.
**Integration:** `sifr/capabilities.py:authorize_action` accepts `revocation_registry` kwarg; revocation check runs immediately after replay check.
**Claim made:** local revocation, with signed registry entries that are re-verified on load.
**Claim NOT made:** distributed revocation synchronization, gossip-based dissemination, real-time revocation propagation.

## VC-inspired capability credentials — 2026-05-08

**Code:** `sifr/credentials.py` (`issue_credential`, `verify_credential`, `credential_to_grant`; W3C-shape JSON with `@context`, `type`, `issuer`, `issuanceDate`, `expirationDate`, `credentialSubject`, `proof.type=Ed25519Signature2020`).
**Tests:** `tests/test_credentials.py` — 15 tests including 6 trap-acceptance tests: mutate-subject-id-fails, mutate-expiration-fails, mutate-capability-fails, swap-proof-value-fails, issuer-DID-must-match-verificationMethod-DID, signed-by-wrong-key-fails. Plus expiration, not-yet-valid, missing-proof, unsupported-proof-type, wrong-proof-purpose.
**Demo:** `examples/demo_capability_credential.py` — issue, verify, extract, mutate-and-fail.
**Documentation:** `docs/credential_model.md` — full data model, verification rules, explicit non-claims (no W3C VC compliance, no JSON-LD, no URDNA2015, no StatusList2021).
**Benchmark:** `benchmarks/bench_credential_verification.py` -> `benchmarks/results/credential_verification.csv`.
**Claim made:** "VC-inspired signed credential" with Ed25519 proof, expiration, subject binding, and issuer-DID/verificationMethod-DID consistency check.
**Claim NOT made:** W3C VC Data Model 1.1 compliance, JSON-LD context handling, URDNA2015 RDF canonicalization, StatusList2021 / RevocationList2020, holder presentations, ZKP proofs.

## Phase 2 integration — 2026-05-08

**Code:** `sifr/capabilities.py:authorize_action` accepts `revocation_registry` and `replay_cache` kwargs. Order of checks: signature verify → replay check → revocation check → existing checks.
**Errors:** `sifr/errors.py` adds `RevocationError`, `ReplayError`, `CredentialError`.
**Messages:** `sifr/messages.py` adds `CapabilityRevocation` to `MESSAGE_TYPES`. AuditDAG accepts the new type with no further changes (existing add_message is type-agnostic).
**Integration demo:** `examples/demo_secure_quic_wasm_did_flow.py` — `Capability credential: OK`, `Replay check: OK`, `Revocation check: OK` lines flipped.
**Tests:** all 102 tests pass (27 v0.1 + 14 keys + 22 DID + 12 replay + 12 revocation + 15 credentials).

## WASM tool isolation — 2026-05-08

**Code:** `sifr/wasm_runner.py` — `WasmToolRunner` using wasmtime 44, no WASI imports linked, fuel-bounded per call (default 1M), fresh Store per call (state isolation). `PythonCalculatorReference` retained as parity reference. Backwards-compat alias `CalculatorTool = PythonCalculatorReference`.
**Modules:** `wasm/calculator/calculator.wat` (13-line WAT, no imports, no memory). `tests/fixtures/wasm_modules/looping.wat` (infinite-loop adversarial fixture). `tests/fixtures/wasm_modules/fs_attempt.wat` (imports `wasi_snapshot_preview1.path_open`, must fail to instantiate).
**Tests:** `tests/test_wasm_runner.py` — 13 tests. **Trap-acceptance tests:**
- `test_python_and_wasm_parity`: 8 input pairs (incl. negatives, large values) bit-identical between Python and WASM.
- `test_evidence_counter_advances_per_call`: every successful call increments `last_invocation_evidence["fuel_consumed"]` (a Python fall-through would never advance it).
- `test_calculator_does_not_have_wasi_imports`: committed module has zero imports.
- `test_fs_attempt_module_fails_to_instantiate`: hostile module importing WASI cannot be instantiated under the runner.
- `test_looping_module_exhausts_fuel`: infinite loop traps on fuel after the configured budget.
**Demo:** `examples/demo_wasm_calculator.py` — runs both implementations, prints `fuel_consumed=4` as evidence the WASM path actually executed (each `i64.add`+`local.get`s consume 4 fuel units).
**Documentation:** `docs/wasm_sandbox.md` — sandbox boundary (no FS/net/env/clock), fuel limit, state isolation, trap-acceptance table, explicit non-claims (no arbitrary-untrusted-code safety, no side-channel resistance, no multi-tenant isolation).
**Benchmark:** `benchmarks/bench_wasm_overhead.py` -> `benchmarks/results/wasm_overhead.csv`:
- python reference: ~0.25 us/call (10K iter)
- wasm-warm (module cached, fresh Store per call): ~113 us/call
- wasm-cold (fresh runner, recompile per call): ~4050 us/call
**Choice:** committed `.wat` (text), not `.wasm` binary. Reviewers can read the module by hand. wasmtime compiles WAT at load time; the trade is one compile per process for full reviewer transparency.
**Claim made:** WASM isolation for the tested calculator module, infinite-loop fixture, and WASI-import-attempt fixture under the documented runner configuration.
**Claim NOT made:** arbitrary untrusted code safety, side-channel resistance, multi-tenant isolation, wall-clock timeout.

## Phase 3 integration — 2026-05-08

**Integration demo:** `examples/demo_secure_quic_wasm_did_flow.py` — `WASM calculator executed: OK` line flipped.
**Tests:** all 115 tests pass (27 v0.1 + 36 Phase 1 + 39 Phase 2 + 13 Phase 3).

## QUIC transport — 2026-05-08

**Code:** `sifr/transport/quic.py` (`QuicTransport` over aioquic 1.3 with single-stream length-prefixed JSON framing, ALPN `sifr/0.2`, exposes `quic_connection` for trap-acceptance), `sifr/transport/_certs.py` (test-only RSA-2048 self-signed cert generator).
**Tests:** `tests/test_quic_transport.py` — 5 tests: handshake-and-bidirectional-roundtrip, **uses-real-aioquic** (asserts `isinstance(quic_connection, aioquic.quic.connection.QuicConnection)` AND `negotiated_alpn == "sifr/0.2"` AND `original_destination_connection_id` non-empty -- the trap-acceptance check that this is real QUIC, not a TCP look-alike), multiple-messages, bad-CA-rejected, peer-disconnect-recv-raises.
**Demo:** `examples/demo_quic_two_agents.py` — minimal QUIC echo with signed messages.
**Claim made:** real QUIC traffic (aioquic-validated, ALPN-negotiated, version 1) on loopback for tests and demos.
**Claim NOT made:** production-grade certificate handling, IP-level packet capture verification, multi-stream load tests.

## Network adversary evaluation — 2026-05-08

**Code:** `tests/test_network_adversary.py` — 11 controlled attack tests, parameterized by attack class. Each test asserts:
1. The exact rejection error class.
2. `WasmToolRunner.last_invocation_evidence` unchanged after rejection (proves the attack never reached the tool).

The 11 attacks:
| # | Attack | Expected error |
|---|---|---|
| 01 | Tamper signed body | `SignatureError` |
| 02 | Replay old message | `ReplayError` |
| 03 | Use expired grant | `UnauthorizedAction(EXPIRED_CAPABILITY)` |
| 04 | Use revoked grant | `UnauthorizedAction(REVOKED_CAPABILITY)` |
| 05 | Swap `sender_id` | `SignatureError` |
| 06 | Swap `kid` | `SignatureError` |
| 07 | Unauthorized action name | `UnauthorizedAction(UNAUTHORIZED_ACTION)` |
| 08 | Malformed frame | `MessageValidationError` |
| 09 | Drop parent DAG node | `AuditDAGError` |
| 10 | Oversized payload | `UnauthorizedAction(PAYLOAD_BUDGET_EXCEEDED)` |
| 11 | WASM execution without grant | `CapabilityError` |

**Demo:** `examples/demo_adversary_cases.py` — runs the suite and prints PASS/FAIL summary.
**Benchmark:** `benchmarks/bench_adversary_rejection.py` -> `benchmarks/results/adversary_rejection.json`. Reject latency ranges: 2.2 us (no-grant) to 2.4 ms (replay -- includes one legitimate authorize+WASM call).
**Claim made:** controlled adversary evaluation across 11 enumerated attack classes; each rejection is automated and asserted to land at the correct layer with the correct error.
**Claim NOT made:** full penetration test, fuzz testing, formal coverage of the attack surface.

## Integration vertical slice — 2026-05-08

**Code:** `examples/demo_secure_quic_wasm_did_flow.py` — full v0.2 vertical slice. Two agents (Alice client, Bob server) connect over real QUIC with self-signed certs; Bob issues a VC-inspired credential; Alice verifies it; Alice signs an Action; Bob runs replay check, revocation check, authorization, then dispatches the WASM calculator; Bob signs the Observation; both sides build an audit DAG which verifies. The demo prints exactly the spec'd `OK` lines and exits 0.
**Test:** `tests/test_secure_flow.py::test_secure_flow_demo_runs_to_completion` — runs the demo as a subprocess, asserts every required `OK` line is present in stdout AND exit code is 0.
**Output (Phase 4):**
```
=== SIFR v0.2 Secure Flow Demo ===
DID resolution: OK
QUIC session: OK
Hello signature: OK
Capability credential: OK
Replay check: OK
Revocation check: OK
Action authorized: OK
WASM calculator executed: OK
Observation verified: OK
Audit DAG integrity: OK
Formal model artifacts: PENDING
Result: 5
Demo completed successfully (formal model artifacts pending Phase 5).
```
**Benchmark:** `benchmarks/bench_quic_latency.py` -> `benchmarks/results/quic_latency.csv`. Sign+verify+DAG round-trip:
- LocalTransport: ~0.20 ms
- HTTP-JSON serialization baseline: ~0.21 ms
- QUIC (loopback): ~0.94 ms
QUIC is ~5x slower than in-process queues, attributable to handshake amortization, framing, and asyncio scheduling.

## Phase 4 integration — 2026-05-08

**Tests:** all 132 tests pass (27 v0.1 + 36 Phase 1 + 39 Phase 2 + 13 Phase 3 + 5 QUIC + 11 adversary + 1 secure_flow).

## Formal model — 2026-05-09

**Code:** `formal/sifr_capability.tla` — TLA+ model of the SIFR capability lifecycle (states `unissued -> active -> {expired | revoked}`; actions `Issue`, `Expire`, `Revoke`, `Consume`; replay set `(subject, message_id)`; bounded budget `MaxCalls`). 6 invariants checked: `NoOverBudgetConsume`, `NoWrongSubjectConsume`, `NoUnauthorizedActionConsume`, `NoReplayedConsume`, `NoConsumeAfterRevoke`, `NoConsumeAfterExpire`, plus `TypeInvariant`.
**Config:** `formal/MC.cfg` -- bounded constants `Caps={c1,c2}`, `Subs={alice,bob}`, `Acts={add,multiply}`, `Msgs={m1,m2}`, `MaxCalls=2`.
**Run wrappers:** `formal/run_tlc.ps1` and `formal/run_tlc.sh`. Install: `scripts/install_tla.ps1` downloads `tla2tools.jar` to gitignored `formal/tools/`.
**Run output:** `formal/output/tlc_output.txt`. TLC 2026.05.04 with 16 workers explored **276,205 distinct states** at depth 9 in 7s. Result: "Model checking completed. No error has been found." across all 7 invariants.
**Tests:** `tests/test_formal_artifacts.py` -- 5 tests: model-file-exists, MC.cfg-exists, every-expected-invariant-defined-in-model, MC.cfg-lists-invariants (>=6), TLC-output-shows-success-marker (skips with clear instructions if Java + tla2tools.jar absent on host). **Trap-acceptance:** the structural tests fail if invariants are renamed or removed; the freshness test fails if a stale tlc_output.txt is committed.
**Documentation:** `docs/formal_model.md` -- model scope, invariant -> code mapping, TLC install instructions for Windows/Linux/macOS, explicit non-claims (no cryptographic proof, no liveness, no implementation correctness, no real concurrency).
**Integration demo:** `examples/demo_secure_quic_wasm_did_flow.py` -- final line `Formal model artifacts: PRESENT`. **All 11 lines now print OK / PRESENT and the demo exits 0 with "Demo completed successfully."**
**Claim made:** TLC model-checked safety: 276K distinct states verified to satisfy all 7 invariants under the bounded constants in MC.cfg.
**Claim NOT made:** cryptographic proof, liveness verification, implementation/spec equivalence proof, exhaustiveness over unbounded constants, real concurrency analysis.

## Phase 5 (formal model) integration — 2026-05-09

**Tests:** all 137 tests pass (27 v0.1 + 36 Phase 1 + 39 Phase 2 + 13 Phase 3 + 17 Phase 4 + 5 formal).
