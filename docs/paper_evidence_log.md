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
