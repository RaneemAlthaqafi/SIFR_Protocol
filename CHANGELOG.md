# Changelog

## [0.2.0] — 2026-05-09

### Identity (Phase 1)
- `sifr/key_management.py`: `EncryptedFileKeyStore` with Argon2id KDF + AES-256-GCM, kid bound as AAD, multi-key per agent, rotation, revocation metadata, atomic write-then-rename.
- `sifr/did/`: `DidResolver` ABC, `DidWebResolver` (W3C did:web spec, percent-encoded port handling), `DidSifrResolver` (local-only with path-traversal protection), `MultiMethodResolver` dispatch.
- `sifr/capabilities.py`: `verify_capability_grant` and `authorize_action` accept `Union[Ed25519PublicKey, KeyResolver]`. Direct-key callers unchanged.

### Authorization Hardening (Phase 2)
- `sifr/replay.py`: `ReplayCache` keyed on `(sender_id, session_id, message_id)` with sliding window (default 5 minutes), optional SQLite persistence with on-load restore.
- `sifr/revocation.py`: `RevocationRegistry` produces signed `CapabilityRevocation` SIFR messages, persists as JSONL, re-verifies signatures on load.
- `sifr/credentials.py`: VC-inspired (NOT W3C VC compliant) credential issuance and verification with `Ed25519Signature2020` proof, full mutation defenses, expiration check, issuer-DID/verificationMethod-DID consistency.
- `sifr/capabilities.py:authorize_action`: new kwargs `revocation_registry`, `replay_cache`. Order: signature verify → replay check → revocation check → existing checks.
- `sifr/errors.py`: `RevocationError`, `ReplayError`, `CredentialError`.
- `sifr/messages.py`: `CapabilityRevocation` message type.

### Sandboxed Execution (Phase 3)
- `sifr/wasm_runner.py`: `WasmToolRunner` over wasmtime 44 with no WASI imports linked, fuel-bounded (default 1M), fresh `Store` per call, `last_invocation_evidence` for trap-acceptance. `PythonCalculatorReference` retained as parity reference. Backwards-compat alias `CalculatorTool`.
- `wasm/calculator/calculator.wat`: 13-line text module, zero imports. Reviewer-readable; no opaque .wasm binary in git.
- `tests/fixtures/wasm_modules/`: `looping.wat` (fuel adversary), `fs_attempt.wat` (WASI-import adversary).

### Transport, Adversary, Integration (Phase 4)
- `sifr/transport/quic.py`: `QuicTransport` over aioquic 1.3 with single-stream length-prefixed JSON framing, ALPN `sifr/0.2`, exposes `aioquic.quic.connection.QuicConnection` for trap-acceptance.
- `sifr/transport/_certs.py`: RSA-2048 self-signed cert generator (test/demo only).
- `tests/test_network_adversary.py`: 11 controlled attack tests, each asserting exact error class AND that `WasmToolRunner.last_invocation_evidence` is unchanged after rejection.
- `examples/demo_secure_quic_wasm_did_flow.py`: full vertical slice over real QUIC. Two agents, DID-resolved keys, VC-inspired credential, replay+revocation+authorization+WASM+observation+DAG. Exits 0 with the spec's verbatim expected output.
- `tests/test_secure_flow.py`: subprocess-launches the demo; asserts each required `OK` line and exit 0.

### Formal Model & Paper (Phase 5)
- `formal/sifr_capability.tla` + `formal/MC.cfg`: TLA+ model of capability lifecycle. Seven invariants checked by TLC: `TypeInvariant`, `NoOverBudgetConsume`, `NoWrongSubjectConsume`, `NoUnauthorizedActionConsume`, `NoReplayedConsume`, `NoConsumeAfterRevoke`, `NoConsumeAfterExpire`.
- `formal/output/tlc_output.txt`: TLC explored 276,205 distinct states at depth 9 in 7 seconds. "Model checking completed. No error has been found."
- `formal/run_tlc.{ps1,sh}`, `scripts/install_tla.ps1`: install + run wrappers.
- `tests/test_formal_artifacts.py`: 5 tests; freshness check skips with clear instructions when no Java/TLC available locally.
- `paper/main.tex`: new abstract distinguishing v0.1 from v0.2; new `\section{v0.2 Security Hardening}` with subsections per feature; new tables (adversary rejection latencies, invariant-to-code mapping, expanded implementation status); updated Limitations / Future Work / Conclusion / Reproducibility.
- `paper/references.bib`: aioquic, wasmtime, did:web spec, Argon2, TLA+, TLC.

### Pre-phase refactor
- `sifr/canonical.py`: extracted canonicalization helpers; re-exported from `sifr.crypto` for back-compat.
- `sifr/keyring_iface.py`: `KeyResolver` Protocol, `RevocationInfo`.
- `sifr/transport/`: package split (`_base.py`, `local.py`); `QuicTransport` added later in Phase 4.
- New base deps: `argon2-cffi`, `httpx`, `aioquic`, `wasmtime`. Optional groups: `keyring`, `formal-tools`, `dev`.
- `.github/workflows/test.yml`: pytest on Ubuntu + Windows × Python 3.11, 3.12.

### Test totals
- v0.1: 27 tests.
- v0.2: 137 tests (27 v0.1 + 14 keys + 22 DID + 12 replay + 12 revocation + 15 credentials + 13 WASM + 5 QUIC + 11 adversary + 1 secure_flow + 5 formal artifacts).
- All 137 tests pass on Python 3.14.2 / Windows 11.

## [0.1.0] — feasibility prototype
- Signed typed frames (Ed25519), capability grants with budgets, content-addressed audit DAG.
- Two-agent vertical slice over `LocalTransport`.
- 27 tests, 5 benchmarks, IEEE-style paper.
