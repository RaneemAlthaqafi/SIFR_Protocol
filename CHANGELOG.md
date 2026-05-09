# Changelog

## [0.3.1] — 2026-05-09

### Release hardening
- `pyproject.toml`: explicit `[tool.setuptools.packages.find]` with `include = ["sifr*"]` and explicit excludes for the sibling top-level directories (`tests`, `paper`, `docs`, `formal`, `review`, `benchmarks`, `scripts`, `docker`, `wasm`). Closes the "Multiple top-level packages discovered in a flat-layout" install failure on a clean clone. Project name normalized to `sifr`, version pinned to `0.3.1`.
- `.github/workflows/test.yml`: pytest now runs with `SIFR_TLC_FROZEN=1` so the formal-artifact freshness checks fail-closed in CI.
- `formal/output/{tlc_output.txt,tlc_metadata.json,model_hashes.json}`: re-run TLC against the v0.3 model. 11,601 distinct states at depth 7, no error. Hashes refreshed.
- `paper/main.tex`: abstract, claim-evidence map intro, discussion, and conclusion all consistently report v0.3 numbers (30-case strict adversary suite, 9 invariants / 11,601 states, QUIC evaluated on loopback AND single-host Docker bridge with NetEm impairment). The Implementation Status table separates v0.2 (11 attacks) from v0.3 strict (30 attacks). The v0.2 Security Hardening section retains its historical v0.2 numbers as labeled narrative. Stale "loopback only" / "276,205 states" / "7 invariants" / "11-attack" claims removed from the current-claim text.
- `benchmarks/results/v0.3/manifest.json`: regenerated to point at the v0.3.1 substance commit; `git_describe` no longer marked dirty; SHA-256 hashes for all 8 result files including `quic_network_latency.csv`.
- `review/v0_3_release_manifest.json`: regenerated for v0.3.1; SHA-256 + byte size + file count for both `sifr-v0.3.1-research-artifact.zip` and `sifr-v0.3.1-overleaf-ready.zip`.
- `scripts/build_release_zips.py` parameterised by `SIFR_RELEASE_VERSION` (default `v0.3.1`).
- `scripts/write_benchmark_manifest.py` and `scripts/build_release_zips.py`: `--dirty` removed from `git describe` so manifests reflect a clean tree.
- New `review/v0_3_1_strict_quality_gate.md` with exact reproduction commands and observed outputs (20/20 Yes).

### What did NOT change
- Per the release-hardening scope: no new research features, no new tests, no new figures beyond the regenerated ones, no new claims. Every change is a freshness, packaging, paper-consistency, or release-mechanics fix.

## [0.3.0] — 2026-05-09

### Strict-evidence layer
- `tests/test_v0_3_adversary.py`: 30 enumerated controlled adversary cases (A01-A30) covering payload/sender/receiver/cap-action tampering, credential-layer mutations, key-layer swaps, replay (incl. modified-signature, persistent-restart, stale, future), oversized payload, malformed frame, missing/tampered DAG node, unauthorized tool, WASM filesystem and infinite-loop, QUIC malformed frame / duplicate / revoked-credential, TensorFrame shape-bomb / invalid-dtype / payload-length-mismatch.
- `examples/demo_v0_3_adversary_cases.py` + `benchmarks/bench_v0_3_adversary_rejection.py`.
- `sifr/crypto.py:verify_message`: kid DID prefix must equal `sender_id` when a resolver is in use. Closes the swap-kid-to-valid-but-unauthorized-key attack.

### Hardened formal model
- `formal/sifr_capability.tla`: added `Issuers` and `Kids` state, `RevokeKey` action, two new invariants (`NoConsumeWithWrongIssuer` and `NoConsumeWithRevokedKey`). Total: 9 TLC-checked invariants, 11,601 distinct states verified.
- `formal/output/{tlc_output.txt,tlc_metadata.json,model_hashes.json}`: TLC artifacts.

### QUIC beyond loopback
- `docker/Dockerfile.quic_node`, `docker/compose_quic_netem.yml`, `docker/quic_node.py`: containerised SIFR QUIC nodes with `NET_ADMIN` for `tc qdisc` NetEm.
- `scripts/run_quic_network_bench.sh`: orchestrates loopback baseline, container baseline, +20 ms delay, +1% loss, +5% loss configurations.
- `benchmarks/results/v0.3/quic_network_latency.csv`, `paper/figures/benchmark_quic_network.png`, `docs/quic_network_evaluation.md`.

### Reproducibility
- `benchmarks/results/{v0.1,v0.2,v0.3}/`: versioned result directories.
- `benchmarks/bench_io.py`: shared `versioned_results_dir()` helper.
- `scripts/run_all_benchmarks.sh`, `scripts/write_benchmark_manifest.py`, `scripts/generate_all_figures.py`, `scripts/refresh_formal_metadata.py`, `scripts/build_release_zips.py`.
- `scripts/reproduce_all.{sh,ps1}`: 9-step fail-closed master script.

### Documentation
- `docs/proof_obligations_v0_3.md` — P1-P14 obligation table.
- `review/v0_3_strict_quality_gate.md` — 20-item strict gate.
- `paper/main.tex` — `\section{Claims and Evidence Map (v0.3)}` with 14-row table.

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
