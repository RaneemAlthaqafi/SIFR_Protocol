# SIFR v0.3 Proof Obligations

A claim is **proven** only if every applicable evidence row is filled and reproducible from a clean checkout via `scripts/reproduce_all.sh`. A claim that is missing any required evidence is not proven; it is **partially proven**, **implemented**, or **future work**.

Status legend:
- **proven** — code + positive tests + negative/adversarial tests + benchmark (if performance-related) + formal artifact (if state-machine-related) + paper text + reproduction script.
- **partial** — most evidence present, at least one required column is incomplete or out of scope.
- **implemented** — code and tests but missing benchmark, formal artifact, or paper.
- **future** — not in v0.3.

---

## P1 Signed canonical frames

| Field | Value |
|---|---|
| Claim | Every SIFR message is canonicalized (sorted-keys JSON, signature stripped) and signed with Ed25519; verification fails on any mutation of the signed bytes or sender_id/kid binding. |
| Implementation files | `sifr/canonical.py`, `sifr/crypto.py` (`message_to_canonical_bytes`, `sign_message`, `verify_message`) |
| Positive tests | `tests/test_crypto.py`, `tests/test_messages.py` |
| Negative tests | `tests/test_v0_3_adversary.py::test_a01_tamper_payload`, `::test_a02_tamper_sender`, `::test_a03_tamper_receiver`, `::test_a04_tamper_capability_action`, `::test_a08_swap_kid_to_valid_unauthorized_key` |
| Benchmarks | `benchmarks/results/v0.3/signature_overhead.csv` |
| Formal artifact | n/a (state machine abstracts away wire bytes) |
| Raw evidence files | `benchmarks/results/v0.3/signature_overhead.csv` |
| Paper locations | abstract; §III Architecture; §V Canonicalization and Signatures |
| Reproduction command | `bash scripts/reproduce_all.sh` |
| Proof status | **proven** |
| Residual limitations | none |

## P2 Capability authorization

| Field | Value |
|---|---|
| Claim | `authorize_action` rejects every action that fails any of: signature verify, replay check, revocation check, capability_id match, subject match, action membership, expiration, payload-size budget, call-count budget, delegation policy. |
| Implementation files | `sifr/capabilities.py` (`authorize_action`, `verify_capability_grant`, `CapabilityStore`) |
| Positive tests | `tests/test_capabilities.py` |
| Negative tests | A01–A04, A07–A09, A12, A18, A22 in `tests/test_v0_3_adversary.py`; the original 11 in `tests/test_network_adversary.py` |
| Benchmarks | `benchmarks/results/v0.3/adversary_rejection.json`, `benchmarks/results/v0.3/revocation_overhead.csv`, `benchmarks/results/v0.3/replay_overhead.csv` |
| Formal artifact | TLA+ invariants I1, I2, I3, I4, I5, I8 (`formal/output/tlc_output.txt`); 11 601 distinct states verified |
| Raw evidence files | as above + `formal/output/tlc_output.txt` |
| Paper locations | abstract; §VI v0.2 Security Hardening; Table tab:invariants; Table tab:adversary |
| Reproduction command | `bash scripts/reproduce_all.sh` |
| Proof status | **proven** |
| Residual limitations | budget tracking is per-process |

## P3 Capability credential verification

| Field | Value |
|---|---|
| Claim | VC-inspired credentials with `Ed25519Signature2020`-shaped proof reject every byte-level mutation, every issuer/verificationMethod inconsistency, and every date-validity violation. **No W3C VC compliance is claimed.** |
| Implementation files | `sifr/credentials.py` |
| Positive tests | `tests/test_credentials.py` (15 tests) |
| Negative tests | A05, A06, A07, A10, A11 in `tests/test_v0_3_adversary.py` |
| Benchmarks | `benchmarks/results/v0.3/credential_verification.csv` |
| Formal artifact | none (cryptographic, not state-machine) |
| Raw evidence files | benchmark CSV; `docs/credential_model.md` |
| Paper locations | §VI.C Capability Credentials; Limitations §IX |
| Reproduction command | `bash scripts/reproduce_all.sh` |
| Proof status | **partial** — proven as VC-inspired; W3C VC compliance is explicitly NOT claimed and NOT tested. |
| Residual limitations | no JSON-LD context processing, no URDNA2015 RDF normalization, no StatusList2021, no external W3C VC interop test |

## P4 Capability revocation

| Field | Value |
|---|---|
| Claim | `RevocationRegistry` produces signed `CapabilityRevocation` SIFR messages, persists them as JSONL, re-verifies signatures on load, and `authorize_action` raises `UnauthorizedAction("REVOKED_CAPABILITY")` for any revoked grant. |
| Implementation files | `sifr/revocation.py`, `sifr/capabilities.py:authorize_action` |
| Positive tests | `tests/test_revocation.py` (12 tests) |
| Negative tests | A12 in `tests/test_v0_3_adversary.py`; `test_persistence_tampered_record_rejected`; `test_load_without_verifier_fails` |
| Benchmarks | `benchmarks/results/v0.3/revocation_overhead.csv` |
| Formal artifact | TLA+ invariant I4 (`NoConsumeAfterRevoke`) |
| Raw evidence files | as above |
| Paper locations | §VI.C; Table tab:invariants |
| Reproduction command | `bash scripts/reproduce_all.sh` |
| Proof status | **proven** for single-process / single-registry semantics |
| Residual limitations | no distributed propagation (gossip / consensus); registry is per-process |

## P5 Replay protection

| Field | Value |
|---|---|
| Claim | The `ReplayCache` rejects duplicate `(sender_id, session_id, message_id)` triples within a sliding timestamp window; the cache key does NOT include the signature, so re-signing the same message is still rejected. |
| Implementation files | `sifr/replay.py` |
| Positive tests | `tests/test_replay.py` (12 tests) |
| Negative tests | A13–A17 in `tests/test_v0_3_adversary.py` |
| Benchmarks | `benchmarks/results/v0.3/replay_overhead.csv` |
| Formal artifact | TLA+ invariant I6 (`NoReplayedConsume`) |
| Raw evidence files | as above |
| Paper locations | §VI.D Replay Protection |
| Reproduction command | `bash scripts/reproduce_all.sh` |
| Proof status | **proven** |
| Residual limitations | per-process cache; cross-process replay protection requires sharing the SQLite path; O(n) GC per check |

## P6 DID resolution and key binding

| Field | Value |
|---|---|
| Claim | `did:web` and `did:sifr` resolvers extract a `verificationMethod` keyed by `kid`, validate `controller == DID`, and reject every documented mismatched/malformed/path-traversal/unknown-method case. The kid's DID prefix must equal the message's `sender_id` (added in v0.3 — closes the `swap-kid-to-valid-key` attack). |
| Implementation files | `sifr/did/__init__.py`, `sifr/did/did_web.py`, `sifr/did/did_sifr.py`, `sifr/crypto.py:verify_message` (kid-DID/sender-id binding) |
| Positive tests | `tests/test_did_resolution.py` (22 tests) |
| Negative tests | A08, A09 in `tests/test_v0_3_adversary.py`; numerous reject paths in `test_did_resolution.py` |
| Benchmarks | `benchmarks/results/v0.3/did_resolution.csv` |
| Formal artifact | n/a (DID resolution is bytes/I-O, not state-machine) |
| Raw evidence files | as above |
| Paper locations | §VI.B DID and Key Resolution |
| Reproduction command | `bash scripts/reproduce_all.sh` |
| Proof status | **partial** — proven for did:web + did:sifr with `Ed25519VerificationKey2020`/`2018` and `publicKeyBase64`. **`publicKeyMultibase` and `publicKeyJwk` are NOT supported in v0.3 despite the v0.3 spec asking for at least one of those formats.** |
| Residual limitations | no `publicKeyMultibase`/`publicKeyJwk`, no `did:key`/`did:ion`/etc., no JSON-LD context handling; did:web tests run only against in-process loopback HTTP fixture |

## P7 QUIC transport

| Field | Value |
|---|---|
| Claim | A real `aioquic.QuicConnection` carries length-prefixed canonical-JSON frames over an ALPN-negotiated `sifr/0.2` stream; trap-acceptance tests rule out a TCP look-alike. |
| Implementation files | `sifr/transport/quic.py`, `sifr/transport/_certs.py` |
| Positive tests | `tests/test_quic_transport.py` (5 tests) |
| Negative tests | A25 (malformed frame), A26 (duplicate over QUIC), A27 (revoked over QUIC) in `tests/test_v0_3_adversary.py` |
| Benchmarks | `benchmarks/results/v0.3/quic_latency.csv` (loopback) |
| Formal artifact | n/a |
| Raw evidence files | as above |
| Paper locations | §VI.E QUIC Transport |
| Reproduction command | `bash scripts/reproduce_all.sh` |
| Proof status | **partial** — proven on `127.0.0.1` loopback with self-signed RSA-2048 certificates. |
| Residual limitations | **No beyond-loopback evaluation in v0.3.** Docker was available locally during this session but a Docker-Compose+NetEm impairment test was not built in time. No real-network, NAT, packet-loss, jitter, or two-host run. This is the largest gap in v0.3. |

## P8 WASM tool isolation

| Field | Value |
|---|---|
| Claim | Tool execution runs inside `wasmtime` with no WASI imports linked, in a fresh `Store` per call, with a fixed fuel budget. The committed calculator module has zero imports; an adversarial module that imports `wasi_snapshot_preview1.path_open` fails to instantiate. |
| Implementation files | `sifr/wasm_runner.py`, `wasm/calculator/calculator.wat`, `tests/fixtures/wasm_modules/{looping,fs_attempt}.wat` |
| Positive tests | `tests/test_wasm_runner.py` (13 tests including parity, evidence-counter advance, no-WASI-imports-on-calculator) |
| Negative tests | A23 (FS), A24 (infinite-loop fuel exhaustion) in `tests/test_v0_3_adversary.py` |
| Benchmarks | `benchmarks/results/v0.3/wasm_overhead.csv` |
| Formal artifact | n/a (sandboxing is host-runtime, not state-machine) |
| Raw evidence files | as above |
| Paper locations | §VI.F WASM Tool Isolation |
| Reproduction command | `bash scripts/reproduce_all.sh` |
| Proof status | **partial** — proven for the calculator and the two adversarial fixtures. |
| Residual limitations | The v0.3 spec also asked for explicit `network import fails`, `environment import fails`, and `memory growth abuse bounded` fixtures. The runner's *no-imports* policy structurally rejects the first two, but separate adversarial fixtures were not added in v0.3. Memory-growth abuse is bounded only indirectly via fuel; no explicit memory-grow fixture. |

## P9 Audit DAG integrity

| Field | Value |
|---|---|
| Claim | Each accepted message is content-addressed by `sha256` over canonical bytes; node mutation, dropped parents, and CID/body inconsistency are detected by `verify_dag_integrity()`. |
| Implementation files | `sifr/audit_dag.py` |
| Positive tests | `tests/test_audit_dag.py` (5 tests) |
| Negative tests | A20 (drop parent), A21 (tampered DAG node) in `tests/test_v0_3_adversary.py` |
| Benchmarks | n/a |
| Formal artifact | I10 (`AuditTamperDetected`) **implementation-tested only** — not modeled in TLA+ |
| Raw evidence files | n/a |
| Paper locations | §III Audit DAG |
| Reproduction command | `bash scripts/reproduce_all.sh` |
| Proof status | **proven** at the implementation level |
| Residual limitations | no formal model of the DAG; integrity is on local stored bytes only |

## P10 Controlled adversary rejection

| Field | Value |
|---|---|
| Claim | 30 enumerated adversary cases each raise the expected error class without reaching the WASM tool runner. |
| Implementation files | `tests/test_v0_3_adversary.py`, `benchmarks/bench_v0_3_adversary_rejection.py`, `examples/demo_v0_3_adversary_cases.py` |
| Positive tests | n/a (this claim *is* about the negative tests) |
| Negative tests | 30 cases A01–A30 in `tests/test_v0_3_adversary.py` |
| Benchmarks | `benchmarks/results/v0.3/adversary_rejection.json` (per-attack reject latency) |
| Formal artifact | each authorization-layer attack maps to a TLA+ invariant; cryptographic and DAG attacks map to implementation-only invariants (I7, I10) |
| Raw evidence files | as above |
| Paper locations | §VI.G Network Adversary Evaluation; Table tab:adversary |
| Reproduction command | `bash scripts/reproduce_all.sh` |
| Proof status | **proven** (30/30 attacks rejected) |
| Residual limitations | not a fuzz test, penetration test, or symbolic-execution survey |

## P11 Formal authorization model

| Field | Value |
|---|---|
| Claim | TLA+ model of the capability lifecycle, model-checked with TLC across 11 601 distinct states under 9 invariants. **Bounded safety, not a cryptographic proof.** |
| Implementation files | `formal/sifr_capability.tla`, `formal/MC.cfg`, `formal/run_tlc.{ps1,sh}`, `scripts/install_tla.ps1`, `scripts/refresh_formal_metadata.py` |
| Positive tests | `tests/test_formal_artifacts.py` (8 tests, fail-closed via `SIFR_TLC_FROZEN=1`) |
| Negative tests | adding an invariant to MC.cfg and not re-running TLC fails `test_mc_config_lists_all_expected_invariants`; tampering with the model file fails `test_model_hashes_match_files` |
| Benchmarks | n/a |
| Formal artifact | `formal/output/tlc_output.txt`, `formal/output/tlc_metadata.json`, `formal/output/model_hashes.json` |
| Raw evidence files | as above |
| Paper locations | §VI.H Formal Model |
| Reproduction command | `bash scripts/reproduce_all.sh` |
| Proof status | **proven** for bounded safety |
| Residual limitations | I7 (TamperedCredentialNeverAllowed) and I10 (AuditTamperDetected) are implementation-tested only; no liveness, no cryptographic abstraction, no implementation-refinement proof |

## P12 End-to-end secure flow

| Field | Value |
|---|---|
| Claim | The integration vertical slice runs end-to-end over real QUIC and exits 0 with the spec's expected output. |
| Implementation files | `examples/demo_secure_quic_wasm_did_flow.py` |
| Positive tests | `tests/test_secure_flow.py` (subprocess-launches the demo) |
| Negative tests | covered by P10 |
| Benchmarks | n/a |
| Formal artifact | covered by P11 |
| Raw evidence files | demo stdout |
| Paper locations | §VI.I End-to-End Vertical Slice |
| Reproduction command | `bash scripts/reproduce_all.sh` |
| Proof status | **proven** on loopback |
| Residual limitations | single-process; no two-host run |

## P13 Reproducible benchmark pipeline

| Field | Value |
|---|---|
| Claim | Every benchmark writes into versioned `benchmarks/results/<version>/`. A manifest captures git commit, timestamp, OS, Python, dependency versions, bench-script hashes, and result-file hashes. |
| Implementation files | `benchmarks/bench_io.py`, `scripts/run_all_benchmarks.sh`, `scripts/write_benchmark_manifest.py` |
| Positive tests | n/a (workflow) |
| Negative tests | `scripts/reproduce_all.sh` step 8 fails closed if any required result file is missing |
| Benchmarks | `benchmarks/results/v0.3/manifest.json` |
| Formal artifact | n/a |
| Raw evidence files | manifest |
| Paper locations | Reproducibility Statement |
| Reproduction command | `bash scripts/run_all_benchmarks.sh` (with `SIFR_BENCH_VERSION=v0.3`) |
| Proof status | **proven** |
| Residual limitations | none |

## P14 Reproducible paper / figure pipeline

| Field | Value |
|---|---|
| Claim | Every figure in `paper/figures/` is regenerated from versioned raw data by `scripts/generate_all_figures.py`, and `paper/figures/figure_manifest.json` records source + output hashes. |
| Implementation files | `scripts/generate_all_figures.py`, `scripts/generate_v0_2_figures.py`, `scripts/generate_v0_3_adversary_figure.py`, `scripts/generate_ieee_figure.py` |
| Positive tests | n/a (workflow) |
| Negative tests | `scripts/reproduce_all.sh` step 8 fails closed if a required figure is missing |
| Benchmarks | n/a |
| Formal artifact | n/a |
| Raw evidence files | `paper/figures/figure_manifest.json` |
| Paper locations | Reproducibility Statement |
| Reproduction command | `python scripts/generate_all_figures.py` |
| Proof status | **proven** |
| Residual limitations | the legacy v0.1 `scripts/generate_figures.py` still exists and would overwrite some shared filenames if run separately; the master `generate_all_figures.py` does not invoke it. |

---

## Summary

| Status | Count | Claims |
|---|---|---|
| proven | 9 | P1, P2, P4, P5, P9, P10, P11, P12, P13, P14 |
| partial | 4 | P3 (VC-inspired), P6 (no multibase/JWK), P7 (loopback only), P8 (no network/env/memgrow fixtures) |
| future | 0 | — |

The artifact carries strong evidence for everything it implements. The four `partial` rows are honest scope boundaries; none is silently overclaimed in the paper.

The largest single residual gap is **P7 (QUIC beyond loopback)** — Docker became available during the session but a Docker-Compose+NetEm test was not built in time. This is the highest-priority follow-up item.
