# SIFR v0.5 Limitations Status

This is the canonical breakdown of how each v0.4 limitation has changed in
v0.5. Three states:

- **Closed**: the v0.4 limitation no longer applies. SIFR can claim the
  inverse property.
- **Narrowed**: the limitation is reduced. The narrowed claim is what we
  *do* support; the residual non-claim is what we still avoid asserting.
- **Remaining**: the v0.4 non-claim still stands.

No limitation is fully closed in v0.5. Each is narrowed with concrete
implementation, tests, and documentation. The honest claims below are the
ones the paper and README state.

## Summary

| Area | v0.4 status | v0.5 status |
|---|---|---|
| L1 Cryptographic assumptions | Stated as assumptions | **Narrowed** — vectors validated, misuse tests added |
| L2 Credential scope | VC-inspired, no W3C | **Narrowed** — renamed, status list, JSON-LD context shipped (not loaded) |
| L3 Identity scope | did:web + did:sifr, b64 only | **Narrowed** — adds did:key, multibase, JWK |
| L4 Revocation/replay scope | Local verifier only | **Narrowed** — process-shared SQLite/JSONL with signature gate |
| L5 WASM scope | Calculator + 2 fixtures | **Narrowed** — 7 fixtures, memory cap, hardened runner |
| L6 Network scope | Localhost + Docker NetEm (delay/loss) | **Narrowed** — 7 profiles incl. jitter/bandwidth, two-bridge harness |
| L7 Formal scope | TLC bounded + Tamarin symbolic | **Narrowed** — adds Apalache config + runtime trace conformance |

## Per-area detail

### L1 — Cryptographic assumptions

**v0.4 claim.** Ed25519, SHA-256, Argon2id, AES-GCM assumed secure under
standard assumptions; their internal security is not proven.

**v0.5 narrowed claim.** *We do not prove primitive security; we validate
integration against standard vectors and rely on standard cryptographic
assumptions.*

**Closed sub-items.**

- Standard test vectors (RFC 8032, FIPS 180-4, NIST SP 800-38D, RFC 9106)
  now run in CI.
- Misuse resistance is exercised: wrong key, modified message, bad AAD,
  modified ciphertext, modified tag, nonce reuse consequence,
  Argon2id parameter mismatch.

**Remaining.** No machine-checked proof of any primitive's security. SIFR
relies on the cited standards and academic results.

**Code & tests.** `docs/crypto_assumptions.md`,
`tests/test_crypto_vectors.py` (18 tests).

### L2 — Credential scope

**v0.4 claim.** Credentials VC-inspired but not W3C VC compliant.

**v0.5 narrowed claim.** *SIFR Capability Credentials* are signed Ed25519
grants whose JSON body resembles a W3C Verifiable Credential. They are
NOT W3C VC compliant: SIFR does not load JSON-LD contexts and does not
perform URDNA2015. SIFR ships `SIFRStatusList2021`, a bitmap-based
credential-status mechanism modelled on but not interoperable with W3C
StatusList2021.

**Closed sub-items.**

- Primary type renamed to `SIFRCapabilityCredential`; VC-shape kept for
  ergonomic recognition only.
- Bitmap status list signed with Ed25519, signature re-verified on load.
- `credentialStatus` field bound into the credential proof — index
  cannot be swapped after issuance.
- SIFR-local JSON-LD context document shipped at
  `docs/contexts/sifr-credential-v1.jsonld` for offline inspection.

**Remaining.** No JSON-LD context loader, no URDNA2015 normalization, no
W3C `StatusList2021Credential` wire compatibility.

**Code & tests.** `sifr/credential_status.py`, updated `sifr/credentials.py`,
`tests/test_credential_status.py` (8 new tests), existing
`tests/test_credentials.py` still passes (15 tests).

### L3 — Identity scope

**v0.4 claim.** Supports `did:web` and local `did:sifr` with selected
Ed25519 key formats; not the full DID ecosystem.

**v0.5 narrowed claim.** *SIFR supports `did:web`, `did:key`, and local
`did:sifr` for Ed25519 keys encoded as `publicKeyBase64`,
`publicKeyMultibase`, or `publicKeyJwk`.*

**Closed sub-items.**

- `did:key` resolver implemented with canonical-form check
  (`sifr/did/did_key.py`).
- `publicKeyMultibase` parsing with Ed25519 multicodec validation
  (`sifr/did/encodings.py`).
- `publicKeyJwk` parsing with `OKP` / `Ed25519` / 32-byte `x` validation.
- Type/format binding rules enforced (e.g., `JsonWebKey2020` ↔ JWK only).
- Multi-format double-key entries rejected at parse time.

**Remaining.** Other curves (X25519, secp256k1, P-256). Other DID methods
(`did:ion`, `did:ethr`, `did:peer`, …).

**Code & tests.** `sifr/did/encodings.py`, `sifr/did/did_key.py`, updated
`sifr/did/__init__.py`, updated `docs/did_method.md`,
`tests/test_did_key_formats.py` (21 new tests), existing
`tests/test_did_resolution.py` still passes (22 tests).

### L4 — Revocation and replay scope

**v0.4 claim.** Revocation and replay protection local to the configured
verifier state.

**v0.5 narrowed claim.** *SIFR supports process-shared replay and
revocation through a durable SQLite-WAL backed verifier state and a
signed-JSONL revocation log re-verified at load time. SIFR does not
implement Byzantine consensus or global revocation propagation between
independent verifier deployments.*

**Closed sub-items.**

- Replay cache opens SQLite in WAL mode with a 5 s busy-timeout; the
  `PRIMARY KEY(sender, session, msgid)` constraint serialises concurrent
  writers across processes.
- Replay records persist across restart (existing instance + new
  instance share the same store).
- Cross-process race: 4-process concurrent test asserts exactly one
  ACCEPT.
- `RevocationRegistry.reload()` re-reads the JSONL into the in-memory
  map; signatures re-checked.
- Tampered log line is rejected at load time.
- Wrong-type entry in the log is rejected at load time.

**Remaining.** No Byzantine consensus. No total ordering across
deployments. No multicast / sync-protocol between hosts.

**Code & tests.** `sifr/replay.py` (WAL+busy-timeout),
`sifr/revocation.py` (`reload()`),
`tests/test_distributed_replay.py` (4 tests),
`tests/test_distributed_revocation.py` (4 tests),
`docs/revocation_replay_scope.md`.

### L5 — WASM scope

**v0.4 claim.** WASM evidence covers a calculator module and adversarial
fixtures. Does not establish arbitrary untrusted-code safety.

**v0.5 narrowed claim.** *SIFR enforces a no-WASI, fuel-bounded,
fresh-store, memory-capped WASM policy tested against the calculator
module and a documented set of adversarial fixtures (filesystem,
environment, socket, infinite loop, memory-grow abuse, missing-export,
unreachable trap).*

**Closed sub-items.**

- Memory cap via `Store.set_limits(memory_size=...)`; default 16 pages
  (1 MiB).
- New fixtures: `env_attempt.wat`, `network_attempt.wat`,
  `memory_grow_abuse.wat`, `trap_unreachable.wat`, `missing_export.wat`.
- Bool args explicitly rejected (Python's `bool` is a subtype of `int`,
  so without this gate one could sneak `True`/`False` past type checks).
- Calculator parity, fuel-consumed evidence, state isolation across
  calls — all reasserted with the hardened store.

**Remaining.** No arbitrary-untrusted-code-safety claim. No side-channel
resistance. No multi-tenant isolation.

**Code & tests.** `sifr/wasm_runner.py` (memory cap +
`_new_store()` helper), 5 new WAT fixtures,
`tests/test_wasm_sandbox_hardening.py` (18 new tests), existing
`tests/test_wasm_runner.py` still passes (11 tests).

### L6 — Network scope

**v0.4 claim.** QUIC evaluated on localhost and a single-host Docker
bridge with NetEm impairment.

**v0.5 narrowed claim.** *SIFR is evaluated under single-host emulated
network impairment with a two-bridge Docker harness. Internet-scale,
multi-host, NAT-traversal, and mobile-network evaluation are out of
scope.*

**Closed sub-items.**

- Two-bridge Compose file: client and server live on disjoint bridges
  joined by a trunk bridge; impairment applied on the trunk-facing
  interface (`docker/compose_quic_two_networks.yml`).
- NetEm wrapper extended with jitter and TBF bandwidth profiles
  (`docker/quic_runner.py`).
- Driver script sweeps 7 profiles (baseline, delay20, delay100, loss1,
  loss5, jitter, bandwidth-10Mbit) and aggregates results
  (`benchmarks/bench_quic_network.py`).
- Documentation explicitly states this is NOT in CI because public
  runners typically lack `NET_ADMIN`.

**Remaining.** No two-machine or WAN run executed inside this artifact.
No public-cloud VM evaluation. The harness ships; the operator runs it.

**Code & docs.** `docker/compose_quic_two_networks.yml`, updated
`docker/quic_runner.py`, `benchmarks/bench_quic_network.py`,
updated `docs/quic_network_evaluation.md`.

### L7 — Formal scope

**v0.4 claim.** TLA+ checking is bounded; Tamarin abstracts crypto and
includes a replay-cache restriction; no Coq/TLAPS refinement proof.

**v0.5 narrowed claim.** *Every TLA+ invariant is bounded-proven by TLC
and trace-checked over realistic Python executions of the SIFR
implementation. SIFR ships an Apalache configuration for
operator-runnable symbolic bounded checking, but does not claim an
Apalache proof until a successful run log is committed. SIFR does not
have an implementation-refinement proof.*

**Closed sub-items.**

- `formal/apalache.cfg` shipped for symbolic re-checking by Apalache-equipped
  reviewers.
- `sifr/trace_conformance.py` provides a Python translation of every
  TLA+ invariant.
- `tests/test_formal_trace_conformance.py` runs three real-flow positive
  traces (issue→consume; revoke-then-blocked; replay-blocked) plus nine
  hand-crafted counterexample traces — proves the checker is sensitive,
  not vacuously satisfied.
- `docs/formal_scope.md` defines the verb vocabulary
  (`bounded-proven`, `symbolic-checkable`, `inductively-proven`,
  `trace-checked`) so paper claims map to verifiable evidence.
- `docs/model_code_traceability_v0_4.md` references the v0.5 trace
  bridge.

**Remaining.** No TLAPS/Coq inductive proof. No machine-checked
simulation relation from Python state to TLA+ state. No quantified bound
on the gap between trace coverage and full implementation behavior.

**Code & tests.** `sifr/trace_conformance.py`,
`tests/test_formal_trace_conformance.py` (12 tests),
`formal/apalache.cfg`, `docs/formal_scope.md`.

## Final v0.5 honest claim set (paper-ready)

1. *We do not prove primitive security; we validate integration against
   standard vectors and rely on standard cryptographic assumptions.*

2. *SIFR Capability Credentials resemble W3C VC shape but are not W3C VC
   compliant; SIFR ships `SIFRStatusList2021` modelled on but not
   interoperable with W3C StatusList2021.*

3. *SIFR supports `did:web`, `did:key`, and local `did:sifr` for Ed25519
   keys in `publicKeyBase64`, `publicKeyMultibase`, or `publicKeyJwk`.*

4. *SIFR supports process-shared replay and revocation through a durable
   SQLite-WAL verifier state, but does not implement Byzantine consensus
   or global revocation propagation.*

5. *SIFR enforces a no-WASI, fuel-bounded, memory-capped, fresh-store
   WASM policy tested against calculator and adversarial fixtures.*

6. *SIFR is evaluated under single-host emulated network impairment, not
   Internet-scale deployment.*

7. *Every TLA+ invariant is bounded-proven by TLC and trace-checked over
   Python executions. SIFR ships an Apalache configuration for
   operator-runnable symbolic bounded checking, but does not claim an
   Apalache proof until a successful run log is committed. There is no
   implementation-refinement proof.*
