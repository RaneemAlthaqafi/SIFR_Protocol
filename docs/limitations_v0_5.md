# SIFR v0.5 Limitations Status

This is the canonical breakdown of how each v0.4 limitation changed in v0.5.
No limitation is fully closed. Each area is narrowed with concrete code,
tests, documentation, or operator-runnable harnesses, and the residual
non-claim remains explicit.

## Summary

| Area | v0.4 status | v0.5 status |
|---|---|---|
| L1 Cryptographic assumptions | Stated as assumptions | Narrowed: vectors and misuse tests |
| L2 Credential scope | VC-inspired, no W3C compliance | Narrowed: SIFR credential type, signed status list |
| L3 Identity scope | did:web + did:sifr, base64 only | Narrowed: did:key, multibase, JWK, relationship checks |
| L4 Revocation/replay scope | Local verifier only | Narrowed: process-shared SQLite/JSONL state |
| L5 WASM scope | Calculator + limited fixtures | Narrowed: no-WASI, fuel, memory, seven fixtures |
| L6 Network scope | Localhost + v0.3 Docker NetEm | Narrowed: measured v0.3, operator-runnable v0.5 harness |
| L7 Formal scope | TLC bounded + Tamarin symbolic | Narrowed: Apalache config + trace invariant checks |
| L8 Production security | Research prototype config | Narrowed: fail-closed config for documented threat model |

## L1 - Cryptographic Assumptions

**Narrowed claim.** SIFR validates cryptographic integration against standard
vectors and misuse tests. It does not prove primitive security.

**Evidence.**

- RFC 8032 Ed25519 TEST 1, TEST 2, and TEST 3.
- FIPS 180-4 SHA-256 short vectors and 1-million-`a` vector.
- NIST SP 800-38D AES-GCM Test Case 1 and Test Case 3.
- RFC 9106 Argon2id reference-style parameter checks. The exact RFC A.3
  secret/ad KAT is not feasible through the current Python binding.
- Misuse tests for wrong Ed25519 key, modified message, AES-GCM wrong key,
  wrong AAD, modified ciphertext, modified tag, nonce-reuse consequence, and
  Argon2 parameter tampering in the keyring.

**Remaining.** Ed25519, SHA-256, AES-GCM, and Argon2id security are assumed
from their standards and libraries.

## L2 - Credential Scope

**Narrowed claim.** SIFR Capability Credentials are VC-shaped, SIFR-native
signed grants. They are not W3C VC compliant.

**Evidence.**

- Primary type `SIFRCapabilityCredential`.
- `credentialStatus` is bound into the signed credential.
- Proof metadata is signed with `proofValue` omitted, so proof metadata
  mutation is rejected.
- `SIFRStatusList2021` is Ed25519-signed and re-verified on load.
- Local JSON-LD context document is shipped for inspection.

**Remaining.** No JSON-LD loader, no URDNA2015, no W3C Data Integrity
interop, no W3C StatusList2021 or Bitstring Status List wire compatibility,
and no external VC verifier interop.

## L3 - Identity Scope

**Narrowed claim.** SIFR supports the documented DID profile:
`did:web`, `did:key`, and local `did:sifr` for Ed25519 keys encoded as
`publicKeyBase64`, `publicKeyMultibase`, or `publicKeyJwk`, with documented
relationship checks for `authentication`, `assertionMethod`,
`capabilityInvocation`, and `capabilityDelegation`.

**Evidence.**

- `did:key` canonical Ed25519 multicodec resolver.
- Multibase Ed25519 validation.
- JWK `OKP` / `Ed25519` / 32-byte `x` validation, with padded `x` rejected.
- Type/format binding rules and multi-format rejection.
- `resolve_for(kid, relationship)` enforces documented relationships.

**Remaining.** No full DID Core compliance, no JSON-LD processing, no
non-Ed25519 curves, and no methods beyond `did:web`, `did:key`, and
`did:sifr`.

## L4 - Revocation and Replay Scope

**Narrowed claim.** SIFR supports process-shared replay and revocation through
durable SQLite-WAL verifier state and signed JSONL revocation logs.

**Evidence.**

- Replay cache uses WAL, busy timeout, and
  `PRIMARY KEY(sender, session, msgid)`.
- Cross-process and restart replay tests pass.
- Four-process same-message race accepts exactly one message.
- Revocation log reload verifies signatures and rejects tampered or wrong-type
  records.

**Remaining.** No Byzantine consensus, no global revocation propagation, no
multi-writer revocation-log locking, and replay database rows are durable
state rather than cryptographically signed rows.

## L5 - WASM Scope

**Narrowed claim.** SIFR enforces a no-WASI, fuel-bounded, memory-capped,
fresh-store WASM policy tested against the calculator and adversarial fixtures.

**Evidence.**

- No WASI imports are linked.
- Fresh `Store` per call.
- Fuel limits and fuel-exhaustion tests.
- Memory cap through `Store.set_limits` when supported by wasmtime-py.
- Bool arguments rejected.
- Fixtures cover filesystem, environment, socket/network import, infinite
  loop, memory growth abuse, missing export, and unreachable trap.

**Remaining.** Memory cap is best effort on wasmtime builds without
`Store.set_limits`. Structured invocation evidence is last-call, success-only,
and not durable audit provenance. No arbitrary untrusted-code safety,
side-channel resistance, or multi-tenant isolation claim.

## L6 - Network Scope

**Narrowed claim.** SIFR has measured v0.3 QUIC results for loopback, Docker
bridge, 20 ms delay, 1% loss, and 5% loss. SIFR also ships an
operator-runnable v0.5 two-bridge Docker/NetEm harness with seven profiles.

**Evidence.**

- Committed v0.3 CSV under `benchmarks/results/v0.3/quic_network_latency.csv`.
- v0.5 compose file with client/server bridges and trunk bridge.
- NetEm runner supports delay, jitter, loss, and bandwidth cap.
- Python driver records profile config, Docker versions, OS, commit, CSV, and
  metadata when run.

**Remaining.** No v0.5 two-network result CSV is committed. No two-machine,
WAN, public-cloud, NAT traversal, mobile-network, or Internet-scale evaluation
is claimed.

## L7 - Formal Scope

**Narrowed claim.** TLA+ invariants are bounded-proven by TLC, Tamarin lemmas
are symbolic-proven in the Dolev-Yao model, Apalache is symbolic-checkable
through an operator-runnable config, and Python traces are trace-checked for
the same invariants.

**Evidence.**

- TLC: 9 invariants, 11,601 states, depth 7, no error.
- Tamarin: 5/5 lemmas verified with zero wellformedness warnings.
- `formal/apalache.cfg` ships the documented command; no Apalache success log
  is committed.
- `sifr/trace_conformance.py` checks the TLA+ invariants over implementation
  traces and rejects counterexample traces.

**Remaining.** Trace conformance is invariant checking, not full
transition-relation checking. There is no TLAPS/Coq proof, no machine-checked
Python-to-TLA+ simulation relation, and no implementation-refinement proof.

## L8 - Production Security Scope

**Narrowed claim.** SIFR is production-hardened for the documented deployment
model and threat model.

**Evidence.**

- `docs/production_security_model.md` documents single-verifier, clustered,
  multi-tenant, and development/demo modes.
- `sifr/config.py` rejects demo keys outside explicit demo mode and requires
  non-demo key storage in production modes.
- Payload-size limits, replay-window configuration, structured error
  redaction, and optional rate-limit parameters are validated.
- `docs/deployment_guide.md` and `docs/incident_response.md` document
  operator setup and response procedures.

**Remaining.** No full-security claim. No HSM-grade key isolation, enterprise
PKI, DDoS resistance, or host-compromise resistance. Multi-tenant data-plane
isolation is assumed from the hosting service.

## Paper-Ready Honest Claim Set

1. SIFR is production-hardened for the documented deployment model and threat
   model; it is not a production standard and does not claim full security.
2. SIFR validates cryptographic integration against standard vectors and
   reference-style Argon2id parameter checks; primitive security is assumed.
3. SIFR Capability Credentials are VC-shaped but not W3C VC compliant.
4. SIFR supports the documented DID profile, not full DID ecosystem
   compliance.
5. SIFR supports process-shared replay and revocation through durable
   SQLite-WAL state and signed JSONL logs; it does not implement consensus or
   global revocation.
6. SIFR enforces a no-WASI, fuel-bounded, memory-capped, fresh-store WASM
   policy tested against calculator and adversarial fixtures.
7. SIFR has measured v0.3 single-host Docker/NetEm delay/loss results and
   ships an operator-runnable v0.5 two-bridge seven-profile harness; it does
   not claim Internet-scale evaluation.
8. TLA+ invariants are bounded-proven by TLC, Tamarin lemmas are
   symbolic-proven, Python traces are trace-checked, and Apalache is
   symbolic-checkable only until a successful log is committed.
