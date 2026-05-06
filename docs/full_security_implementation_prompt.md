# SIFR v0.2 Full Security Implementation Prompt

You are the lead scientist and principal engineer for SIFR: Secure Interchange for Federated Reasoning.

Your mission is to upgrade SIFR from a v0.1 feasibility prototype into a rigorously verified v0.2 research artifact that implements and evaluates the security, identity, transport, sandboxing, replay, revocation, and formal-analysis features that v0.1 honestly listed as future work.

You must not fake implementation. You must not claim security properties without evidence. Every claim must map to code, tests, benchmarks, logs, traces, formal model output, or a clearly labeled limitation.

## 1. Required Features To Implement

Implement the following features fully enough that they can be tested, benchmarked, documented, and reviewed.

### 1.1 QUIC Transport Backend

Implement a real QUIC transport backend using `aioquic` or another maintained QUIC implementation.

Requirements:

- Add `QuicTransport` implementing the existing `Transport` interface.
- Support bidirectional agent communication.
- Support multiple logical streams or sessions.
- Use TLS certificates or QUIC-native cryptographic setup.
- Provide localhost integration tests.
- Provide failure tests for connection refusal, malformed frame, and peer disconnect.
- Benchmark local QUIC latency against:
  - LocalTransport
  - simulated HTTP JSON baseline
  - SIFR signing + verification + DAG append

Deliverables:

- `sifr/quic_transport.py`
- `examples/demo_quic_two_agents.py`
- `tests/test_quic_transport.py`
- `benchmarks/bench_quic_latency.py`
- raw CSV results
- plot in `paper/figures/benchmark_quic_latency.png`

Claim rule:

Only claim QUIC is implemented if the demo and tests pass over a real QUIC connection.

### 1.2 Production-Oriented Key Management

Implement a key-management layer beyond demo-only in-memory keys.

Requirements:

- Add key generation, loading, saving, rotation, and key identifiers.
- Store private keys encrypted at rest using a passphrase-derived key or OS keyring.
- Support multiple public keys per agent.
- Support key revocation metadata.
- Add public-key lookup by `kid`.
- Add test fixtures using temporary directories only.
- Never commit real private keys.

Deliverables:

- `sifr/key_management.py`
- `examples/demo_key_rotation.py`
- `tests/test_key_management.py`
- documentation in `docs/key_management.md`

Claim rule:

Do not claim enterprise PKI. Claim only local encrypted key storage and key rotation if implemented.

### 1.3 DID Resolver

Implement DID resolution for at least one real method or a clearly specified local method.

Preferred:

- `did:web` resolver using HTTPS or local test HTTP server.

Minimum acceptable:

- `did:sifr` local resolver with formal method syntax and test DID documents.

Requirements:

- Resolve DID to DID document.
- Extract verification methods.
- Match `kid` to public key.
- Verify message signatures using resolved DID document keys.
- Reject unknown DID.
- Reject malformed DID document.
- Reject missing verification method.
- Reject mismatched key id.

Deliverables:

- `sifr/did.py`
- `docs/did_method.md`
- `examples/demo_did_resolution.py`
- `tests/test_did_resolution.py`

Claim rule:

Only claim DID support for the method actually implemented and tested. Do not claim W3C DID ecosystem interoperability unless tested against real DID documents.

### 1.4 Verifiable Credential Verification

Implement capability grants backed by Verifiable Credential-like signed credentials.

Requirements:

- Define a CapabilityCredential data model.
- Include issuer, subject, actions, resources, expiration, constraints, and proof.
- Support JSON-LD VC only if a real proof suite/library is used correctly.
- Otherwise clearly call it `VC-inspired signed credential`.
- Verify issuer signature.
- Verify subject binding.
- Verify expiration.
- Verify credential status or revocation if implemented.
- Map verified credential to SIFR capability grant.

Deliverables:

- `sifr/credentials.py`
- `examples/demo_capability_credential.py`
- `tests/test_credentials.py`
- `docs/credential_model.md`

Claim rule:

Do not claim W3C VC compliance unless JSON-LD context handling, proof verification, and status/revocation behavior are actually implemented and tested.

### 1.5 Capability Revocation

Implement grant revocation.

Requirements:

- Add a revocation registry.
- Support revoking by `capability_id`.
- Support revocation reason and timestamp.
- Enforce revocation before action authorization.
- Include revoked grants in audit DAG.
- Test revoked-before-use and revoked-after-one-use.
- Test tampered revocation record.

Deliverables:

- updates to `sifr/capabilities.py`
- optional `sifr/revocation.py`
- `examples/demo_revoked_capability.py`
- `tests/test_revocation.py`

Claim rule:

Only claim local revocation unless distributed revocation synchronization is implemented.

### 1.6 Replay Protection

Implement replay protection.

Requirements:

- Add nonce or message-id replay cache.
- Bind replay cache to sender, session, and timestamp window.
- Reject duplicate message IDs.
- Reject stale timestamps outside configured window.
- Persist replay cache optionally for long-running processes.
- Add tests for same-message replay, modified-signature replay, stale timestamp, and valid new message.

Deliverables:

- `sifr/replay.py`
- integration into action verification
- `tests/test_replay.py`
- `examples/demo_replay_rejection.py`

Claim rule:

Only claim replay protection within the tested cache and time-window model.

### 1.7 WASM/WASI Tool Isolation

Implement real sandboxed tool execution using `wasmtime` or another maintained WASM runtime.

Requirements:

- Add `WasmToolRunner`.
- Compile or include a tiny calculator WASM module.
- Execute `calculator.add(a,b)` in WASM.
- Disable filesystem, network, environment, and host imports unless explicitly needed.
- Enforce timeout or fuel limit if supported.
- Reject unsupported tools.
- Test that Python fallback and WASM runner produce same calculator result.
- Test that unauthorized actions cannot reach WASM execution.

Deliverables:

- `sifr/wasm_runner.py` upgraded
- `wasm/` source or build artifact
- `examples/demo_wasm_calculator.py`
- `tests/test_wasm_runner.py`
- `docs/wasm_sandbox.md`

Claim rule:

Only claim WASM isolation for the tested calculator module and runtime configuration. Do not claim arbitrary untrusted code safety.

### 1.8 Network Adversary Evaluation

Implement controlled adversary tests.

Requirements:

- Tamper with signed messages in transit.
- Replay old messages.
- Use expired grant.
- Use revoked grant.
- Swap `sender_id`.
- Swap `kid`.
- Attempt unauthorized action.
- Send malformed frame.
- Drop parent DAG node.
- Attempt oversized payload.
- Attempt WASM execution without grant.

Deliverables:

- `tests/test_network_adversary.py`
- `examples/demo_adversary_cases.py`
- `benchmarks/bench_adversary_rejection.py`
- raw JSON results
- plot in `paper/figures/benchmark_adversary.png`

Claim rule:

Call this a controlled adversary evaluation, not a full penetration test.

### 1.9 Formal Security Model

Create a formal model for at least the authorization state machine.

Acceptable tools:

- TLA+
- Alloy
- ProVerif
- Tamarin
- Ivy
- Coq/Lean only if actually proven

Minimum recommended:

- TLA+ model of capability lifecycle:
  - issued
  - active
  - consumed
  - expired
  - revoked
  - rejected

Properties to check:

- Unauthorized action is never allowed.
- Expired grant is never allowed.
- Revoked grant is never allowed.
- Over-budget grant is never allowed.
- Wrong-subject grant is never allowed.
- Replay of consumed message is rejected.

Deliverables:

- `formal/sifr_capability.tla`
- `formal/MC.cfg`
- model-checker output logs
- `docs/formal_model.md`

Claim rule:

Only claim model-checked properties for the model. Do not claim a full cryptographic proof unless using a proof tool/model that actually covers cryptographic assumptions.

## 2. Integration Requirements

After implementing the features, update the end-to-end vertical slice:

1. Agent A resolves Agent B DID.
2. Agent B resolves Agent A DID.
3. Agents establish QUIC transport.
4. Agent A sends signed Hello.
5. Agent B verifies signature through DID-resolved key.
6. Agent B offers calculator capability.
7. Agent B issues VC-backed or VC-inspired capability credential.
8. Agent A verifies credential.
9. Agent A sends Action with nonce and capability reference.
10. Agent B checks:
    - message signature
    - DID key binding
    - replay cache
    - capability credential
    - revocation registry
    - expiration
    - subject
    - action
    - budget
11. Agent B executes WASM calculator.
12. Agent B returns signed Observation.
13. Both agents append audit DAG nodes.
14. DAG integrity verifies.
15. Formal model output is included in the artifact.

Deliverable:

- `examples/demo_secure_quic_wasm_did_flow.py`

Expected output:

```text
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
Formal model artifacts: PRESENT
Result: 5
Demo completed successfully.
```

## 3. Testing Requirements

All tests must pass:

```bash
pytest
```

Required new tests:

- `tests/test_quic_transport.py`
- `tests/test_key_management.py`
- `tests/test_did_resolution.py`
- `tests/test_credentials.py`
- `tests/test_revocation.py`
- `tests/test_replay.py`
- `tests/test_wasm_runner.py`
- `tests/test_network_adversary.py`
- `tests/test_secure_flow.py`

The test suite must include positive and negative cases. Negative tests are as important as positive tests.

## 4. Benchmark Requirements

Run and save raw results for:

- QUIC latency.
- Replay-cache overhead.
- DID resolution overhead.
- Credential verification overhead.
- WASM calculator overhead.
- Revocation-check overhead.
- Adversary rejection cases.

Update:

- `benchmarks/results/*.csv`
- `benchmarks/results/*.json`
- `paper/figures/*.png`
- `benchmarks/results/environment.json`

Do not overwrite old v0.1 results without labeling versions.

## 5. Paper Revision Requirements

Update `paper/main.tex`.

The title may remain:

`SIFR: Secure Interchange for Federated Reasoning --- A Prototype Protocol for Structured and Verifiable AI-Agent Communication`

But the abstract must distinguish:

- implemented security mechanisms,
- evaluated adversary cases,
- model-checked properties,
- remaining limitations.

Add sections:

- QUIC Transport Implementation
- DID and Key Resolution
- Capability Credentials and Revocation
- Replay Protection
- WASM Tool Isolation
- Formal Model
- Network Adversary Evaluation

Add tables:

- Feature implementation evidence table.
- Security property to test/formal-artifact mapping.
- Adversary rejection results.
- v0.1 vs v0.2 comparison.

Add figures:

- QUIC handshake and SIFR frame exchange.
- Capability lifecycle state machine.
- Revocation flow.
- Formal model state graph if available.
- Adversary rejection benchmark.

## 6. Review Checklist

Before asking for review, produce:

```text
A. What was implemented
B. Evidence for each implementation
C. What was tested
D. Test output
E. Benchmark summary
F. Formal model result
G. Remaining limitations
H. Claims that were intentionally not made
I. Files changed
J. Commit hash
```

## 7. Non-Negotiable Scientific Honesty Rules

- Do not claim QUIC unless real QUIC traffic is used.
- Do not claim production key management unless keys are stored, loaded, rotated, and protected.
- Do not claim DID compliance unless DID documents are resolved and used for key verification.
- Do not claim VC compliance unless real VC proof verification is implemented.
- Do not claim revocation unless revoked capabilities are rejected.
- Do not claim replay protection unless duplicate/stale messages are rejected.
- Do not claim WASM isolation unless a real WASM runtime executes the tool under constrained permissions.
- Do not claim network adversary evaluation unless adversary tests are automated and results are saved.
- Do not claim formal security proof unless a formal tool model or proof artifact exists.
- Do not claim production readiness.

## 8. Final Review Request

When the implementation is complete, ask Codex to review with this instruction:

```text
Review SIFR v0.2 as a hostile systems/security reviewer.

Check every claimed feature against code, tests, benchmarks, formal artifacts, and paper text.

Reject any claim that is not implemented or verified.

Prioritize:
- false security claims,
- broken authorization,
- replay bypass,
- revoked grant reuse,
- DID/key mismatch,
- VC proof gaps,
- QUIC-in-name-only,
- WASM sandbox escape or fake sandboxing,
- missing raw benchmark data,
- paper claims not backed by artifacts.

Return findings ordered by severity with file paths and reproduction steps.
```
