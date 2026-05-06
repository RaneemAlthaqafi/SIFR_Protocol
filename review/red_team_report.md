# Red-Team Report

## Finding 1
Finding: SIFR overlaps with MCP/A2A/ACP/ANP.
Severity: Medium
Location: Paper related work.
Issue: The novelty can sound broader than the prototype proves.
Reproduction: Compare paper claims against cited protocol specs.
Impact: Reviewers may reject marketing-style claims.
Fix: State SIFR v0.1 is a focused vertical slice: signed typed frames plus capabilities plus audit DAG.
Status: Fixed in paper and docs.

## Finding 2
Finding: QUIC is not implemented.
Severity: High
Location: Transport layer.
Issue: A low-latency protocol claim would be overstated.
Reproduction: Inspect `sifr/transport.py`.
Impact: Misleading evaluation.
Fix: Label QUIC as future backend.
Status: Fixed.

## Finding 3
Finding: WASM sandbox is not implemented.
Severity: High
Location: Tool execution.
Issue: Python calculator stub is not equivalent to WASM isolation.
Reproduction: Inspect `sifr/wasm_runner.py`.
Impact: Security overclaim.
Fix: Label WASM/WASI as future work.
Status: Fixed.

## Finding 4
Finding: DID/VC are not implemented.
Severity: High
Location: Identity model.
Issue: `did:sifr:*` strings are syntax only.
Reproduction: Search for DID resolver or VC verification code.
Impact: Identity claims would be false.
Fix: Paper says DID-style identifiers only.
Status: Fixed.

## Finding 5
Finding: Signed messages can still be unauthorized.
Severity: High
Location: Capability layer.
Issue: Signature verification alone does not grant authority.
Reproduction: Run unauthorized action demo.
Impact: Tool misuse.
Fix: Capability enforcement checks action, subject, expiration, and budget.
Status: Tested.

## Finding 6
Finding: Tampered grants must fail.
Severity: High
Location: Capability tests.
Issue: Changed grant actions must invalidate the signature.
Reproduction: `pytest tests/test_capabilities.py`.
Impact: Privilege escalation.
Fix: Grant signature is verified before authorization.
Status: Tested.

## Finding 7
Finding: Audit DAG omits malformed-request logging.
Severity: Medium
Location: Audit layer.
Issue: v0.1 logs accepted messages, not every rejected probe.
Reproduction: Inspect `AuditDAG`.
Impact: Incomplete forensic record.
Fix: Document as limitation and future work.
Status: Documented.

## Finding 8
Finding: Replay protection is incomplete.
Severity: Medium
Location: Protocol spec.
Issue: Unique message IDs exist, but no seen-message cache.
Reproduction: Inspect code.
Impact: Replay risk in networked deployment.
Fix: Label replay cache as future work.
Status: Documented.

## Finding 9
Finding: Benchmark comparisons are local microbenchmarks.
Severity: Medium
Location: Evaluation.
Issue: Results do not prove distributed scalability.
Reproduction: Inspect benchmark scripts.
Impact: Overgeneralization.
Fix: Paper explicitly scopes them as local microbenchmarks.
Status: Fixed.

## Finding 10
Finding: TensorFrame is not KV-cache sharing.
Severity: Medium
Location: Tensor section.
Issue: Base64 vector encoding is only a payload encoding demo.
Reproduction: Inspect `sifr/tensor.py`.
Impact: Privacy and performance overclaim.
Fix: Label TensorFrame as demo encoding.
Status: Fixed.
