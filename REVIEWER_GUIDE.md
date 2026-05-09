# Reviewer Guide For SIFR v0.2

This guide is the fastest way to audit the repository.

## Review Verdict At A Glance

SIFR v0.2 is a strong demo/workshop research artifact. It is not yet a full production-security or full-conference artifact.

What is strong:

- 137 tests pass.
- The secure flow demo runs end to end over real `aioquic` QUIC on localhost.
- The controlled adversary suite rejects 11 attack classes.
- WASM execution uses `wasmtime`, no WASI imports, and fuel limits.
- The TLA+ authorization model was checked by TLC over 276,205 distinct states.
- The paper contains explicit limitations and non-claims.

Known reviewer caveats:

- QUIC is validated on `127.0.0.1` loopback only.
- Credentials are VC-inspired, not W3C VC compliant.
- The TLA+ model is bounded authorization-safety checking, not a cryptographic proof.
- WASM evidence covers the included calculator and adversarial fixtures, not arbitrary untrusted code.
- Revocation and replay protection are local/per-process unless configured otherwise.
- The benchmark/figure workflow is fragmented and will be hardened in v0.3.

## Commands To Run

```bash
pip install -e ".[dev]"
pytest
python examples/demo_secure_quic_wasm_did_flow.py
python examples/demo_adversary_cases.py
```

On Windows without Bash, run benchmarks with:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_benchmarks.ps1
```

Expected outcomes:

- `137 passed`
- secure flow prints `Result: 5`
- adversary demo prints `All 11 attacks were correctly rejected.`

## Evidence Checklist

| Area | Where to inspect |
|---|---|
| Signed frames | `sifr/crypto.py`, `tests/test_crypto.py` |
| Canonicalization | `sifr/canonical.py`, `tests/test_messages.py` |
| Capabilities | `sifr/capabilities.py`, `tests/test_capabilities.py` |
| Replay | `sifr/replay.py`, `tests/test_replay.py` |
| Revocation | `sifr/revocation.py`, `tests/test_revocation.py` |
| DID | `sifr/did/`, `tests/test_did_resolution.py`, `docs/did_method.md` |
| Credentials | `sifr/credentials.py`, `tests/test_credentials.py`, `docs/credential_model.md` |
| WASM | `sifr/wasm_runner.py`, `wasm/calculator/calculator.wat`, `tests/test_wasm_runner.py` |
| QUIC | `sifr/transport/quic.py`, `tests/test_quic_transport.py` |
| Adversary suite | `tests/test_network_adversary.py`, `examples/demo_adversary_cases.py` |
| Formal model | `formal/sifr_capability.tla`, `formal/MC.cfg`, `formal/output/tlc_output.txt` |
| Paper claim map | `docs/paper_evidence_log.md`, `paper/main.tex` |

## Benchmark Results

Raw results are in `benchmarks/results/`.

Selected v0.2 results:

- QUIC loopback RTT: `0.3831 ms`
- LocalTransport same payload: `0.20 ms`
- WASM warm calculator call: approximately `40.6 us`
- Revocation lookup: approximately `0.3 us`
- VC-inspired credential verification: approximately `0.071 ms`
- 11 attack rejection latencies: `1.0 us` to `1124.2 us`

v0.1 baseline results are preserved under `benchmarks/results/v0.1/`.

## Paper Scope

The paper title is:

`SIFR: Secure Interchange for Federated Reasoning --- Structured and Verifiable AI-Agent Communication`

The title uses the project name, but the artifact does not claim production security. The abstract and limitations should be read together.

## What Would Make v0.3 Stronger

- One-command fail-closed `scripts/reproduce_all.sh` and `.ps1`.
- Versioned benchmark directories and manifests.
- Figure manifest mapping every figure to raw data hashes.
- Formal model freshness checks that fail closed in CI.
- Docker/namespace/NetEm QUIC evaluation beyond loopback.
- Expanded adversary suite with at least 25 cases.

## Suggested Hostile Review Prompt

```text
Review SIFR v0.2 as a hostile systems/security reviewer.
Check every paper claim against code, tests, benchmark outputs, formal artifacts, and docs.
Reject any claim that lacks direct evidence.
Pay special attention to QUIC scope, VC-inspired credentials, DID limitations, WASM sandbox scope, replay/revocation locality, formal-model scope, and reproducibility workflow gaps.
```
