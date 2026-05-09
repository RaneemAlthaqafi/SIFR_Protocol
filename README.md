# SIFR: Secure Interchange for Federated Reasoning

SIFR is a research artifact for a new agent-native service protocol: signed, typed, capability-checked communication between AI agents with replay protection, revocation, bounded tool execution, and content-addressed audit lineage.

The core idea is simple:

> An AI-agent action should not be "some JSON or text sent over HTTP." It should be a signed typed frame, authorized by a constrained capability, checked for replay and revocation, executed only after verification, and recorded in an audit DAG.

SIFR is intended for the era of agentic services, where AI agents discover tools, delegate tasks, call services, and coordinate with other agents. The artifact is built to support an ICWS/LNCS-style research paper on secure, verifiable AI-agent service communication.

## What SIFR Implements

- Canonical signed SIFR frames using Ed25519.
- Typed messages: `Hello`, `CapabilityOffer`, `CapabilityGrant`, `Thought`, `Action`, `ToolUse`, `Observation`, `Result`, `Critique`, `Error`, and `TensorFrame`.
- Capability grants with issuer, subject, allowed actions, resources, expiration, payload budget, call budget, and delegation policy.
- Replay protection keyed by `(sender_id, session_id, message_id)`.
- Signed capability revocation registry.
- DID-style key lookup for `did:web` and local `did:sifr`.
- VC-inspired capability credentials with mutation detection.
- Content-addressed audit DAG with tamper and missing-parent detection.
- Local transport and QUIC transport through `aioquic`.
- WASM calculator execution through `wasmtime` with no WASI imports and fuel limits.
- TensorFrame demo encoding for numeric vectors.
- A complete two-agent secure-flow demo.
- Benchmarks, figures, raw results, formal artifacts, and release manifests.

## Proof And Evidence

SIFR is a proof-carrying research artifact. Claims are mapped to code, tests, TLA+ invariants, and Tamarin lemmas.

| Claim | Evidence |
|---|---|
| Authorization safety | TLA+ bounded model, Tamarin `authorization_required`, capability tests |
| Replay safety | TLA+ `NoReplayedConsume`, Tamarin `replay_resistance`, replay tests |
| Revocation safety | TLA+ `NoConsumeAfterRevoke`, Tamarin `revocation_safety`, revocation tests |
| Signature binding | Tamarin `authentication`, crypto and DID tests |
| Audit-DAG tamper evidence | audit-DAG tests and adversarial tests |
| No tool before authorization | Tamarin `tool_safety`, WASM and proof-obligation tests |
| Bounded state-machine safety | TLC: 9 invariants, 11,601 states |

Current verification summary:

- `190` Python tests pass with `SIFR_TLC_FROZEN=1`.
- `30` strict adversarial cases reject unauthorized or malformed behavior.
- TLC verifies `9` invariants over `11,601` states.
- Tamarin Prover verifies `5/5` symbolic lemmas with zero wellformedness warnings.
- GitHub Actions passes on Ubuntu and Windows for Python 3.11 and 3.12.

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
SIFR_TLC_FROZEN=1 python -m pytest -q
```

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
$env:SIFR_TLC_FROZEN="1"
python -m pytest -q
```

## Run The Secure Flow Demo

```bash
python examples/demo_secure_quic_wasm_did_flow.py
```

Expected highlights:

```text
DID resolution: OK
QUIC session: OK
Capability credential: OK
Action authorized: OK
WASM calculator executed: OK
Audit DAG integrity: OK
Result: 5
Demo completed successfully.
```

## Run Adversary Tests

```bash
python examples/demo_v0_3_adversary_cases.py
```

The adversary suite covers tampering, replay, expiration, revocation, sender/key swaps, unauthorized tools, malformed frames, dropped DAG parents, payload limits, wrong subjects, wrong issuers, revoked keys, and tool-bypass attempts.

## Reproduce Formal Proofs

TLA+:

```bash
bash formal/run_tlc.sh
python scripts/refresh_formal_metadata.py
SIFR_TLC_FROZEN=1 python -m pytest tests/test_formal_artifacts.py -q
```

Tamarin with Docker:

```bash
docker run --rm --entrypoint sh \
  -e LANG=C.UTF-8 -e LC_ALL=C.UTF-8 \
  -v "$PWD:/work" -w /work aeads/tamarin:latest \
  -c 'tamarin-prover --prove formal/tamarin/sifr_core.spthy --output=/tmp/proof.spthy'
```

## Benchmarks And Figures

Run all benchmark scripts:

```bash
bash scripts/run_all_benchmarks.sh
```

Generate figures:

```bash
python scripts/generate_all_figures.py
```

Selected measured results:

- Plain JSON action: `53` bytes.
- Signed SIFR action: `411` bytes.
- Ed25519 sign: `0.0314 ms`.
- Ed25519 verify: `0.0615 ms`.
- Sign + verify + DAG append: `0.1104 ms`.
- QUIC loopback mean RTT: `0.42 ms`.
- Docker + 20 ms NetEm delay: `22.03 ms` mean RTT.
- WASM calculator warm execution: about `40.6 us`.

## Paper

The paper is now written for an LNCS-style ICWS submission:

- Main LaTeX file: `paper/main.tex`
- Bibliography: `paper/references.bib`
- Figures: `paper/figures/`
- Upload instructions: `paper/overleaf_upload_instructions.md`

ICWS 2026 requires LNCS Proceedings style. The paper uses:

```tex
\documentclass[runningheads]{llncs}
```

Use Overleaf's Springer LNCS template or upload this repository's `paper/` folder into an LNCS project.

## Honest Non-Claims

SIFR is a research artifact, not a production standard.

It does not claim:

- Full W3C Verifiable Credential compliance.
- HSM-grade key isolation or enterprise PKI.
- Distributed revocation or distributed replay protection.
- Arbitrary untrusted-code WASM safety.
- Internet-scale or multi-host QUIC evaluation.
- A cryptographic proof of Ed25519, SHA-256, AES-GCM, or Argon2id.
- A full implementation-refinement proof from Python to TLA+/Tamarin.
- Production-deployment readiness.

## Key Files

- Protocol implementation: `sifr/`
- Secure demos: `examples/`
- Tests: `tests/`
- Benchmarks: `benchmarks/`
- Formal models: `formal/`
- Proof obligations: `docs/proof_obligations_v0_4.md`
- Model-code traceability: `docs/model_code_traceability_v0_4.md`
- Security claims: `docs/security_claims_v0_4.md`
- Paper: `paper/main.tex`

## License

MIT. See `LICENSE`.
