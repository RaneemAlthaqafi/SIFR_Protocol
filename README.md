# SIFR v0.2 Research Artifact

SIFR, Secure Interchange for Federated Reasoning, is a research artifact for structured, signed, capability-checked AI-agent communication with replay protection, revocation, DID-based key lookup, VC-inspired capability credentials, WASM tool execution, QUIC transport, audit-DAG lineage, and a bounded TLA+ authorization model.

Researchers:

- Raneem Althaqafi, althaqafi.raneem@gmail.com
- Majid Althaqafi, imajedmuhammad@gmail.com

## Start Here For Reviewers

Read [REVIEWER_GUIDE.md](REVIEWER_GUIDE.md) first. It summarizes exactly what is implemented, what is tested, what is measured, and what is **not** claimed.

Fast validation:

```bash
pip install -e ".[dev]"
pytest
python examples/demo_secure_quic_wasm_did_flow.py
python examples/demo_adversary_cases.py
```

Expected status:

- `137 passed`
- secure flow prints `Result: 5` and `Demo completed successfully.`
- adversary demo reports 11 attacks rejected.

## Implemented In v0.2

- Signed Ed25519 SIFR frames with canonical JSON serialization.
- Capability authorization for subject, action, expiration, payload size, call budget, delegation, replay, and revocation.
- Content-addressed audit DAG with tamper and missing-parent detection.
- Encrypted-at-rest file key store using Argon2id and AES-256-GCM with `kid` bound as AAD.
- DID resolution for `did:web` and local `did:sifr`.
- VC-inspired capability credentials with mutation defenses.
- Signed capability revocation registry with on-load signature verification.
- Replay cache keyed on `(sender_id, session_id, message_id)` with timestamp-window checks.
- WASM calculator execution through `wasmtime`, no WASI imports linked, per-call fuel limit.
- QUIC transport through `aioquic` with ALPN `sifr/0.2`, validated on localhost loopback.
- 11-case controlled adversary evaluation.
- TLA+ model of the capability authorization state machine checked over 276,205 distinct states under 7 invariants.
- IEEE-style paper source, figures, benchmark results, and review packet.

## Explicit Non-Claims

SIFR v0.2 is **not production-ready**.

This artifact does **not** claim:

- W3C Verifiable Credential compliance. Credentials are VC-inspired; no JSON-LD context processing or URDNA2015 RDF normalization is implemented.
- A cryptographic proof. The TLA+ artifact is bounded model checking for authorization safety.
- Enterprise PKI, HSM-grade key isolation, or distributed key management.
- Complete DID ecosystem interoperability. Supported DID methods/key formats are documented in [docs/did_method.md](docs/did_method.md).
- Distributed revocation or distributed replay protection.
- Arbitrary untrusted-code WASM safety. WASM evidence covers the calculator module and adversarial fixtures.
- Internet-scale QUIC evaluation. QUIC is real `aioquic`, but currently validated on localhost loopback with self-signed test/demo certificates.
- Fuzzing, penetration testing, side-channel resistance, or MCP/A2A/ACP/ANP interoperability.

## Evidence Map

| Claim | Main evidence |
|---|---|
| Signed frames | `sifr/crypto.py`, `tests/test_crypto.py` |
| Capability authorization | `sifr/capabilities.py`, `tests/test_capabilities.py`, `tests/test_network_adversary.py` |
| DID key binding | `sifr/did/`, `tests/test_did_resolution.py` |
| VC-inspired credentials | `sifr/credentials.py`, `tests/test_credentials.py` |
| Revocation | `sifr/revocation.py`, `tests/test_revocation.py` |
| Replay protection | `sifr/replay.py`, `tests/test_replay.py` |
| WASM execution | `sifr/wasm_runner.py`, `tests/test_wasm_runner.py`, `wasm/calculator/calculator.wat` |
| QUIC transport | `sifr/transport/quic.py`, `tests/test_quic_transport.py` |
| Adversary evaluation | `tests/test_network_adversary.py`, `benchmarks/results/v0.2/adversary_rejection.json` |
| Formal model | `formal/sifr_capability.tla`, `formal/MC.cfg`, `formal/output/tlc_output.txt` |
| Paper evidence | `docs/paper_evidence_log.md`, `review/v0.2_review_packet.md`, `paper/main.tex` |

## Reproducibility

Install:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

Run tests:

```bash
pytest
```

Run demos:

```bash
python examples/demo_secure_quic_wasm_did_flow.py
python examples/demo_adversary_cases.py
```

Run all current benchmark scripts:

```bash
bash scripts/run_benchmarks.sh
```

Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_benchmarks.ps1
```

Regenerate paper figures:

```bash
python scripts/generate_figures.py
python scripts/generate_v0_2_figures.py
python scripts/generate_ieee_figure.py
```

Important v0.2 workflow note: the repository is currently suitable as a workshop/demo artifact. The v0.3 plan is to replace the benchmark/figure workflow with a single fail-closed `scripts/reproduce_all.*` pipeline and versioned result manifests.

## Paper And Reviewer Files

- IEEE-style paper: [paper/main.tex](paper/main.tex)
- Paper package note: [paper/README_FOR_REVIEWERS.md](paper/README_FOR_REVIEWERS.md)
- Review packet: [review/v0.2_review_packet.md](review/v0.2_review_packet.md)
- Evidence log: [docs/paper_evidence_log.md](docs/paper_evidence_log.md)
- Formal model notes: [docs/formal_model.md](docs/formal_model.md)
- Overleaf instructions: [paper/overleaf_upload_instructions.md](paper/overleaf_upload_instructions.md)

## Current Readiness

- Demo artifact: ready.
- Workshop short paper: ready after reviewer reads the explicit non-claims.
- Full research paper: not yet. v0.3 should add one-command fail-closed reproduction, versioned benchmark manifests, stronger formal freshness checks, and non-loopback/emulated QUIC evaluation.

## License

MIT. See [LICENSE](LICENSE).
