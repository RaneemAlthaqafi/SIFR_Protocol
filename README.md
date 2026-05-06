# SIFR v0.1 Research Prototype

## What is SIFR?
SIFR, Secure Interchange for Federated Reasoning, is an early research prototype for signed, typed, capability-checked AI-agent communication.

## What problem does it solve?
Current agents often exchange plain text or generic JSON over web-era protocols. SIFR explores a native frame format where actions, observations, capabilities, signatures, and audit lineage are explicit.

## What is implemented in v0.1?
- Signed Ed25519 message envelopes.
- Canonical JSON serialization.
- CapabilityOffer and signed CapabilityGrant.
- Capability checks for subject, action, expiration, payload size, call budget, and delegation.
- Content-addressed audit DAG.
- Local in-memory transport abstraction.
- TensorFrame demo encoding for random float32 vectors.
- Safe Python calculator tool stub.
- Unit tests, security tests, benchmarks, figures, and IEEE-style paper source.

## What is not implemented yet?
QUIC, WASM/WASI isolation, DID resolution, Verifiable Credentials, replay cache, grant revocation, MCP/A2A/ACP/ANP adapters, real KV-cache sharing, and production security hardening.

## Architecture
See `paper/figures/architecture.png` and `docs/protocol_spec_v0.md`.

## Quickstart
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest
python examples/demo_two_agents.py
bash scripts/run_benchmarks.sh
python scripts/generate_figures.py
```

On Windows PowerShell, use `.venv\Scripts\Activate.ps1` instead of `source`.

## Run Demo
```bash
python examples/demo_two_agents.py
```

Expected result includes `Result: 5` and `Audit DAG integrity: OK`.

## Run Tests
```bash
pytest
```

## Run Benchmarks
```bash
bash scripts/run_benchmarks.sh
```

Or run each script with Python from the repository root.

## Reproduce Figures
```bash
python scripts/generate_figures.py
```

## Paper and Overleaf
Paper source is in `paper/main.tex`, with references in `paper/references.bib` and upload notes in `paper/overleaf_upload_instructions.md`.

## Security Model
See `docs/security_model.md` and `docs/threat_model.md`.

## Limitations
This is a research prototype. It is not production-ready and has no formal security proof.

## Citation
See `CITATION.cff`.

## License
MIT.
