# Implementation Notes

The prototype is intentionally small:
- `sifr/messages.py` creates and validates envelopes.
- `sifr/crypto.py` canonicalizes, signs, verifies, and hashes.
- `sifr/capabilities.py` signs and enforces grants.
- `sifr/audit_dag.py` stores content-addressed lineage.
- `sifr/transport.py` implements local in-memory transport.
- `sifr/tensor.py` compares JSON-list and base64 float32 vector encodings.
- `sifr/wasm_runner.py` contains a safe Python calculator stub, not WASM.
