# Security Model

SIFR v0.1 protects message integrity and minimal action authorization in a local two-agent workflow.

Implemented checks:
- Ed25519 signatures over canonical message bytes.
- Tamper detection for payload and sender fields.
- Signed capability grant verification.
- Subject, action, expiration, payload-size, and call-budget enforcement.
- Audit DAG missing-parent and mutation detection.

Not implemented:
- Key discovery, DID resolution, VC verification, revocation, replay cache, QUIC transport security, WASM isolation, or formal proofs.
