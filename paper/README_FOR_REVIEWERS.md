# SIFR Paper Package For Reviewers

This folder contains the LNCS-style paper source for:

**SIFR: A Proof-Carrying Protocol for Secure Interchange in Federated AI-Agent Services**

The target venue is ICWS 2026, whose submission page requires Springer LNCS Proceedings style.

## Contents

- `main.tex` — LNCS-style paper source.
- `references.bib` — bibliography.
- `figures/` — architecture, handshake, audit DAG, benchmark, and proof/evaluation figures.
- `overleaf_upload_instructions.md` — instructions for using Overleaf's LNCS template.

## Reviewer Scope

The paper presents SIFR as a research artifact for agent-native service communication. The central claim is that signed typed frames, constrained capability grants, replay and revocation checks, bounded tool execution, and audit-DAG lineage can be combined into one reproducible protocol artifact.

Evidence included in the repository:

- Python implementation under `sifr/`.
- Secure two-agent QUIC/WASM/DID demo.
- 190 implementation tests.
- 30-case adversarial rejection suite.
- TLA+ model checked by TLC: 9 invariants, 11,601 states.
- Tamarin symbolic model: 5/5 lemmas verified.
- Benchmark scripts, raw results, generated plots, and manifests.

## Non-Claims

The paper does not claim:

- production deployment readiness;
- full W3C Verifiable Credential compliance;
- HSM-grade key isolation or enterprise PKI;
- arbitrary untrusted-code WASM safety;
- Internet-scale or multi-host QUIC evaluation;
- cryptographic proof of Ed25519, SHA-256, AES-GCM, or Argon2id;
- implementation-refinement proof from Python to TLA+/Tamarin.

## Compilation

Use Overleaf's Springer LNCS template. If compiling locally, make sure `llncs.cls` and `splncs04.bst` are available.
