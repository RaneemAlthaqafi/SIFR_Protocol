# SIFR v0.2 Paper Package

This package contains the IEEE-style paper source for SIFR v0.2, a research artifact for signed, typed, capability-checked AI-agent communication.

Reviewers should also read the repository-root `REVIEWER_GUIDE.md`, which lists supported claims, non-claims, and known workflow gaps.

## Researchers

- Raneem Althaqafi, althaqafi.raneem@gmail.com
- Majid Althaqafi, imajedmuhammad@gmail.com

## What the Paper Claims

SIFR v0.2 demonstrates a reproducible prototype with:

- signed typed agent frames,
- capability authorization with replay and revocation checks,
- encrypted-at-rest key management,
- DID resolution for `did:web` and local `did:sifr`,
- VC-inspired signed capability credentials,
- WASM calculator execution through `wasmtime`,
- real QUIC transport through `aioquic`, validated on localhost loopback,
- content-addressed audit DAG verification,
- an 11-case controlled adversary evaluation,
- a TLA+ authorization model checked over 276,205 distinct states under 7 invariants.

The paper does not claim production readiness, W3C VC compliance, cryptographic proof, full DID interoperability, arbitrary untrusted WASM safety, distributed revocation/replay, real-network QUIC validation, full attack-surface coverage, or implementation equivalence to the formal model.

## Figures Included

The `figures/` folder includes:

- protocol architecture and sequence diagrams,
- v0.1 payload, signature, latency, and capability benchmark figures,
- v0.2 DID, credential, replay, revocation, WASM, QUIC, adversary, and v0.1-v0.2 comparison figures,
- `ieee_adversary_rejection.pdf`, a publication-style adversary rejection figure.

All benchmark figures are generated from raw files under `benchmarks/results/` in the full repository.

## Compile

Upload this folder to Overleaf, set `main.tex` as the main file, and compile with pdfLaTeX.
