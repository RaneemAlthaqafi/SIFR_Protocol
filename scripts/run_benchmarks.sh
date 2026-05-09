#!/usr/bin/env bash
set -euo pipefail

echo "Running SIFR benchmark suite."
echo "Note: v0.1 baseline files are preserved under benchmarks/results/v0.1/."

python benchmarks/bench_payload_size.py
python benchmarks/bench_signature_overhead.py
python benchmarks/bench_latency.py
python benchmarks/bench_capability_enforcement.py
SIFR_BENCH_VERSION=v0.2 python benchmarks/bench_did_resolution.py
SIFR_BENCH_VERSION=v0.2 python benchmarks/bench_credential_verification.py
SIFR_BENCH_VERSION=v0.2 python benchmarks/bench_replay_overhead.py
SIFR_BENCH_VERSION=v0.2 python benchmarks/bench_revocation_overhead.py
SIFR_BENCH_VERSION=v0.2 python benchmarks/bench_wasm_overhead.py
SIFR_BENCH_VERSION=v0.2 python benchmarks/bench_quic_latency.py
SIFR_BENCH_VERSION=v0.2 python benchmarks/bench_adversary_rejection.py
python benchmarks/environment.py
