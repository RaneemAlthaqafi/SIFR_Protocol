#!/usr/bin/env bash
# Runs every benchmark and writes results into benchmarks/results/$SIFR_BENCH_VERSION
# (defaults to v0.3). Also writes manifest.json with versions, hashes, environment.
set -euo pipefail

cd "$(dirname "$0")/.."
export SIFR_BENCH_VERSION="${SIFR_BENCH_VERSION:-v0.3}"
mkdir -p "benchmarks/results/$SIFR_BENCH_VERSION"

BENCHES=(
    "benchmarks/bench_payload_size.py"
    "benchmarks/bench_signature_overhead.py"
    "benchmarks/bench_latency.py"
    "benchmarks/bench_capability_enforcement.py"
    "benchmarks/bench_did_resolution.py"
    "benchmarks/bench_credential_verification.py"
    "benchmarks/bench_replay_overhead.py"
    "benchmarks/bench_revocation_overhead.py"
    "benchmarks/bench_wasm_overhead.py"
    "benchmarks/bench_quic_latency.py"
    "benchmarks/bench_adversary_rejection.py"
    "benchmarks/bench_v0_3_adversary_rejection.py"
    "benchmarks/environment.py"
)

for b in "${BENCHES[@]}"; do
    echo "--- running $b ---"
    python "$b"
done

python scripts/write_benchmark_manifest.py
echo
echo "All benchmarks done. Manifest at benchmarks/results/$SIFR_BENCH_VERSION/manifest.json"
