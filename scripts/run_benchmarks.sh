#!/usr/bin/env bash
set -euo pipefail
python benchmarks/bench_payload_size.py
python benchmarks/bench_signature_overhead.py
python benchmarks/bench_latency.py
python benchmarks/bench_capability_enforcement.py
python benchmarks/environment.py
