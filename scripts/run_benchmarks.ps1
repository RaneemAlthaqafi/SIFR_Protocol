$ErrorActionPreference = "Stop"

Write-Host "Running SIFR benchmark suite."
Write-Host "Note: v0.1 baseline files are preserved under benchmarks/results/v0.1/."

python benchmarks/bench_payload_size.py
python benchmarks/bench_signature_overhead.py
python benchmarks/bench_latency.py
python benchmarks/bench_capability_enforcement.py
$env:SIFR_BENCH_VERSION = "v0.2"
python benchmarks/bench_did_resolution.py
python benchmarks/bench_credential_verification.py
python benchmarks/bench_replay_overhead.py
python benchmarks/bench_revocation_overhead.py
python benchmarks/bench_wasm_overhead.py
python benchmarks/bench_quic_latency.py
python benchmarks/bench_adversary_rejection.py
Remove-Item Env:\SIFR_BENCH_VERSION
python benchmarks/environment.py
