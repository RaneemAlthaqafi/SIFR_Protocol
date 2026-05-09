#!/usr/bin/env bash
# SIFR v0.3 fail-closed reproduction script.
#
# Steps (in order, all required):
#   1. verify environment (Python, Java, deps)
#   2. install dev dependencies
#   3. run all tests (with SIFR_TLC_FROZEN=1 so freshness checks run)
#   4. run all demos
#   5. run all benchmarks (writes to benchmarks/results/v0.3/)
#   6. regenerate all figures
#   7. run TLC against the v0.3 model (refresh tlc_output + metadata + hashes)
#   8. verify generated artifacts are present
#   9. print proof summary
# Any failure exits non-zero. There are no silent skips.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

err() { echo "FAIL: $*" >&2; exit 1; }
ok()  { echo "ok    $*"; }
step(){ echo; echo "=== $* ==="; }

# ---------- 1. environment ----------
step "1/9 Verify environment"
command -v python >/dev/null 2>&1 || err "python not on PATH"
PYV="$(python -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')"
ok "Python $PYV"

command -v java >/dev/null 2>&1 || \
  [ -x "/c/Users/USER/AppData/Local/Programs/Microsoft/jdk-17.0.10.7-hotspot/bin/java.exe" ] || \
  err "java not found (install JRE 11+; needed for TLC)"
if command -v java >/dev/null 2>&1; then
    JAVA_BIN="java"
else
    JAVA_BIN="/c/Users/USER/AppData/Local/Programs/Microsoft/jdk-17.0.10.7-hotspot/bin/java.exe"
fi
ok "java available"

TLA_TOOLS="${TLA_TOOLS_PATH:-$REPO_ROOT/formal/tools/tla2tools.jar}"
[ -f "$TLA_TOOLS" ] || err "tla2tools.jar missing at $TLA_TOOLS (run scripts/install_tla.ps1 or download manually)"
ok "tla2tools.jar present"

python -c "import aioquic, wasmtime, argon2, httpx, cryptography, numpy, pytest, matplotlib" 2>/dev/null || \
  err "missing required Python deps; run: pip install -e \".[dev]\""
ok "Python deps importable"

# ---------- 2. install dev deps ----------
step "2/9 Install dev dependencies"
python -m pip install -q -e ".[dev]" || err "pip install failed"
ok "deps installed"

# ---------- 3. tests ----------
step "3/9 Run pytest (with SIFR_TLC_FROZEN=1)"
SIFR_TLC_FROZEN=1 python -m pytest -q || err "pytest failed"
ok "all tests passed"

# ---------- 4. demos ----------
step "4/9 Run demos"
DEMOS=(
  "examples/demo_secure_quic_wasm_did_flow.py"
  "examples/demo_adversary_cases.py"
  "examples/demo_v0_3_adversary_cases.py"
  "examples/demo_wasm_calculator.py"
  "examples/demo_did_resolution.py"
  "examples/demo_key_rotation.py"
  "examples/demo_capability_credential.py"
  "examples/demo_revoked_capability.py"
  "examples/demo_replay_rejection.py"
)
for d in "${DEMOS[@]}"; do
  [ -f "$d" ] || err "missing demo: $d"
  python "$d" >/dev/null 2>&1 || err "demo failed: $d"
  ok "demo: $d"
done

# ---------- 5. benchmarks ----------
step "5/9 Run all benchmarks (v0.3)"
SIFR_BENCH_VERSION=v0.3 bash scripts/run_all_benchmarks.sh || err "benchmark suite failed"
ok "benchmarks regenerated"

# ---------- 6. figures ----------
step "6/9 Regenerate figures"
python scripts/generate_all_figures.py || err "figure regeneration failed"
ok "figures regenerated"

# ---------- 7. TLC ----------
step "7/9 Run TLC against v0.3 model"
mkdir -p formal/output
"$JAVA_BIN" -XX:+UseParallelGC -cp "$TLA_TOOLS" tlc2.TLC \
  -workers auto -deadlock -config formal/MC.cfg formal/sifr_capability.tla \
  > formal/output/tlc_output.txt 2>&1 || err "TLC reported violations -- see formal/output/tlc_output.txt"
grep -q "No error has been found" formal/output/tlc_output.txt || \
  err "TLC output missing success marker"
python scripts/refresh_formal_metadata.py || err "could not refresh formal metadata"
ok "TLC verified, metadata refreshed"

# ---------- 8. artifact verification ----------
step "8/9 Verify required artifacts"
REQUIRED=(
  "benchmarks/results/v0.3/adversary_rejection.json"
  "benchmarks/results/v0.3/did_resolution.csv"
  "benchmarks/results/v0.3/wasm_overhead.csv"
  "benchmarks/results/v0.3/quic_latency.csv"
  "benchmarks/results/v0.3/replay_overhead.csv"
  "benchmarks/results/v0.3/revocation_overhead.csv"
  "benchmarks/results/v0.3/credential_verification.csv"
  "benchmarks/results/v0.3/manifest.json"
  "paper/figures/figure_manifest.json"
  "paper/figures/benchmark_v0_3_adversary.png"
  "formal/output/tlc_output.txt"
  "formal/output/tlc_metadata.json"
  "formal/output/model_hashes.json"
  "docs/proof_obligations_v0_3.md"
  "review/v0_3_strict_quality_gate.md"
)
for f in "${REQUIRED[@]}"; do
  [ -f "$f" ] || err "required artifact missing: $f"
done
ok "all required artifacts present"

# ---------- 9. summary ----------
step "9/9 Proof summary"
TESTS=$(python -m pytest --collect-only -q 2>/dev/null | tail -1)
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "no-git")
DIRTY=""
if ! git diff --quiet 2>/dev/null; then DIRTY=" (dirty)"; fi

cat <<EOF

SIFR v0.3 reproduction summary
  commit:     $COMMIT$DIRTY
  python:     $PYV
  pytest:     $TESTS
  benchmarks: benchmarks/results/v0.3/
  figures:    paper/figures/
  formal:     formal/output/tlc_output.txt
  proof:      docs/proof_obligations_v0_3.md
  gate:       review/v0_3_strict_quality_gate.md

All steps completed. Artifact is reproducible from a clean checkout
provided the prerequisites in step 1 are satisfied.
EOF
