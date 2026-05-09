#!/usr/bin/env bash
# v0.3 beyond-loopback QUIC evaluation: runs sign+verify+DAG round-trip
# across two Docker containers on a Docker bridge network, with optional
# NetEm packet impairment (delay / loss).
#
# Outputs:
#   benchmarks/results/v0.3/quic_network_latency.csv
#
# Configurations measured (each row in the output CSV):
#   loopback_baseline      -- copied from quic_latency.csv (sanity)
#   container_baseline     -- bridge network, no impairment
#   container_delay_20ms   -- NetEm delay 20ms
#   container_loss_1pct    -- NetEm loss 1%
#   container_loss_5pct    -- NetEm loss 5%

set -euo pipefail

cd "$(dirname "$0")/.."
COMPOSE="docker compose -f docker/compose_quic_netem.yml"
RESULTS_DIR="benchmarks/results/v0.3"
OUT_CSV="$RESULTS_DIR/quic_network_latency.csv"
DOCKER_OUT="docker/out"

mkdir -p "$RESULTS_DIR" "$DOCKER_OUT"
rm -f "$DOCKER_OUT/quic_rtt.csv"

# ---- 1. seed loopback baseline from existing v0.3 quic_latency ----
python <<'PY'
import csv
from pathlib import Path
src = Path("benchmarks/results/v0.3/quic_latency.csv")
dst = Path("docker/out/quic_rtt.csv")
dst.parent.mkdir(parents=True, exist_ok=True)
rows = list(csv.DictReader(src.open(encoding="utf-8"))) if src.exists() else []
quic = next((r for r in rows if r.get("transport") == "quic"), None)
with dst.open("w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["label", "n", "avg_rtt_ms", "p95_rtt_ms"])
    if quic:
        w.writerow(["loopback_baseline", quic["n"], quic["avg_rtt_ms"], "n/a"])
print(f"seeded {dst} with loopback_baseline")
PY

# ---- 2. build the QUIC node image ----
$COMPOSE build

# ---- 3. run each impairment config ----
run_config () {
    local label=$1 delay=$2 loss=$3 n=$4
    echo "=== $label  delay=${delay:-none}  loss=${loss:-none}  n=$n ==="
    SIFR_BENCH_LABEL="$label" \
    SIFR_BENCH_N="$n" \
    SIFR_NETEM_DELAY_MS="$delay" \
    SIFR_NETEM_LOSS_PCT="$loss" \
    $COMPOSE up --abort-on-container-exit --exit-code-from client
    $COMPOSE down -v
}

run_config container_baseline    ""   ""  100
run_config container_delay_20ms  20   ""  100
run_config container_loss_1pct   ""   1   100
run_config container_loss_5pct   ""   5   60

cp "$DOCKER_OUT/quic_rtt.csv" "$OUT_CSV"
echo
echo "Wrote $OUT_CSV"
cat "$OUT_CSV"
