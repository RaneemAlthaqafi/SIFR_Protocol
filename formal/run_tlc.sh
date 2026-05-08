#!/usr/bin/env bash
# Wrapper that runs TLC against sifr_capability.tla using MC.cfg.
#
# Prerequisites:
#   - java in PATH (JRE 11+)
#   - tla2tools.jar at $TLA_TOOLS_PATH (or first arg)

set -euo pipefail

TOOLS_PATH="${1:-${TLA_TOOLS_PATH:-}}"
if [ -z "$TOOLS_PATH" ] || [ ! -f "$TOOLS_PATH" ]; then
    echo "tla2tools.jar not found. Set TLA_TOOLS_PATH or pass as first arg." >&2
    echo "See scripts/install_tla.ps1 / docs/formal_model.md for download steps." >&2
    exit 2
fi

here="$(cd "$(dirname "$0")" && pwd)"
out_dir="$here/output"
mkdir -p "$out_dir"
out_file="$out_dir/tlc_output.txt"

cd "$here"
java -XX:+UseParallelGC -cp "$TOOLS_PATH" tlc2.TLC -workers auto -deadlock -config MC.cfg sifr_capability.tla 2>&1 | tee "$out_file"
echo "Output captured at $out_file"
