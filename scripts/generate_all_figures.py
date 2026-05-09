"""Master figure pipeline. Reads versioned raw benchmark data and produces
every figure referenced in the paper, plus paper/figures/figure_manifest.json
recording (figure_file, source_data_file, generator_script, source_sha256,
figure_sha256).

Default version: v0.3. Override with SIFR_BENCH_VERSION.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
VERSION = os.environ.get("SIFR_BENCH_VERSION", "v0.3")
RESULTS = REPO / "benchmarks" / "results" / VERSION
FIG = REPO / "paper" / "figures"
FIG.mkdir(parents=True, exist_ok=True)


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def run(cmd: list[str], cwd: Path | None = None) -> None:
    proc = subprocess.run(cmd, cwd=cwd or REPO, check=True, env={**os.environ, "SIFR_BENCH_VERSION": VERSION})
    return proc


def main() -> None:
    # 1. v0.2-style benchmark figures (8 PNGs). The script reads from
    #    benchmarks/results/v0.2 by default; for v0.3, we re-point its
    #    RESULTS dir via env so it reads the current versioned dir.
    os.environ["SIFR_FIGURE_DATA_DIR"] = str(RESULTS)
    run([sys.executable, "scripts/generate_v0_2_figures.py"])

    # 2. IEEE single-column PDF for the adversary figure.
    run([sys.executable, "scripts/generate_ieee_figure.py"])

    # 3. v0.3-specific adversary figure (30 attacks).
    run([sys.executable, "scripts/generate_v0_3_adversary_figure.py"])

    # 3b. Paper-referenced v0.3 QUIC network figure.
    run([sys.executable, "scripts/generate_quic_network_figure.py"])

    # 4. Manifest. Each entry maps a figure to its source data file and the
    #    SHA-256 of both, so reviewers can detect stale figures.
    pairs = {
        "architecture.png": None,
        "handshake_sequence.png": None,
        "audit_dag.png": None,
        "benchmark_payload.png": "../payload_size.csv",
        "benchmark_quic_network.png": "quic_network_latency.csv",
        "benchmark_did_resolution.png": "did_resolution.csv",
        "benchmark_replay_overhead.png": "replay_overhead.csv",
        "benchmark_revocation_overhead.png": "revocation_overhead.csv",
        "benchmark_credential_verification.png": "credential_verification.csv",
        "benchmark_wasm_overhead.png": "wasm_overhead.csv",
        "benchmark_quic_latency.png": "quic_latency.csv",
        "benchmark_adversary.png": "adversary_rejection.json",
        "benchmark_v0_1_vs_v0_2.png": None,  # synthesized table
        "ieee_adversary_rejection.pdf": "adversary_rejection.json",
        "benchmark_v0_3_adversary.png": "adversary_rejection.json",
    }
    manifest = {
        "version": VERSION,
        "results_dir": str(RESULTS.relative_to(REPO)),
        "figures": [],
    }
    for fig, src in pairs.items():
        fig_path = FIG / fig
        entry: dict = {"figure": fig, "source_data": src, "exists": fig_path.is_file()}
        if fig_path.is_file():
            entry["figure_sha256"] = sha256(fig_path)
        if src:
            src_path = (RESULTS / src).resolve()
            if src_path.is_file():
                entry["source_sha256"] = sha256(src_path)
        manifest["figures"].append(entry)

    out = FIG / "figure_manifest.json"
    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
