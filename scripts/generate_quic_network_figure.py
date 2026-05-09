"""Render paper/figures/benchmark_quic_network.png from
benchmarks/results/v0.3/quic_network_latency.csv (Docker + NetEm runs).
"""
from __future__ import annotations

import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

REPO = Path(__file__).resolve().parents[1]
DATA = REPO / "benchmarks" / "results" / "v0.3" / "quic_network_latency.csv"
OUT = REPO / "paper" / "figures" / "benchmark_quic_network.png"

PAL = {
    "loopback_baseline":      "#2ca02c",
    "container_baseline":     "#1f77b4",
    "container_delay_20ms":   "#9467bd",
    "container_loss_1pct":    "#ff7f0e",
    "container_loss_5pct":    "#d62728",
}


def main() -> None:
    rows = list(csv.DictReader(DATA.open(encoding="utf-8")))
    labels = [r["label"] for r in rows]
    avgs = [float(r["avg_rtt_ms"]) for r in rows]

    p95s = []
    for r in rows:
        v = r.get("p95_rtt_ms", "")
        try:
            p95s.append(float(v))
        except (TypeError, ValueError):
            p95s.append(0.0)

    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 11,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.titleweight": "bold",
            "axes.titlesize": 12,
            "axes.labelsize": 11,
            "figure.dpi": 130,
        }
    )

    x = np.arange(len(labels))
    width = 0.38
    fig, ax = plt.subplots(figsize=(9.0, 4.5))
    colors = [PAL.get(l, "#7f7f7f") for l in labels]
    b1 = ax.bar(x - width / 2, avgs, width, label="mean", color=colors, edgecolor="black", linewidth=0.5)
    b2 = ax.bar(x + width / 2, p95s, width, label="p95", color=colors, alpha=0.45, edgecolor="black", linewidth=0.5, hatch="///")

    for bar, v in zip(b1, avgs):
        ax.text(bar.get_x() + bar.get_width() / 2, v + 0.4, f"{v:.2f}", ha="center", fontsize=8)
    for bar, v in zip(b2, p95s):
        if v > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, v + 0.4, f"{v:.2f}", ha="center", fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels([l.replace("_", "\n") for l in labels], fontsize=9)
    ax.set_ylabel("RTT (ms)")
    ax.set_title("SIFR v0.3 QUIC RTT across loopback and Docker + NetEm impairments")
    ax.grid(axis="y", linestyle=":", alpha=0.4)
    ax.legend(frameon=False, loc="upper left")
    fig.tight_layout()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT)
    plt.close(fig)
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
