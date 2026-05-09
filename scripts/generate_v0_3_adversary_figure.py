"""Render paper/figures/benchmark_v0_3_adversary.png from the v0.3 strict
30-case adversary benchmark (benchmarks/results/v0.3/adversary_rejection.json).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

REPO = Path(__file__).resolve().parents[1]
VERSION = os.environ.get("SIFR_BENCH_VERSION", "v0.3")
DATA = REPO / "benchmarks" / "results" / VERSION / "adversary_rejection.json"
OUT = REPO / "paper" / "figures" / "benchmark_v0_3_adversary.png"

PALETTE = {
    "SignatureError":         "#440154",
    "ReplayError":            "#414487",
    "UnauthorizedAction":     "#2a788e",
    "AuditDAGError":          "#22a884",
    "MessageValidationError": "#7ad151",
    "CapabilityError":        "#fde725",
    "CredentialError":        "#fee08b",
    "WasmToolError":          "#999999",
    "Trap":                   "#666666",
    "ValueError":             "#cccccc",
    "PytestOnly":             "#dddddd",
}


def family(actual: str | None, expected: str) -> str:
    if actual == "_pytest_only_":
        return "PytestOnly"
    s = (actual or "") + " " + expected
    for key in PALETTE:
        if key in s:
            return key
    return "ValueError"


def main() -> None:
    rows = json.loads(DATA.read_text(encoding="utf-8"))
    rows.sort(key=lambda r: r["attack_id"])

    labels = [f'{r["attack_id"]} {r["name"]}' for r in rows]
    values = [r["latency_us"] if r["latency_us"] not in (None, -1) else 0.5 for r in rows]
    fams = [family(r.get("actual_error"), r.get("expected", "")) for r in rows]
    pytest_only = [r.get("actual_error") == "_pytest_only_" for r in rows]

    plt.rcParams.update({
        "font.size": 10,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "axes.axisbelow": True,
        "grid.alpha": 0.3,
        "grid.linestyle": ":",
    })

    fig, ax = plt.subplots(figsize=(10.0, 7.5))
    y = np.arange(len(labels))
    for yi, val, fam, py in zip(y, values, fams, pytest_only):
        ax.barh(yi, val, height=0.7, color=PALETTE[fam], edgecolor="black", linewidth=0.5,
                hatch="///" if py else None)
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=8)
    ax.invert_yaxis()
    ax.set_xscale("log")
    ax.set_xlim(left=0.5, right=max(values) * 2.5)
    ax.set_xlabel("Mean rejection latency (us, log scale; pytest-only cases shown as <1us with hatch)")
    ax.set_title("SIFR v0.3 Strict Adversary Evaluation -- 30 controlled cases")

    for yi, val, py in zip(y, values, pytest_only):
        if py:
            ax.text(0.6, yi, "pytest only", va="center", ha="left", fontsize=7, style="italic")
        else:
            ax.text(val * 1.1, yi, f"{val:.0f}", va="center", ha="left", fontsize=7)

    legend_handles = [
        plt.Rectangle((0, 0), 1, 1, color=PALETTE[fam], label=fam, edgecolor="black", linewidth=0.4)
        for fam in PALETTE
    ]
    ax.legend(handles=legend_handles, loc="upper center", bbox_to_anchor=(0.5, -0.07),
              ncol=4, frameon=False, fontsize=8)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(OUT, dpi=160, bbox_inches="tight")
    plt.close(fig)
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
