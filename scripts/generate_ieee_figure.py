"""IEEE-publication-quality figure for the SIFR v0.2 controlled adversary
evaluation. Reads benchmarks/results/adversary_rejection.json and writes a
600 DPI PDF for direct LaTeX inclusion at IEEE single-column width.

IEEE Transactions formatting compliance:
- Serif typeface (Times New Roman, falling back to DejaVu Serif).
- 10 pt axis labels, 12 pt title and legend, 9 pt tick labels.
- Single-column figure width: 3.5 inches.
- Distinct hatching patterns per error class so the figure is readable in
  monochrome reproduction.
- High-contrast, colorblind-friendly palette derived from viridis.
- Top and right spines removed; light dotted grid at alpha = 0.3.
- Axes labelled with units in parentheses; latency on a log scale because
  rejection times span more than three orders of magnitude.
- Output is vector PDF with TrueType font embedding (pdf.fonttype = 42).
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA = REPO_ROOT / "benchmarks" / "results" / "adversary_rejection.json"
OUT = REPO_ROOT / "paper" / "figures" / "ieee_adversary_rejection.pdf"

# ---------- IEEE typography ----------
plt.rcParams.update(
    {
        "font.family": "serif",
        "font.serif": ["Times New Roman", "DejaVu Serif"],
        "mathtext.fontset": "cm",
        "font.size": 10,
        "axes.titlesize": 12,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 10,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "axes.axisbelow": True,
        "grid.alpha": 0.3,
        "grid.linestyle": ":",
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
    }
)

# ---------- Load and order data ----------
with DATA.open("r", encoding="utf-8") as fh:
    rows = json.load(fh)
rows.sort(key=lambda d: d["attack"])


def error_family(expected: str) -> str:
    if "Signature" in expected:
        return "SignatureError"
    if "Replay" in expected:
        return "ReplayError"
    if "MessageValidation" in expected:
        return "MessageValidationError"
    if "AuditDAG" in expected:
        return "AuditDAGError"
    if "Unauthorized" in expected:
        return "UnauthorizedAction"
    if "Capability" in expected:
        return "CapabilityError"
    return "Other"


# Viridis-derived high-contrast colors, distinct under deuteranopia simulation.
PALETTE = {
    "SignatureError":         "#440154",
    "ReplayError":            "#414487",
    "UnauthorizedAction":     "#2a788e",
    "AuditDAGError":          "#22a884",
    "MessageValidationError": "#7ad151",
    "CapabilityError":        "#fde725",
}
# Hatch patterns ensure the bars remain distinguishable in grayscale.
HATCHES = {
    "SignatureError":         "////",
    "ReplayError":            "....",
    "UnauthorizedAction":     "xxxx",
    "AuditDAGError":          "----",
    "MessageValidationError": "++++",
    "CapabilityError":        "\\\\\\\\",
}
LEGEND_ORDER = [
    "SignatureError",
    "ReplayError",
    "UnauthorizedAction",
    "AuditDAGError",
    "MessageValidationError",
    "CapabilityError",
]

labels = [r["attack"].replace("_", " ") for r in rows]
values = [float(r["avg_reject_us"]) for r in rows]
families = [error_family(r["expected"]) for r in rows]

# ---------- Figure ----------
fig, ax = plt.subplots(figsize=(3.5, 4.6))
y = np.arange(len(labels))

for yi, val, fam in zip(y, values, families):
    ax.barh(
        yi,
        val,
        height=0.72,
        color=PALETTE[fam],
        hatch=HATCHES[fam],
        edgecolor="black",
        linewidth=0.5,
    )

ax.set_yticks(y)
ax.set_yticklabels(labels)
ax.invert_yaxis()
ax.set_xscale("log")
ax.set_xlim(left=1, right=max(values) * 2.0)
ax.set_xlabel("Mean Rejection Latency ($\\mu$s, log scale)")
ax.set_title("SIFR v0.2 Controlled Adversary Evaluation")
ax.grid(axis="x", which="both", alpha=0.3, linestyle=":")
ax.tick_params(axis="y", which="both", length=0)

for yi, val in zip(y, values):
    ax.text(
        val * 1.12,
        yi,
        f"{val:.1f}",
        va="center",
        ha="left",
        fontsize=8,
    )

legend_handles = [
    plt.Rectangle(
        (0, 0),
        1,
        1,
        facecolor=PALETTE[fam],
        hatch=HATCHES[fam],
        edgecolor="black",
        linewidth=0.5,
        label=fam,
    )
    for fam in LEGEND_ORDER
]
ax.legend(
    handles=legend_handles,
    loc="upper center",
    bbox_to_anchor=(0.5, -0.18),
    ncol=2,
    frameon=False,
    fontsize=8,
    handlelength=2.4,
    columnspacing=1.0,
)

# ---------- Save ----------
OUT.parent.mkdir(parents=True, exist_ok=True)
fig.savefig(OUT, dpi=600, bbox_inches="tight", pad_inches=0.02, format="pdf")
plt.close(fig)
print(f"Wrote {OUT.relative_to(REPO_ROOT)}")
