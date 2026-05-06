from __future__ import annotations

import csv
import json
from pathlib import Path

import matplotlib.pyplot as plt

FIG = Path("paper/figures")
FIG.mkdir(parents=True, exist_ok=True)


def save_layers():
    layers = ["Agent Application", "Structured Messages", "Capability/Auth", "Audit DAG", "TensorFrame (demo)", "Tool Sandbox (stub)", "Transport (local)"]
    fig, ax = plt.subplots(figsize=(8, 4.8))
    for i, layer in enumerate(layers):
        ax.add_patch(plt.Rectangle((0.15, i), 0.7, 0.72, facecolor="#d8eef2" if i not in [4,5] else "#f5e6b3", edgecolor="#234"))
        ax.text(0.5, i + 0.36, layer, ha="center", va="center", fontsize=11)
    ax.set_xlim(0, 1); ax.set_ylim(-0.1, len(layers)); ax.axis("off")
    ax.set_title("SIFR v0.1 Layered Architecture")
    fig.tight_layout(); fig.savefig(FIG / "architecture.png", dpi=180); plt.close(fig)


def save_sequence():
    steps = ["Hello", "CapabilityOffer", "CapabilityGrant", "Signed Action", "ToolUse", "Signed Observation", "Audit DAG"]
    fig, ax = plt.subplots(figsize=(8, 4.2))
    ax.text(0.15, 1, "Agent A", ha="center", weight="bold"); ax.text(0.85, 1, "Agent B", ha="center", weight="bold")
    for x in [0.15, 0.85]: ax.plot([x, x], [0.05, 0.92], color="#555")
    y = 0.85
    for i, step in enumerate(steps):
        if i in [0,3,6]: start, end = 0.18, 0.82
        else: start, end = 0.82, 0.18
        ax.annotate("", xy=(end, y), xytext=(start, y), arrowprops=dict(arrowstyle="->", color="#245"))
        ax.text(0.5, y + 0.02, step, ha="center", fontsize=9)
        y -= 0.12
    ax.axis("off"); fig.tight_layout(); fig.savefig(FIG / "handshake_sequence.png", dpi=180); plt.close(fig)


def save_dag():
    nodes = ["Hello", "Offer", "Grant", "Action", "ToolUse", "Observation", "Result"]
    fig, ax = plt.subplots(figsize=(8, 2.2))
    for i, n in enumerate(nodes):
        ax.scatter(i, 0, s=1200, color="#e7f0d4", edgecolor="#345")
        ax.text(i, 0, n, ha="center", va="center", fontsize=8)
        if i:
            ax.annotate("", xy=(i - 0.28, 0), xytext=(i - 0.72, 0), arrowprops=dict(arrowstyle="->"))
    ax.set_xlim(-0.7, len(nodes)-0.3); ax.set_ylim(-0.6, 0.6); ax.axis("off")
    fig.tight_layout(); fig.savefig(FIG / "audit_dag.png", dpi=180); plt.close(fig)


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def save_payload():
    rows = read_csv("benchmarks/results/payload_size.csv")
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar([r["case"] for r in rows], [int(r["bytes"]) for r in rows], color="#7aa6a1")
    ax.set_ylabel("Bytes"); ax.tick_params(axis="x", rotation=25); ax.set_title("Payload Size")
    fig.tight_layout(); fig.savefig(FIG / "benchmark_payload.png", dpi=180); plt.close(fig)


def save_signature():
    rows = read_csv("benchmarks/results/signature_overhead.csv")
    n = [int(r["n"]) for r in rows]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot(n, [float(r["avg_sign_ms"]) for r in rows], marker="o", label="sign")
    ax.plot(n, [float(r["avg_verify_ms"]) for r in rows], marker="o", label="verify")
    ax.set_xscale("log"); ax.set_ylabel("Average ms/message"); ax.set_xlabel("Messages"); ax.legend(); ax.set_title("Ed25519 Overhead")
    fig.tight_layout(); fig.savefig(FIG / "benchmark_signature_overhead.png", dpi=180); plt.close(fig)


def save_latency():
    rows = read_csv("benchmarks/results/latency.csv")
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar([r["case"] for r in rows], [float(r["mean_ms"]) for r in rows], color="#b88f75")
    ax.set_ylabel("Mean ms"); ax.tick_params(axis="x", rotation=25); ax.set_title("Local Latency Microbenchmark")
    fig.tight_layout(); fig.savefig(FIG / "benchmark_latency.png", dpi=180); plt.close(fig)


def save_capability():
    rows = json.loads(Path("benchmarks/results/capability_results.json").read_text(encoding="utf-8"))
    expected = {"authorized_action": True}
    vals = [1 if (r["passed"] == expected.get(r["case"], False)) else 0 for r in rows]
    fig, ax = plt.subplots(figsize=(8, 3.8))
    ax.bar([r["case"] for r in rows], vals, color=["#719f7a" if v else "#c7665a" for v in vals])
    ax.set_ylim(0, 1.2); ax.set_ylabel("Expected outcome met"); ax.tick_params(axis="x", rotation=25); ax.set_title("Capability Enforcement Cases")
    fig.tight_layout(); fig.savefig(FIG / "benchmark_capability.png", dpi=180); plt.close(fig)


def main():
    save_layers(); save_sequence(); save_dag(); save_payload(); save_signature(); save_latency(); save_capability()
    print("Generated figures in paper/figures")


if __name__ == "__main__":
    main()
