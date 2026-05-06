from __future__ import annotations

import csv
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sifr.audit_dag import AuditDAG
from sifr.crypto import generate_keypair, sign_message, verify_message
from sifr.messages import create_message
from sifr.transport import HttpJsonBaselineTransport


def summarize(case: str, samples: list[float]) -> dict:
    samples_ms = sorted(s * 1000 for s in samples)
    def pct(p: float) -> float:
        idx = min(len(samples_ms) - 1, int(round((p / 100) * (len(samples_ms) - 1))))
        return samples_ms[idx]
    return {
        "case": case,
        "mean_ms": statistics.mean(samples_ms),
        "stddev_ms": statistics.pstdev(samples_ms),
        "p50_ms": pct(50),
        "p95_ms": pct(95),
        "p99_ms": pct(99),
    }


def main(n: int = 1000) -> None:
    priv, pub = generate_keypair()
    rows = []
    cases: dict[str, list[float]] = {k: [] for k in ["plain_local_dict", "sifr_create_only", "sifr_sign_verify", "sifr_sign_verify_dag", "http_json_baseline_serialization"]}
    for i in range(n):
        t = time.perf_counter(); x = {"i": i}; y = x; cases["plain_local_dict"].append(time.perf_counter() - t)
        t = time.perf_counter(); msg = create_message("Thought", "did:sifr:a", "did:sifr:b", {"content": str(i), "confidence": 1}); cases["sifr_create_only"].append(time.perf_counter() - t)
        t = time.perf_counter(); signed = sign_message(msg, priv); verify_message(signed, pub); cases["sifr_sign_verify"].append(time.perf_counter() - t)
        dag = AuditDAG()
        t = time.perf_counter(); signed = sign_message(msg, priv); verify_message(signed, pub); dag.add_message(signed); cases["sifr_sign_verify_dag"].append(time.perf_counter() - t)
        t = time.perf_counter(); data = HttpJsonBaselineTransport.serialize(msg); HttpJsonBaselineTransport.deserialize(data); cases["http_json_baseline_serialization"].append(time.perf_counter() - t)
    rows = [summarize(case, samples) for case, samples in cases.items()]
    out = Path("benchmarks/results/latency.csv")
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(out)


if __name__ == "__main__":
    main()
