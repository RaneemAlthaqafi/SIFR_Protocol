from __future__ import annotations

import csv
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sifr.crypto import generate_keypair, sign_message, verify_message
from sifr.messages import create_message


def run(n: int) -> dict:
    priv, pub = generate_keypair()
    msgs = [create_message("Thought", "did:sifr:a", "did:sifr:b", {"content": f"x{i}", "confidence": 0.9}) for i in range(n)]
    t0 = time.perf_counter()
    signed = [sign_message(m, priv) for m in msgs]
    sign_total = time.perf_counter() - t0
    t0 = time.perf_counter()
    for msg in signed:
        verify_message(msg, pub)
    verify_total = time.perf_counter() - t0
    return {
        "n": n,
        "avg_sign_ms": sign_total / n * 1000,
        "avg_verify_ms": verify_total / n * 1000,
        "sign_total_s": sign_total,
        "verify_total_s": verify_total,
        "sign_msg_per_s": n / sign_total,
        "verify_msg_per_s": n / verify_total,
    }


def main() -> None:
    out = Path("benchmarks/results/signature_overhead.csv")
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = [run(n) for n in [100, 1000, 10000]]
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(out)


if __name__ == "__main__":
    main()
