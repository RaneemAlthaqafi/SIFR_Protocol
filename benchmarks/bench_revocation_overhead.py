"""Benchmark revocation-registry lookup overhead at different registry sizes."""
from __future__ import annotations

import csv
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from sifr.crypto import generate_keypair
from sifr.revocation import RevocationRegistry


def bench_lookup_overhead(prefill: int, n_probes: int = 5000) -> dict:
    priv, pub = generate_keypair()
    reg = RevocationRegistry(
        issuer="did:sifr:alice",
        issuer_kid="did:sifr:alice#key-1",
        issuer_private_key=priv,
        verifier_key=pub,
    )
    for i in range(prefill):
        reg.revoke(f"cap_pre_{i}", "bench")

    t0 = time.perf_counter()
    for i in range(n_probes):
        reg.is_revoked(f"cap_probe_{i}")
    miss_elapsed = time.perf_counter() - t0

    t0 = time.perf_counter()
    for i in range(n_probes):
        reg.is_revoked(f"cap_pre_{i % max(1, prefill)}")
    hit_elapsed = time.perf_counter() - t0

    return {
        "registry_size": prefill,
        "probes": n_probes,
        "miss_avg_us": round(miss_elapsed / n_probes * 1_000_000, 3),
        "hit_avg_us": round(hit_elapsed / n_probes * 1_000_000, 3),
    }


def main() -> None:
    out = REPO_ROOT / "benchmarks" / "results" / "revocation_overhead.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        bench_lookup_overhead(0),
        bench_lookup_overhead(1_000),
        bench_lookup_overhead(10_000),
    ]
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {out}")
    for r in rows:
        print(
            f"  registry_size={r['registry_size']:>6}  "
            f"miss={r['miss_avg_us']:.3f} us  hit={r['hit_avg_us']:.3f} us"
        )


if __name__ == "__main__":
    main()
