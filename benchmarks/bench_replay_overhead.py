"""Benchmark replay-cache overhead at different cache sizes."""
from __future__ import annotations

import csv
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from sifr.replay import ReplayCache
from sifr.utils import utc_now_iso


def _make(sender: str, session: str, msgid: str, ts: str) -> dict:
    return {
        "sender_id": sender,
        "session_id": session,
        "message_id": msgid,
        "timestamp": ts,
    }


def bench_lookup_overhead(prefill: int, n_probes: int = 1000) -> dict:
    cache = ReplayCache(window_seconds=86400)
    base_ts = utc_now_iso()
    now = datetime.now(timezone.utc)
    for i in range(prefill):
        cache.check_and_record(_make("did:sifr:a", "sess_a", f"msg_pre_{i}", base_ts), now=now)
    t0 = time.perf_counter()
    for i in range(n_probes):
        cache.check_and_record(_make("did:sifr:a", "sess_a", f"msg_probe_{i}", base_ts), now=now)
    elapsed = time.perf_counter() - t0
    return {
        "cache_size": prefill,
        "probes": n_probes,
        "avg_check_us": round(elapsed / n_probes * 1_000_000, 3),
        "throughput_per_s": round(n_probes / elapsed, 1),
    }


def main() -> None:
    out = REPO_ROOT / "benchmarks" / "results" / "replay_overhead.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        bench_lookup_overhead(100),
        bench_lookup_overhead(10_000),
        bench_lookup_overhead(100_000),
    ]
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {out}")
    for r in rows:
        print(
            f"  cache_size={r['cache_size']:>6}  "
            f"avg_check={r['avg_check_us']:.3f} us  "
            f"throughput={r['throughput_per_s']:.0f}/s"
        )


if __name__ == "__main__":
    main()
