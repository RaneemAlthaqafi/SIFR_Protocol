"""Benchmark WASM calculator overhead vs Python reference."""
from __future__ import annotations

import csv
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from sifr.wasm_runner import PythonCalculatorReference, WasmToolRunner


def bench_python(n: int) -> dict:
    runner = PythonCalculatorReference()
    args = {"a": 12345, "b": 67890}
    t0 = time.perf_counter()
    for _ in range(n):
        runner.execute("tool.calculator.add", args)
    elapsed = time.perf_counter() - t0
    return {
        "implementation": "python",
        "n": n,
        "avg_call_us": round(elapsed / n * 1_000_000, 3),
        "throughput_per_s": round(n / elapsed, 0),
    }


def bench_wasm_warm(n: int) -> dict:
    """Module compiled once, reused for n calls. Each call uses a fresh Store."""
    runner = WasmToolRunner()
    runner.execute("tool.calculator.add", {"a": 1, "b": 1})  # warm: compile
    args = {"a": 12345, "b": 67890}
    t0 = time.perf_counter()
    for _ in range(n):
        runner.execute("tool.calculator.add", args)
    elapsed = time.perf_counter() - t0
    return {
        "implementation": "wasm-warm",
        "n": n,
        "avg_call_us": round(elapsed / n * 1_000_000, 3),
        "throughput_per_s": round(n / elapsed, 0),
    }


def bench_wasm_cold(n: int) -> dict:
    """Each call uses a fresh runner (and re-compiles the module)."""
    args = {"a": 12345, "b": 67890}
    t0 = time.perf_counter()
    for _ in range(n):
        runner = WasmToolRunner()
        runner.execute("tool.calculator.add", args)
    elapsed = time.perf_counter() - t0
    return {
        "implementation": "wasm-cold",
        "n": n,
        "avg_call_us": round(elapsed / n * 1_000_000, 3),
        "throughput_per_s": round(n / elapsed, 0),
    }


def main() -> None:
    out = REPO_ROOT / "benchmarks" / "results" / "wasm_overhead.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        bench_python(10_000),
        bench_wasm_warm(10_000),
        bench_wasm_cold(200),
    ]
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {out}")
    for r in rows:
        print(
            f"  {r['implementation']:10}  n={r['n']:>5}  "
            f"avg={r['avg_call_us']:.3f} us  thrpt={r['throughput_per_s']:.0f}/s"
        )


if __name__ == "__main__":
    main()
