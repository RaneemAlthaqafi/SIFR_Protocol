"""Shared helpers for versioned benchmark output paths."""
from __future__ import annotations

import os
from pathlib import Path

DEFAULT_VERSION = "v0.2"
ROOT = Path(__file__).resolve().parents[1]


def benchmark_version() -> str:
    return os.environ.get("SIFR_BENCH_VERSION", DEFAULT_VERSION)


def versioned_results_dir() -> Path:
    out = ROOT / "benchmarks" / "results" / benchmark_version()
    out.mkdir(parents=True, exist_ok=True)
    return out
