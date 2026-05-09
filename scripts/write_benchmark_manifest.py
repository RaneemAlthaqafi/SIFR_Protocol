"""Write benchmarks/results/$VERSION/manifest.json with command, git commit,
timestamp, OS/Python info, dependency versions, bench script hashes, and
result file hashes. Reproducibility metadata for the v0.3 strict gate.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
VERSION = os.environ.get("SIFR_BENCH_VERSION", "v0.3")
RESULTS = REPO / "benchmarks" / "results" / VERSION


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def git(*args: str) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=REPO, text=True).strip()
    except Exception:
        return "unknown"


def main() -> None:
    bench_files = sorted((REPO / "benchmarks").glob("bench_*.py")) + [
        REPO / "benchmarks" / "environment.py",
        REPO / "benchmarks" / "bench_io.py",
    ]
    bench_hashes = {p.name: sha256(p) for p in bench_files if p.is_file()}

    result_files = sorted(p for p in RESULTS.iterdir() if p.is_file() and p.name != "manifest.json")
    result_hashes = {p.name: sha256(p) for p in result_files}

    deps = {}
    for pkg in [
        "aioquic", "wasmtime", "argon2-cffi", "httpx",
        "cryptography", "numpy", "pytest", "matplotlib",
    ]:
        try:
            deps[pkg] = metadata.version(pkg)
        except metadata.PackageNotFoundError:
            deps[pkg] = "missing"

    manifest = {
        "version": VERSION,
        "command": "scripts/run_all_benchmarks.sh",
        "git_commit": git("rev-parse", "HEAD"),
        "git_describe": git("describe", "--always", "--tags"),
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "dependencies": deps,
        "benchmark_script_hashes": bench_hashes,
        "result_file_hashes": result_hashes,
    }
    out = RESULTS / "manifest.json"
    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
