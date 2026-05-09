"""Driver for the docker-compose QUIC + NetEm benchmark sweep.

Profiles produced:

  baseline      no NetEm
  delay20       20 ms one-way delay
  delay100      100 ms one-way delay
  loss1         1% loss
  loss5         5% loss
  jitter        20 ms ± 10 ms jitter
  bandwidth     10 Mbit/s TBF cap

Each profile invokes the docker-compose stack with the right env vars,
captures the per-profile latency CSV emitted by the client container, and
aggregates the results into `benchmarks/results/quic_network_latency.csv`.

This script does NOT require Docker to import — `pytest -k bench_quic_network`
should not fire it. It is meant to be invoked directly:

    python benchmarks/bench_quic_network.py --profiles baseline delay20

Honest scope claim:

> This harness produces single-host emulated network impairment, not
> Internet-scale evaluation. It uses Linux NetEm in Docker bridges and
> requires NET_ADMIN capability inside the client container.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILE = REPO_ROOT / "docker" / "compose_quic_two_networks.yml"
RESULTS_DIR = REPO_ROOT / "benchmarks" / "results"
DOCKER_OUT_DIR = REPO_ROOT / "docker" / "out"

PROFILES: dict[str, dict[str, str]] = {
    "baseline": {},
    "delay20": {"SIFR_NETEM_DELAY_MS": "20"},
    "delay100": {"SIFR_NETEM_DELAY_MS": "100"},
    "loss1": {"SIFR_NETEM_LOSS_PCT": "1"},
    "loss5": {"SIFR_NETEM_LOSS_PCT": "5"},
    "jitter": {"SIFR_NETEM_DELAY_MS": "20", "SIFR_NETEM_JITTER_MS": "10"},
    "bandwidth": {"SIFR_NETEM_RATE_KBIT": "10000"},
}


def _have_docker() -> bool:
    return shutil.which("docker") is not None


def _run_compose(env: dict[str, str], n: int, label: str) -> Optional[Path]:
    full_env = os.environ.copy()
    full_env.update(env)
    full_env["SIFR_BENCH_N"] = str(n)
    full_env["SIFR_BENCH_LABEL"] = label

    DOCKER_OUT_DIR.mkdir(parents=True, exist_ok=True)
    # Clean prior client output to make the new artifact unambiguous.
    for f in DOCKER_OUT_DIR.glob("*.csv"):
        try:
            f.unlink()
        except OSError:
            pass

    cmd = [
        "docker", "compose", "-f", str(COMPOSE_FILE),
        "up", "--build", "--abort-on-container-exit", "--exit-code-from", "client",
    ]
    print(f"\n=== profile {label!r} env={env} ===", flush=True)
    rc = subprocess.call(cmd, env=full_env, cwd=str(REPO_ROOT))
    subprocess.call(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "down"],
        env=full_env,
        cwd=str(REPO_ROOT),
    )
    if rc != 0:
        print(f"compose returned {rc} for profile {label}", file=sys.stderr)
        return None

    # The client container writes one CSV per run in /out (mounted from
    # docker/out). Pick the most recent.
    csvs = sorted(DOCKER_OUT_DIR.glob("*.csv"), key=lambda p: p.stat().st_mtime)
    if not csvs:
        print(f"no CSV emitted for profile {label}", file=sys.stderr)
        return None
    return csvs[-1]


def _aggregate(per_profile: dict[str, Path], out_csv: Path) -> None:
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["profile", "iteration", "rtt_ms"])
        for profile, src in per_profile.items():
            with src.open("r", encoding="utf-8") as src_fh:
                reader = csv.reader(src_fh)
                rows = list(reader)
            # The container CSV format is whatever bench_quic_latency emits;
            # we expect header + 1 column "rtt_ms" or similar. We re-write as
            # (profile, iteration, rtt_ms).
            data_rows = rows[1:] if rows and any("rtt" in c.lower() for c in rows[0]) else rows
            for i, row in enumerate(data_rows):
                if not row:
                    continue
                # take the last numeric value as rtt_ms
                value = None
                for cell in reversed(row):
                    try:
                        value = float(cell)
                        break
                    except ValueError:
                        continue
                if value is None:
                    continue
                writer.writerow([profile, i, value])
    print(f"wrote {out_csv}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profiles", nargs="+", default=list(PROFILES.keys()))
    parser.add_argument("--n", type=int, default=200)
    parser.add_argument(
        "--out",
        type=Path,
        default=RESULTS_DIR / "quic_network_latency.csv",
    )
    parser.add_argument(
        "--metadata-out",
        type=Path,
        default=RESULTS_DIR / "quic_network_metadata.json",
    )
    args = parser.parse_args()

    if not _have_docker():
        print(
            "docker is not on PATH. This benchmark requires Docker + Docker Compose.\n"
            "See docs/quic_network_evaluation.md for setup.",
            file=sys.stderr,
        )
        return 2

    if not COMPOSE_FILE.exists():
        print(f"compose file missing: {COMPOSE_FILE}", file=sys.stderr)
        return 2

    per_profile: dict[str, Path] = {}
    for profile in args.profiles:
        if profile not in PROFILES:
            print(f"unknown profile {profile!r}; valid: {list(PROFILES.keys())}", file=sys.stderr)
            return 2
        result_csv = _run_compose(PROFILES[profile], args.n, label=profile)
        if result_csv is not None:
            per_profile[profile] = result_csv

    if not per_profile:
        print("no profile produced data", file=sys.stderr)
        return 1

    _aggregate(per_profile, args.out)
    args.metadata_out.parent.mkdir(parents=True, exist_ok=True)
    args.metadata_out.write_text(
        json.dumps(
            {
                "profiles_run": list(per_profile.keys()),
                "n_per_profile": args.n,
                "compose_file": str(COMPOSE_FILE.relative_to(REPO_ROOT)),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
