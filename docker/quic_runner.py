"""Convenience wrapper used by the Docker container for `tc qdisc` setup.

Supported NetEm profiles, controlled via env vars:

  SIFR_NETEM_DELAY_MS    one-way delay applied at the egress qdisc (e.g. "20")
  SIFR_NETEM_JITTER_MS   delay jitter (e.g. "5")
  SIFR_NETEM_LOSS_PCT    drop probability percentage (e.g. "1")
  SIFR_NETEM_RATE_KBIT   bandwidth cap in kbit (e.g. "10000" for 10 Mbit/s);
                         applied via a TBF child qdisc when set
  SIFR_NETEM_IFACE       interface name (default eth0)

Examples (composed via docker-compose env):

  delay20:    DELAY_MS=20
  delay100:   DELAY_MS=100
  loss1:      LOSS_PCT=1
  loss5:      LOSS_PCT=5
  jitter:     DELAY_MS=20 JITTER_MS=10
  bandwidth:  RATE_KBIT=10000
"""
from __future__ import annotations

import os
import subprocess
import sys


def _run(cmd: list[str]) -> int:
    print("$", " ".join(cmd), flush=True)
    try:
        subprocess.check_call(cmd)
        return 0
    except subprocess.CalledProcessError as exc:
        print(f"command failed: {exc}", file=sys.stderr)
        return exc.returncode or 2


def main() -> int:
    delay_ms = os.environ.get("SIFR_NETEM_DELAY_MS")
    jitter_ms = os.environ.get("SIFR_NETEM_JITTER_MS")
    loss_pct = os.environ.get("SIFR_NETEM_LOSS_PCT")
    rate_kbit = os.environ.get("SIFR_NETEM_RATE_KBIT")
    iface = os.environ.get("SIFR_NETEM_IFACE", "eth0")

    if not any((delay_ms, jitter_ms, loss_pct, rate_kbit)):
        return 0

    # Root qdisc: NetEm with optional delay/jitter/loss.
    netem_cmd = ["tc", "qdisc", "add", "dev", iface, "root", "handle", "1:", "netem"]
    if delay_ms:
        if jitter_ms:
            netem_cmd += ["delay", f"{delay_ms}ms", f"{jitter_ms}ms"]
        else:
            netem_cmd += ["delay", f"{delay_ms}ms"]
    if loss_pct:
        netem_cmd += ["loss", f"{loss_pct}%"]
    rc = _run(netem_cmd)
    if rc != 0:
        return rc

    # Child qdisc for bandwidth cap.
    if rate_kbit:
        # TBF: token bucket filter. burst sized to ~1ms at the configured rate.
        burst_bytes = max(int(int(rate_kbit) * 1000 / 8 / 1000), 1500)
        rc = _run(
            [
                "tc", "qdisc", "add", "dev", iface, "parent", "1:1", "handle", "10:",
                "tbf", "rate", f"{rate_kbit}kbit", "burst", str(burst_bytes), "latency", "50ms",
            ]
        )
        if rc != 0:
            return rc

    # Verify and print the active qdisc tree.
    _run(["tc", "qdisc", "show", "dev", iface])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
