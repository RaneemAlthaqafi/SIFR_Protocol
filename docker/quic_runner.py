"""Convenience wrapper used by the Docker container for `tc qdisc` setup."""
from __future__ import annotations

import os
import subprocess
import sys


def main() -> int:
    delay_ms = os.environ.get("SIFR_NETEM_DELAY_MS")
    loss_pct = os.environ.get("SIFR_NETEM_LOSS_PCT")
    iface = os.environ.get("SIFR_NETEM_IFACE", "eth0")
    if delay_ms or loss_pct:
        cmd = ["tc", "qdisc", "add", "dev", iface, "root", "netem"]
        if delay_ms:
            cmd += ["delay", f"{delay_ms}ms"]
        if loss_pct:
            cmd += ["loss", f"{loss_pct}%"]
        print("setting NetEm:", " ".join(cmd), flush=True)
        try:
            subprocess.check_call(cmd)
        except subprocess.CalledProcessError as exc:
            print(f"NetEm setup failed: {exc}", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
