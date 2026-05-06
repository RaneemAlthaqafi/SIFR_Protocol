from __future__ import annotations

import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from importlib.metadata import version, PackageNotFoundError
from pathlib import Path

try:
    import psutil
except Exception:
    psutil = None


def main() -> None:
    pkgs = {}
    for name in ["cryptography", "numpy", "matplotlib", "pytest", "psutil"]:
        try:
            pkgs[name] = version(name)
        except PackageNotFoundError:
            pkgs[name] = None
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        commit = None
    data = {
        "os": platform.platform(),
        "python": platform.python_version(),
        "cpu": platform.processor(),
        "ram_bytes": psutil.virtual_memory().total if psutil else None,
        "datetime_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "packages": pkgs,
        "git_commit": commit,
    }
    out = Path("benchmarks/results/environment.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(out)


if __name__ == "__main__":
    main()
