"""Phase v0.3 demo: walk through the 30 controlled adversary cases.

Runs the v0.3 adversary suite via pytest and prints PASS/FAIL summary.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_FILE = REPO_ROOT / "tests" / "test_v0_3_adversary.py"


def main() -> int:
    print("=== SIFR v0.3 Strict Adversary Cases (30 attacks) ===")
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", str(TEST_FILE), "-v", "--no-header", "-q"],
        capture_output=True,
        text=True,
    )
    print(proc.stdout)
    if proc.returncode == 0:
        print("All 30 v0.3 attacks were correctly rejected.")
        return 0
    print(f"v0.3 adversary suite FAILED (exit {proc.returncode}):")
    print(proc.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
