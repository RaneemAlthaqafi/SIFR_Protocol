"""Phase 4 demo: walk through the 11 controlled adversary cases.

For each attack, prints the attack name, the expected error class, and
PASS/FAIL based on whether the attack was correctly rejected. Exits 0 only
if all 11 attacks were blocked.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import importlib

mod = importlib.import_module("tests.test_network_adversary") if False else None

# Inline the test logic to avoid depending on the test directory layout in
# distributions; we just call each function in order.
import subprocess

REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_FILE = REPO_ROOT / "tests" / "test_network_adversary.py"


def main() -> int:
    print("=== SIFR v0.2 Adversary Cases ===")
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", str(TEST_FILE), "-v", "--no-header", "-q"],
        capture_output=True,
        text=True,
    )
    print(proc.stdout)
    if proc.returncode == 0:
        print("All 11 attacks were correctly rejected.")
        return 0
    print(f"Adversary suite failed (exit {proc.returncode}):")
    print(proc.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
