"""Asserts the integration demo runs to completion and prints every required
OK line. Formal-model artifacts may legitimately be PENDING in Phase 4 and
flip to PRESENT in Phase 5.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEMO = REPO_ROOT / "examples" / "demo_secure_quic_wasm_did_flow.py"

EXPECTED_OK_LINES = [
    "DID resolution: OK",
    "QUIC session: OK",
    "Hello signature: OK",
    "Capability credential: OK",
    "Replay check: OK",
    "Revocation check: OK",
    "Action authorized: OK",
    "WASM calculator executed: OK",
    "Observation verified: OK",
    "Audit DAG integrity: OK",
    "Result: 5",
]


def test_secure_flow_demo_runs_to_completion():
    proc = subprocess.run(
        [sys.executable, str(DEMO)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    output = proc.stdout
    missing = [line for line in EXPECTED_OK_LINES if line not in output]
    assert not missing, (
        f"missing required OK lines: {missing}\n"
        f"--- stdout ---\n{output}\n--- stderr ---\n{proc.stderr}"
    )
    assert proc.returncode == 0, (
        f"demo exited {proc.returncode}\nstdout:\n{output}\nstderr:\n{proc.stderr}"
    )
