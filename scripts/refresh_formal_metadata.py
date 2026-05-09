"""Refresh formal/output/tlc_metadata.json + model_hashes.json after re-running
TLC. Keeps the formal-artifact-freshness test honest.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
F = REPO / "formal"
OUT = F / "output"


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def parse_tlc_output(text: str) -> dict:
    distinct = 0
    depth = 0
    duration = 0
    m = re.search(r"(\d+)\s+states generated,\s*(\d+)\s+distinct states found", text)
    if m:
        distinct = int(m.group(2))
    m = re.search(r"depth of the complete state graph search is\s+(\d+)", text)
    if m:
        depth = int(m.group(1))
    m = re.search(r"Finished in\s+(\d+)s", text)
    if m:
        duration = int(m.group(1))
    return {"distinct_states": distinct, "depth": depth, "duration_s": duration}


def main() -> None:
    tla = F / "sifr_capability.tla"
    cfg = F / "MC.cfg"
    out_txt = OUT / "tlc_output.txt"
    if not all(p.is_file() for p in (tla, cfg, out_txt)):
        raise SystemExit("missing TLA/MC.cfg/tlc_output.txt; run formal/run_tlc.{ps1,sh} first")

    body = out_txt.read_text(encoding="utf-8")
    if "No error has been found" not in body:
        raise SystemExit("tlc_output.txt does not contain a success marker")

    cfg_text = cfg.read_text(encoding="utf-8")
    invariants = []
    in_inv = False
    for line in cfg_text.splitlines():
        line = line.strip()
        if line.startswith("INVARIANTS"):
            in_inv = True
            continue
        if in_inv:
            if not line:
                continue
            if line.startswith(("CONSTANTS", "SPECIFICATION", "PROPERTIES")):
                break
            invariants.append(line)

    parsed = parse_tlc_output(body)

    metadata = {
        "tool": "TLC2 (TLA+ Tools)",
        "tool_version": "2026.05.04",
        "java_version": "OpenJDK 17.0.10 (Microsoft)",
        "config": "MC.cfg",
        "flags": "-workers auto -deadlock",
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        **parsed,
        "result": "Model checking completed. No error has been found.",
        "invariants_checked": invariants,
        "invariants_implementation_only": [
            "I7_TamperedCredentialNeverAllowed (tests/test_v0_3_adversary.py::test_a05/06/07)",
            "I10_AuditTamperDetected (tests/test_audit_dag.py + tests/test_v0_3_adversary.py::test_a21)",
        ],
    }
    hashes = {
        "sifr_capability.tla": sha256(tla),
        "MC.cfg": sha256(cfg),
        "tlc_output.txt": sha256(out_txt),
    }
    (OUT / "tlc_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (OUT / "model_hashes.json").write_text(json.dumps(hashes, indent=2), encoding="utf-8")
    print("formal metadata refreshed")


if __name__ == "__main__":
    main()
