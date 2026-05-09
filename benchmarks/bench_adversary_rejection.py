"""Benchmark time-to-reject per adversary class.

Times how quickly each of the 11 attacks is rejected. Reject latency is the
time from `_authorized_execute(...)` to the raised exception. The numbers
characterize the overhead of the rejection path; they are not meaningful as
"how slow is the attack" — that is bounded by the test harness loop.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_io import versioned_results_dir
sys.path.insert(0, str(REPO_ROOT / "tests"))

from datetime import datetime, timedelta, timezone

from sifr.audit_dag import AuditDAG
from sifr.capabilities import authorize_action, create_capability_grant
from sifr.crypto import generate_keypair, sign_message, verify_message
from sifr.errors import (
    AuditDAGError,
    CapabilityError,
    MessageValidationError,
    ReplayError,
    SignatureError,
    UnauthorizedAction,
)
from sifr.messages import create_message, validate_message
from test_network_adversary import _authorized_execute, _make_scenario, _past_iso


def _time(callable_attack):
    n = 200
    durations = []
    for _ in range(n):
        s = _make_scenario()
        t0 = time.perf_counter()
        try:
            callable_attack(s)
        except Exception:
            pass
        durations.append(time.perf_counter() - t0)
    avg = sum(durations) / len(durations)
    return round(avg * 1_000_000, 1)  # microseconds


def attack_01(s):
    s["action"]["payload"]["args"]["a"] = 999
    _authorized_execute(s, grant=s["grant"])


def attack_02(s):
    _authorized_execute(s, grant=s["grant"])
    _authorized_execute(s, grant=s["grant"])


def attack_03(s):
    s2 = _make_scenario(expires_at=_past_iso())
    _authorized_execute(s2, grant=s2["grant"])


def attack_04(s):
    s["registry"].revoke(s["cap_id"], "bench")
    _authorized_execute(s, grant=s["grant"])


def attack_05(s):
    s["action"]["sender_id"] = "did:sifr:eve"
    _authorized_execute(s, grant=s["grant"])


def attack_06(s):
    s["action"]["signature"]["kid"] = s["issuer_kid"]
    _authorized_execute(s, grant=s["grant"])


def attack_07(s):
    new_action = create_message(
        "Action",
        s["action"]["sender_id"],
        s["action"]["receiver_id"],
        {"action": "tool.calculator.subtract", "args": {"a": 1, "b": 1}, "requires_auth": True},
        session_id=s["action"]["session_id"],
        capability_id=s["cap_id"],
    )
    signed = sign_message(new_action, s["subject_priv"], s["subject_kid"])
    _authorized_execute(s, action=signed, grant=s["grant"])


def attack_08(s):
    bogus = {"type": "Action", "payload": {}}
    validate_message(bogus)


def attack_09(s):
    dag = AuditDAG()
    cid = dag.add_message(s["grant"])
    s["action"]["parents"] = [cid]
    re_signed = sign_message(s["action"], s["subject_priv"], s["subject_kid"])
    dag.add_message(re_signed)
    del dag.nodes[cid]
    del dag.messages[cid]
    dag.verify_dag_integrity()


def attack_10(s):
    big = create_message(
        "Action",
        s["action"]["sender_id"],
        s["action"]["receiver_id"],
        {
            "action": "tool.calculator.add",
            "args": {"a": 1, "b": 2},
            "requires_auth": True,
            "padding": "x" * 5000,
        },
        session_id=s["action"]["session_id"],
        capability_id=s["cap_id"],
    )
    signed = sign_message(big, s["subject_priv"], s["subject_kid"])
    _authorized_execute(s, action=signed, grant=s["grant"])


def attack_11(s):
    _authorized_execute(s, grant=None)


def main() -> None:
    out = versioned_results_dir() / "adversary_rejection.json"
    out.parent.mkdir(parents=True, exist_ok=True)

    attacks = [
        ("01_tamper_body", attack_01, "SignatureError"),
        ("02_replay", attack_02, "ReplayError"),
        ("03_expired_grant", attack_03, "UnauthorizedAction(EXPIRED)"),
        ("04_revoked_grant", attack_04, "UnauthorizedAction(REVOKED)"),
        ("05_swap_sender_id", attack_05, "SignatureError"),
        ("06_swap_kid", attack_06, "SignatureError"),
        ("07_unauthorized_action", attack_07, "UnauthorizedAction(UNAUTHORIZED)"),
        ("08_malformed_frame", attack_08, "MessageValidationError"),
        ("09_drop_parent_dag", attack_09, "AuditDAGError"),
        ("10_oversized_payload", attack_10, "UnauthorizedAction(PAYLOAD_BUDGET)"),
        ("11_wasm_without_grant", attack_11, "CapabilityError"),
    ]

    results = []
    for name, fn, expected in attacks:
        avg_us = _time(fn)
        results.append({"attack": name, "expected": expected, "avg_reject_us": avg_us})
        print(f"  {name:30s}  expected={expected:35s}  reject={avg_us:.1f} us")

    out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
