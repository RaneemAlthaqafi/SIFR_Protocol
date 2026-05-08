"""Phase 2 demo: replay protection.

Sends an Action through `authorize_action` with a `ReplayCache`. The first
delivery is accepted; the second (same message_id) is rejected before any
authorization checks run.

Run:
    python examples/demo_replay_rejection.py
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sifr.capabilities import CapabilityStore, authorize_action, create_capability_grant
from sifr.crypto import generate_keypair, sign_message
from sifr.errors import ReplayError
from sifr.messages import create_message
from sifr.replay import ReplayCache
from sifr.utils import utc_now_iso


def main() -> int:
    issuer_priv, issuer_pub = generate_keypair()
    subject_priv, _ = generate_keypair()
    issuer = "did:sifr:alice"
    subject = "did:sifr:bob"

    grant = create_capability_grant(
        issuer=issuer,
        subject=subject,
        actions=["tool.calculator.add"],
        resource_scope=["calculator"],
        issuer_private_key=issuer_priv,
        receiver_id=subject,
        session_id="sess_demo",
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
    )
    cap_id = grant["payload"]["capability_id"]

    action = create_message(
        "Action",
        subject,
        issuer,
        {"action": "tool.calculator.add", "args": {"a": 2, "b": 3}, "requires_auth": True},
        session_id="sess_demo",
        capability_id=cap_id,
    )
    signed_action = sign_message(action, subject_priv, f"{subject}#key-1")

    store = CapabilityStore()
    store.add(grant)
    cache = ReplayCache()

    authorize_action(signed_action, grant, issuer_pub, store, replay_cache=cache)
    print("First delivery: authorized")

    try:
        authorize_action(signed_action, grant, issuer_pub, store, replay_cache=cache)
        print("ERROR: replay was NOT rejected")
        return 1
    except ReplayError as e:
        print(f"Second delivery (replay): rejected -- {e}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
