"""Phase 2 demo: capability revocation.

Issues a grant, exercises an Action successfully, revokes the grant, and
shows that a fresh Action with the same capability_id is rejected with
REVOKED_CAPABILITY before any other checks run.

Run:
    python examples/demo_revoked_capability.py
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sifr.capabilities import CapabilityStore, authorize_action, create_capability_grant
from sifr.crypto import generate_keypair, sign_message
from sifr.errors import UnauthorizedAction
from sifr.messages import create_message
from sifr.revocation import RevocationRegistry


def main() -> int:
    issuer_priv, issuer_pub = generate_keypair()
    subject_priv, _ = generate_keypair()
    issuer = "did:sifr:alice"
    subject = "did:sifr:bob"
    issuer_kid = f"{issuer}#key-1"

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
    print(f"Issued grant: {cap_id}")

    store = CapabilityStore()
    store.add(grant)
    registry = RevocationRegistry(
        issuer=issuer,
        issuer_kid=issuer_kid,
        issuer_private_key=issuer_priv,
        verifier_key=issuer_pub,
    )

    def make_action(msgid: str):
        msg = create_message(
            "Action",
            subject,
            issuer,
            {"action": "tool.calculator.add", "args": {"a": 1, "b": 1}, "requires_auth": True},
            session_id="sess_demo",
            capability_id=cap_id,
            message_id=msgid,
        )
        return sign_message(msg, subject_priv, f"{subject}#key-1")

    authorize_action(make_action("msg_1"), grant, issuer_pub, store, revocation_registry=registry)
    print("Pre-revoke action: authorized")

    rev = registry.revoke(cap_id, "demo: rotated subject key")
    print(f"Revoked. Registry now contains {len(registry.export())} entry/entries.")
    print(f"  Revocation message_id: {rev['message_id']}")

    try:
        authorize_action(make_action("msg_2"), grant, issuer_pub, store, revocation_registry=registry)
        print("ERROR: post-revoke action was NOT rejected")
        return 1
    except UnauthorizedAction as e:
        print(f"Post-revoke action: rejected -- {e}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
