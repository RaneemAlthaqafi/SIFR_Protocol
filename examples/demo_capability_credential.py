"""Phase 2 demo: VC-inspired capability credential.

Issues a credential wrapping a capability grant, verifies it, then mutates
the credentialSubject.id after signing and shows that verification fails.

Run:
    python examples/demo_capability_credential.py
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sifr.credentials import credential_to_grant, issue_credential, verify_credential
from sifr.crypto import generate_keypair
from sifr.errors import CredentialError
from sifr.utils import utc_now_iso


def main() -> int:
    issuer_priv, issuer_pub = generate_keypair()
    issuer = "did:sifr:alice"
    subject = "did:sifr:bob"
    issuer_kid = f"{issuer}#key-1"

    grant_payload = {
        "capability_id": "cap_001",
        "issuer": issuer,
        "subject": subject,
        "actions": ["tool.calculator.add"],
        "resource_scope": ["calculator"],
        "issued_at": utc_now_iso(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10))
        .isoformat()
        .replace("+00:00", "Z"),
        "budget": {"max_calls": 5, "max_payload_bytes": 1024},
        "constraints": {"allow_delegation": False},
    }

    cred = issue_credential(
        issuer=issuer,
        subject=subject,
        capability_grant_payload=grant_payload,
        issuer_private_key=issuer_priv,
        issuer_kid=issuer_kid,
        expires_at=grant_payload["expires_at"],
    )
    print(f"Issued VC-inspired credential. type={cred['type']}")

    verify_credential(cred, issuer_pub)
    print("Verified pristine credential: OK")

    extracted = credential_to_grant(cred)
    print(f"Extracted capability: id={extracted['capability_id']} actions={extracted['actions']}")

    cred["credentialSubject"]["id"] = "did:sifr:eve"
    try:
        verify_credential(cred, issuer_pub)
        print("ERROR: tampered credential was NOT rejected")
        return 1
    except CredentialError as e:
        print(f"Verified tampered credential (subject swap): rejected -- {e}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
