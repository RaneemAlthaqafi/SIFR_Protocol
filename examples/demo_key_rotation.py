"""Phase 1 demo: encrypted-at-rest keystore with key rotation.

Generates a fresh keystore in a temp dir, signs a message with key-1, rotates
to key-2 (key-1 not revoked), and shows that the original signature still
verifies via the keystore acting as a KeyResolver. Then revokes key-1 and shows
the revocation metadata.

Run:
    python examples/demo_key_rotation.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sifr.crypto import sign_message, verify_message
from sifr.key_management import TEST_ARGON2_PARAMS, EncryptedFileKeyStore


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "keys.json"
        keystore = EncryptedFileKeyStore(path, "demo-passphrase", argon2_params=TEST_ARGON2_PARAMS)

        agent_did = "did:sifr:alice"
        kid_v1 = f"{agent_did}#key-1"
        kid_v2 = f"{agent_did}#key-2"

        keystore.generate_keypair(kid_v1)
        priv_v1 = keystore.load_private_key(kid_v1)

        msg = {"sender_id": agent_did, "type": "Hello", "payload": {"hello": "world"}}
        signed_v1 = sign_message(msg, priv_v1, kid_v1)
        print(f"Signed with {kid_v1}: signature[:24]={signed_v1['signature']['value'][:24]}...")

        keystore.generate_keypair(kid_v2)
        print(f"Rotated. Active kids: {sorted(keystore.list_kids())}")

        verify_message(signed_v1, keystore)
        print(f"Old signature still verifies via keystore-as-resolver: OK")

        keystore.revoke(kid_v1, "rotation cleanup")
        info = keystore.resolve_revoked(kid_v1)
        assert info is not None
        print(f"Revocation metadata for {kid_v1}: reason={info.reason!r} at={info.revoked_at}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
