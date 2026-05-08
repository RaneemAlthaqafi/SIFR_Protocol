"""Phase 1 demo: resolving a did:sifr document and verifying a signed message.

Generates a keypair, writes a did:sifr DID document for the test agent,
constructs a DidSifrResolver pointed at that directory, signs a message,
and verifies the signature using the resolver (not a directly-passed public key).

Run:
    python examples/demo_did_resolution.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sifr.crypto import generate_keypair, public_key_to_b64, sign_message, verify_message
from sifr.did.did_sifr import DidSifrResolver


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        priv, pub = generate_keypair()

        did = "did:sifr:alice"
        kid = f"{did}#key-1"

        doc = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "verificationMethod": [
                {
                    "id": kid,
                    "type": "Ed25519VerificationKey2020",
                    "controller": did,
                    "publicKeyBase64": public_key_to_b64(pub),
                }
            ],
        }
        (root / "alice.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")

        resolver = DidSifrResolver(root)
        print(f"Resolved DID document for {did}")

        msg = {"sender_id": did, "type": "Hello", "payload": {"hello": "world"}}
        signed = sign_message(msg, priv, kid)
        verify_message(signed, resolver)
        print(f"Signed message verified via resolver -> {kid}: OK")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
