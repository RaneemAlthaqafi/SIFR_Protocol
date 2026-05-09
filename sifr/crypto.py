from __future__ import annotations

import base64
import copy
import hashlib
from typing import Any, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from .canonical import _without_signature, canonical_json, message_to_canonical_bytes
from .errors import SignatureError
from .keyring_iface import KeyResolver

__all__ = [
    "_without_signature",
    "canonical_json",
    "message_to_canonical_bytes",
    "sha256_cid",
    "generate_keypair",
    "public_key_to_b64",
    "public_key_from_b64",
    "private_key_to_b64",
    "sign_message",
    "verify_message",
]


def sha256_cid(message: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(message_to_canonical_bytes(message)).hexdigest()


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private = Ed25519PrivateKey.generate()
    return private, private.public_key()


def public_key_to_b64(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def public_key_from_b64(value: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(value))


def private_key_to_b64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return base64.b64encode(raw).decode("ascii")


def sign_message(message: dict[str, Any], private_key: Ed25519PrivateKey, kid: str | None = None) -> dict[str, Any]:
    signed = copy.deepcopy(message)
    signature = private_key.sign(message_to_canonical_bytes(signed))
    signed["signature"] = {
        "alg": "Ed25519",
        "kid": kid or f"{signed.get('sender_id', 'did:sifr:unknown')}#key-1",
        "value": base64.b64encode(signature).decode("ascii"),
    }
    return signed


def verify_message(
    message: dict[str, Any],
    key_or_resolver: Union[Ed25519PublicKey, KeyResolver],
) -> bool:
    sig = message.get("signature")
    if not isinstance(sig, dict) or sig.get("alg") != "Ed25519" or not sig.get("value"):
        raise SignatureError("missing or unsupported signature")
    if isinstance(key_or_resolver, Ed25519PublicKey):
        public_key = key_or_resolver
    else:
        kid = sig.get("kid")
        if not kid:
            raise SignatureError("signature missing kid; required for resolver-based verification")
        # v0.3 binding: a resolver-verified message must use a kid whose DID
        # prefix matches the message's sender_id. This prevents the
        # "swap-kid-to-valid-but-unauthorized-key" attack class where the
        # attacker re-signs with a different valid keypair and forges sender_id.
        sender_id = message.get("sender_id")
        if isinstance(sender_id, str) and "#" in kid:
            kid_did = kid.split("#", 1)[0]
            if kid_did != sender_id:
                raise SignatureError(
                    f"kid DID {kid_did!r} does not match sender_id {sender_id!r}"
                )
        public_key = key_or_resolver.resolve(kid)
    try:
        public_key.verify(base64.b64decode(sig["value"]), message_to_canonical_bytes(message))
        return True
    except (InvalidSignature, ValueError) as exc:
        raise SignatureError("signature verification failed") from exc
