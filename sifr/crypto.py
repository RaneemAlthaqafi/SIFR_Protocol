from __future__ import annotations

import base64
import copy
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from .errors import SignatureError


def _without_signature(obj: dict[str, Any]) -> dict[str, Any]:
    clone = copy.deepcopy(obj)
    clone.pop("signature", None)
    return clone


def message_to_canonical_bytes(message: dict[str, Any]) -> bytes:
    unsigned = _without_signature(message)
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


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


def verify_message(message: dict[str, Any], public_key: Ed25519PublicKey) -> bool:
    sig = message.get("signature")
    if not isinstance(sig, dict) or sig.get("alg") != "Ed25519" or not sig.get("value"):
        raise SignatureError("missing or unsupported signature")
    try:
        public_key.verify(base64.b64decode(sig["value"]), message_to_canonical_bytes(message))
        return True
    except (InvalidSignature, ValueError) as exc:
        raise SignatureError("signature verification failed") from exc
