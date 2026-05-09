"""Multibase, multicodec, and JWK encodings for Ed25519 public keys.

Scope: SIFR supports exactly one curve, Ed25519. We do not implement the
full multibase alphabet set or the full JOSE JWK spec.

Supported encodings:
  - publicKeyBase64: standard base64 of the 32-byte Ed25519 public key.
  - publicKeyMultibase: 'z' (base58btc) prefix, followed by base58btc(
      multicodec(0xed01) || raw_pubkey ).
  - publicKeyJwk: {"kty":"OKP","crv":"Ed25519","x":<base64url-no-pad>}.

References:
  - W3C DID Core: https://www.w3.org/TR/did-core/
  - Multibase draft: https://datatracker.ietf.org/doc/draft-multiformats-multibase/
  - Multicodec table: https://github.com/multiformats/multicodec
  - RFC 7518 §6.1.2 (JWK OKP): https://datatracker.ietf.org/doc/html/rfc7518
  - RFC 8037 §2 (CFRG Curve OKP for Ed25519): https://datatracker.ietf.org/doc/html/rfc8037
"""
from __future__ import annotations

import base64
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..errors import SIFRError

__all__ = [
    "DidEncodingError",
    "ED25519_MULTICODEC",
    "ED25519_RAW_LEN",
    "encode_multibase_base58btc",
    "decode_multibase_base58btc",
    "ed25519_pub_to_multibase",
    "ed25519_pub_from_multibase",
    "ed25519_pub_to_jwk",
    "ed25519_pub_from_jwk",
    "ed25519_pub_to_did_key",
    "ed25519_pub_from_did_key",
]


class DidEncodingError(SIFRError):
    pass


# Multicodec varint-encoded prefix for Ed25519 public key: 0xed (305) -> bytes 0xed 0x01
ED25519_MULTICODEC = b"\xed\x01"
ED25519_RAW_LEN = 32

_BASE58_ALPHABET = (
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)
_BASE58_INDEX = {c: i for i, c in enumerate(_BASE58_ALPHABET)}


def _b58encode(data: bytes) -> bytes:
    n = int.from_bytes(data, "big") if data else 0
    out = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        out.append(_BASE58_ALPHABET[r])
    # leading zero-bytes -> leading '1's
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    out.extend(b"1" * pad)
    out.reverse()
    return bytes(out)


def _b58decode(data: bytes) -> bytes:
    n = 0
    for ch in data:
        if ch not in _BASE58_INDEX:
            raise DidEncodingError(f"invalid base58 character: {chr(ch)!r}")
        n = n * 58 + _BASE58_INDEX[ch]
    full_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = 0
    for ch in data:
        if ch == 0x31:  # '1'
            pad += 1
        else:
            break
    return b"\x00" * pad + full_bytes


def encode_multibase_base58btc(payload: bytes) -> str:
    """Encode bytes as 'z' + base58btc(payload)."""
    return "z" + _b58encode(payload).decode("ascii")


def decode_multibase_base58btc(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise DidEncodingError("multibase value must be a non-empty string")
    prefix, rest = value[0], value[1:]
    if prefix != "z":
        raise DidEncodingError(
            f"unsupported multibase prefix {prefix!r}; only 'z' (base58btc) is supported"
        )
    return _b58decode(rest.encode("ascii"))


def ed25519_pub_to_multibase(pub: Ed25519PublicKey) -> str:
    """Encode an Ed25519 public key as the standard W3C `publicKeyMultibase` form.

    Output is `z` + base58btc(0xed 0x01 || raw32). This is the form used by
    the W3C VC Data Integrity ed25519-2020 cryptosuite and by did:key.
    """
    raw = pub.public_bytes_raw()
    if len(raw) != ED25519_RAW_LEN:
        raise DidEncodingError(f"unexpected Ed25519 public key length: {len(raw)}")
    return encode_multibase_base58btc(ED25519_MULTICODEC + raw)


def ed25519_pub_from_multibase(value: str) -> Ed25519PublicKey:
    decoded = decode_multibase_base58btc(value)
    if not decoded.startswith(ED25519_MULTICODEC):
        raise DidEncodingError(
            f"multibase payload missing Ed25519 multicodec prefix 0xed 0x01"
        )
    raw = decoded[len(ED25519_MULTICODEC):]
    if len(raw) != ED25519_RAW_LEN:
        raise DidEncodingError(
            f"Ed25519 raw key must be 32 bytes, got {len(raw)}"
        )
    return Ed25519PublicKey.from_public_bytes(raw)


def _b64url_nopad_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_nopad_decode(value: str) -> bytes:
    if "=" in value:
        raise DidEncodingError("base64url value must not contain padding")
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def ed25519_pub_to_jwk(pub: Ed25519PublicKey) -> dict[str, str]:
    """Encode an Ed25519 public key as a JWK (RFC 8037 §2)."""
    raw = pub.public_bytes_raw()
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64url_nopad_encode(raw)}


def ed25519_pub_from_jwk(jwk: dict[str, Any]) -> Ed25519PublicKey:
    if not isinstance(jwk, dict):
        raise DidEncodingError("publicKeyJwk must be an object")
    if jwk.get("kty") != "OKP":
        raise DidEncodingError(f"JWK kty must be 'OKP', got {jwk.get('kty')!r}")
    if jwk.get("crv") != "Ed25519":
        raise DidEncodingError(f"JWK crv must be 'Ed25519', got {jwk.get('crv')!r}")
    x = jwk.get("x")
    if not isinstance(x, str):
        raise DidEncodingError("JWK 'x' must be a string")
    try:
        raw = _b64url_nopad_decode(x)
    except Exception as exc:
        raise DidEncodingError(f"JWK 'x' is not valid base64url: {exc}") from exc
    if len(raw) != ED25519_RAW_LEN:
        raise DidEncodingError(
            f"Ed25519 raw key must be 32 bytes, got {len(raw)}"
        )
    return Ed25519PublicKey.from_public_bytes(raw)


def ed25519_pub_to_did_key(pub: Ed25519PublicKey) -> str:
    """Build a did:key identifier for the given Ed25519 public key.

    Form: did:key:z<base58btc(0xed01 || raw32)>.
    """
    return "did:key:" + ed25519_pub_to_multibase(pub)


def ed25519_pub_from_did_key(did: str) -> Ed25519PublicKey:
    if not did.startswith("did:key:"):
        raise DidEncodingError(f"not a did:key identifier: {did!r}")
    return ed25519_pub_from_multibase(did[len("did:key:"):])
