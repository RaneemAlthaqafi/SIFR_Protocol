"""SIFR credential-status list.

A bitmap-backed credential-status mechanism in the spirit of W3C
StatusList2021, but without the JSON-LD context machinery and without
GZIP/multibase encoding required by the formal spec.

Honest claim:

> SIFR ships a bitmap-based credential-status mechanism modeled on
> StatusList2021. It is NOT W3C StatusList2021-compliant: we do not encode
> the bitmap as base64-multibase-gzip, we do not use JSON-LD contexts, and
> we do not produce a `StatusList2021Credential`. We DO sign the list with
> Ed25519 and re-verify the signature on every load.

Wire format (`StatusList`):

    {
      "id": "<URL or local id>",
      "issuer": "did:...",
      "size": 16384,
      "bits": "<base64-encoded little-endian bytes; size = ceil(size/8)>",
      "issued_at": "<ISO-8601 UTC>",
      "proof": {
         "type": "Ed25519Signature2020",
         "verificationMethod": "did:...#key-1",
         "proofPurpose": "assertionMethod",
         "proofValue": "<base64 Ed25519 signature over canonical JSON of the
                        list with proof omitted>"
      }
    }

The `credentialStatus` field embedded in a credential references this list
by `id` and a numeric `statusListIndex`:

    "credentialStatus": {
      "id": "<list_id>#<index>",
      "type": "SIFRStatusList2021",
      "statusPurpose": "revocation",
      "statusListIndex": 42,
      "statusListCredential": "<list id>"
    }
"""
from __future__ import annotations

import base64
import copy
from typing import Any, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonical_json
from .errors import SIFRError
from .keyring_iface import KeyResolver
from .utils import utc_now_iso

__all__ = [
    "CredentialStatusError",
    "StatusList",
    "build_credential_status_field",
]


class CredentialStatusError(SIFRError):
    pass


_PROOF_TYPE = "Ed25519Signature2020"
_PROOF_PURPOSE = "assertionMethod"


class StatusList:
    """A signed bitmap of revoked-credential indexes."""

    DEFAULT_SIZE = 16384  # 16K credential slots, fits in 2 KiB

    def __init__(
        self,
        *,
        list_id: str,
        issuer: str,
        size: int = DEFAULT_SIZE,
        issuer_kid: Optional[str] = None,
        issuer_private_key: Optional[Ed25519PrivateKey] = None,
        verifier_key: Optional[Union[Ed25519PublicKey, KeyResolver]] = None,
    ) -> None:
        if size <= 0 or size % 8 != 0:
            raise CredentialStatusError("size must be a positive multiple of 8")
        self.list_id = list_id
        self.issuer = issuer
        self.size = size
        self.issuer_kid = issuer_kid
        self.issuer_private_key = issuer_private_key
        self.verifier_key = verifier_key
        self._bytes = bytearray(size // 8)
        self._issued_at: Optional[str] = None
        self._signed_doc: Optional[dict[str, Any]] = None

    # ---- mutation ----

    def revoke(self, index: int) -> None:
        self._set_bit(index, True)
        self._issued_at = None
        self._signed_doc = None

    def is_revoked(self, index: int) -> bool:
        if not 0 <= index < self.size:
            raise CredentialStatusError(f"index {index} out of range [0, {self.size})")
        byte_idx = index // 8
        bit_idx = index % 8
        return bool(self._bytes[byte_idx] & (1 << bit_idx))

    def _set_bit(self, index: int, value: bool) -> None:
        if not 0 <= index < self.size:
            raise CredentialStatusError(f"index {index} out of range [0, {self.size})")
        byte_idx = index // 8
        bit_idx = index % 8
        if value:
            self._bytes[byte_idx] |= (1 << bit_idx)
        else:
            self._bytes[byte_idx] &= ~(1 << bit_idx)

    # ---- serialization ----

    def _body(self) -> dict[str, Any]:
        return {
            "id": self.list_id,
            "type": "SIFRStatusList2021",
            "issuer": self.issuer,
            "size": self.size,
            "bits": base64.b64encode(bytes(self._bytes)).decode("ascii"),
            "issued_at": self._issued_at or utc_now_iso(),
        }

    def sign(self) -> dict[str, Any]:
        if self.issuer_private_key is None or self.issuer_kid is None:
            raise CredentialStatusError("StatusList has no signing key configured")
        body = self._body()
        # Pin the issued_at into the instance so re-signs are stable for the
        # same in-memory state.
        self._issued_at = body["issued_at"]
        canonical = canonical_json(body)
        sig = self.issuer_private_key.sign(canonical)
        signed = dict(body)
        signed["proof"] = {
            "type": _PROOF_TYPE,
            "verificationMethod": self.issuer_kid,
            "proofPurpose": _PROOF_PURPOSE,
            "created": body["issued_at"],
            "proofValue": base64.b64encode(sig).decode("ascii"),
        }
        self._signed_doc = signed
        return signed

    @classmethod
    def from_signed(
        cls,
        signed: dict[str, Any],
        *,
        verifier_key: Union[Ed25519PublicKey, KeyResolver],
    ) -> "StatusList":
        proof = signed.get("proof")
        if not isinstance(proof, dict):
            raise CredentialStatusError("StatusList missing proof")
        if proof.get("type") != _PROOF_TYPE:
            raise CredentialStatusError(f"unsupported proof type: {proof.get('type')!r}")
        if proof.get("proofPurpose") != _PROOF_PURPOSE:
            raise CredentialStatusError(
                f"proofPurpose must be {_PROOF_PURPOSE!r}, got {proof.get('proofPurpose')!r}"
            )
        proof_value = proof.get("proofValue")
        verification_method = proof.get("verificationMethod")
        if not isinstance(proof_value, str) or not isinstance(verification_method, str):
            raise CredentialStatusError("proof missing proofValue or verificationMethod")

        body = copy.deepcopy(signed)
        body.pop("proof", None)
        canonical = canonical_json(body)
        if isinstance(verifier_key, Ed25519PublicKey):
            pub = verifier_key
        else:
            pub = verifier_key.resolve(verification_method)
        try:
            pub.verify(base64.b64decode(proof_value), canonical)
        except (InvalidSignature, ValueError) as exc:
            raise CredentialStatusError("status list signature invalid") from exc

        issuer = body.get("issuer")
        if isinstance(issuer, str) and "#" in verification_method:
            vm_did = verification_method.split("#", 1)[0]
            if vm_did != issuer:
                raise CredentialStatusError(
                    f"verificationMethod DID {vm_did!r} does not match issuer {issuer!r}"
                )

        size = body.get("size")
        if not isinstance(size, int) or size <= 0 or size % 8 != 0:
            raise CredentialStatusError("size must be a positive multiple of 8")
        bits_b64 = body.get("bits")
        if not isinstance(bits_b64, str):
            raise CredentialStatusError("bits must be a base64 string")
        try:
            raw = base64.b64decode(bits_b64, validate=True)
        except Exception as exc:
            raise CredentialStatusError(f"bits not valid base64: {exc}") from exc
        if len(raw) != size // 8:
            raise CredentialStatusError(
                f"bits length {len(raw)} bytes does not match size {size}"
            )

        instance = cls(
            list_id=body["id"],
            issuer=issuer if isinstance(issuer, str) else "",
            size=size,
            verifier_key=verifier_key,
        )
        instance._bytes = bytearray(raw)
        instance._issued_at = body.get("issued_at")
        instance._signed_doc = signed
        return instance


def build_credential_status_field(
    *,
    status_list_id: str,
    statusListIndex: int,
    status_purpose: str = "revocation",
) -> dict[str, Any]:
    """Construct a `credentialStatus` field referencing a SIFR status list.

    Embedded in the credential body, so the (index, list) binding is covered
    by the credential signature.
    """
    return {
        "id": f"{status_list_id}#{statusListIndex}",
        "type": "SIFRStatusList2021",
        "statusPurpose": status_purpose,
        "statusListIndex": statusListIndex,
        "statusListCredential": status_list_id,
    }
