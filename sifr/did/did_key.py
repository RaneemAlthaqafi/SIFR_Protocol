"""did:key resolver for Ed25519.

did:key is a purely cryptographic DID method: the identifier *is* the
multibase-encoded multicodec public key. There is no off-host resolution; the
DID document is derived deterministically.

Spec: https://w3c-ccg.github.io/did-method-key/

Scope: SIFR's resolver supports only Ed25519. Other curves (X25519,
secp256k1, P-256, …) are not implemented. The resolver rejects unsupported
multicodec prefixes explicitly.

The synthesized DID document follows the W3C-CCG canonical form:

    {
      "id": "did:key:z<multibase>",
      "verificationMethod": [{
        "id": "did:key:z<multibase>#z<multibase>",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:key:z<multibase>",
        "publicKeyMultibase": "z<multibase>"
      }]
    }

where the fragment of the verification-method id repeats the multibase form,
matching the convention used by W3C-CCG and major did:key resolver libraries.
"""
from __future__ import annotations

from . import (
    DidDocument,
    DidResolutionError,
    DidResolver,
    VerificationMethod,
)
from .encodings import (
    DidEncodingError,
    ed25519_pub_from_did_key,
    ed25519_pub_to_multibase,
)

__all__ = ["DidKeyResolver"]


class DidKeyResolver(DidResolver):
    def resolve_document(self, did: str) -> DidDocument:
        if not did.startswith("did:key:"):
            raise DidResolutionError(f"not a did:key identifier: {did}")
        try:
            pub = ed25519_pub_from_did_key(did)
        except DidEncodingError as exc:
            raise DidResolutionError(f"invalid did:key {did!r}: {exc}") from exc
        # Re-encode to canonical multibase to confirm the identifier is in
        # canonical form and to populate the verificationMethod entry.
        multibase = ed25519_pub_to_multibase(pub)
        if did != f"did:key:{multibase}":
            raise DidResolutionError(
                f"did:key {did!r} is not in canonical form; expected "
                f"did:key:{multibase}"
            )
        kid = f"{did}#{multibase}"
        method = VerificationMethod(
            id=kid,
            type="Ed25519VerificationKey2020",
            controller=did,
            public_key_multibase=multibase,
            key_format="publicKeyMultibase",
        )
        return DidDocument(id=did, verification_methods=(method,))
