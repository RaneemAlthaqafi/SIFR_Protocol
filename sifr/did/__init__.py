"""DID resolution for SIFR.

Three methods are implemented:
- did:web (preferred) — fetches DID documents over HTTP/HTTPS.
- did:key — pure-cryptographic, derives the document from the identifier.
- did:sifr (local fallback) — reads documents from a local directory.

All resolvers implement the KeyResolver Protocol from keyring_iface, so they
can be passed directly to crypto.verify_message and capabilities.authorize_action.

This package does NOT claim full W3C DID interoperability. It supports the
following Ed25519 verification-method shapes:

  - publicKeyBase64 + type Ed25519VerificationKey2018 / 2020
  - publicKeyMultibase + type Ed25519VerificationKey2020
  - publicKeyJwk + type JsonWebKey2020 (kty=OKP, crv=Ed25519)

Other key types, JSON-LD context expansion, and URDNA2015 canonicalization
are out of scope. See docs/did_method.md.
"""
from __future__ import annotations

import base64
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..crypto import public_key_from_b64
from ..errors import SIFRError
from ..keyring_iface import RevocationInfo

from .encodings import (
    DidEncodingError,
    ed25519_pub_from_did_key,
    ed25519_pub_from_jwk,
    ed25519_pub_from_multibase,
    ed25519_pub_to_multibase,
)

__all__ = [
    "DidError",
    "DidResolutionError",
    "DidDocumentError",
    "DidKeyMismatch",
    "VerificationMethod",
    "DidDocument",
    "DidResolver",
    "MultiMethodResolver",
    "parse_kid",
    "parse_did_document",
    "SUPPORTED_VERIFICATION_TYPES",
]

# Type names accepted in verificationMethod entries. We intentionally accept
# both the 2018 and 2020 Ed25519 W3C suite names as well as JsonWebKey2020
# (which is the suite that carries publicKeyJwk for OKP/Ed25519).
SUPPORTED_VERIFICATION_TYPES = frozenset(
    {
        "Ed25519VerificationKey2020",
        "Ed25519VerificationKey2018",
        "JsonWebKey2020",
    }
)


class DidError(SIFRError):
    pass


class DidResolutionError(DidError):
    pass


class DidDocumentError(DidError):
    pass


class DidKeyMismatch(DidError):
    pass


@dataclass(frozen=True)
class VerificationMethod:
    """A parsed Ed25519 verification method.

    Exactly one of the public_key_* fields is non-empty after parsing; we
    keep all three for round-tripping and traceability. The `key_format`
    field records which DID-Core encoding was used in the source document.
    """

    id: str
    type: str
    controller: str
    public_key_b64: str = ""
    public_key_multibase: str = ""
    public_key_jwk: Optional[dict] = None
    key_format: str = "publicKeyBase64"

    def to_public_key(self) -> Ed25519PublicKey:
        if self.key_format == "publicKeyBase64":
            return public_key_from_b64(self.public_key_b64)
        if self.key_format == "publicKeyMultibase":
            return ed25519_pub_from_multibase(self.public_key_multibase)
        if self.key_format == "publicKeyJwk":
            if self.public_key_jwk is None:
                raise DidDocumentError("publicKeyJwk format with no JWK body")
            return ed25519_pub_from_jwk(self.public_key_jwk)
        raise DidDocumentError(f"unsupported key_format: {self.key_format!r}")


@dataclass(frozen=True)
class DidDocument:
    id: str
    verification_methods: tuple[VerificationMethod, ...]

    def find_method(self, kid: str) -> VerificationMethod:
        for m in self.verification_methods:
            if m.id == kid:
                return m
        raise DidKeyMismatch(f"verification method {kid!r} not found in document {self.id}")


def parse_kid(kid: str) -> tuple[str, str]:
    """Split a kid like 'did:method:foo#key-1' into (did, kid)."""
    if not isinstance(kid, str) or "#" not in kid:
        raise DidError(f"kid must include fragment: {kid!r}")
    did, _ = kid.split("#", 1)
    if not did.startswith("did:"):
        raise DidError(f"kid does not reference a DID: {kid!r}")
    return did, kid


def _parse_verification_method_entry(m: dict) -> VerificationMethod:
    if not isinstance(m, dict):
        raise DidDocumentError("verificationMethod entry must be an object")
    method_id = m.get("id")
    method_type = m.get("type")
    controller = m.get("controller")
    if not isinstance(method_id, str) or not isinstance(method_type, str):
        raise DidDocumentError(f"verificationMethod missing id or type: {m}")
    if not isinstance(controller, str):
        raise DidDocumentError(f"verificationMethod missing controller: {m}")
    if method_type not in SUPPORTED_VERIFICATION_TYPES:
        raise DidDocumentError(f"unsupported verificationMethod type: {method_type}")

    has_b64 = isinstance(m.get("publicKeyBase64"), str)
    has_mb = isinstance(m.get("publicKeyMultibase"), str)
    has_jwk = isinstance(m.get("publicKeyJwk"), dict)
    formats_present = sum(1 for x in (has_b64, has_mb, has_jwk) if x)
    if formats_present == 0:
        raise DidDocumentError(
            f"verificationMethod must carry one of publicKeyBase64, "
            f"publicKeyMultibase, or publicKeyJwk: {m}"
        )
    if formats_present > 1:
        raise DidDocumentError(
            f"verificationMethod must carry exactly one of publicKeyBase64, "
            f"publicKeyMultibase, or publicKeyJwk; got {formats_present}: {m}"
        )

    if has_b64:
        if method_type == "JsonWebKey2020":
            raise DidDocumentError(
                "JsonWebKey2020 must carry publicKeyJwk, not publicKeyBase64"
            )
        # validate decodes and is the right length to fail fast.
        b64 = m["publicKeyBase64"]
        try:
            raw = base64.b64decode(b64, validate=True)
        except Exception as exc:
            raise DidDocumentError(f"publicKeyBase64 not valid base64: {exc}") from exc
        if len(raw) != 32:
            raise DidDocumentError(
                f"Ed25519 publicKeyBase64 must decode to 32 bytes, got {len(raw)}"
            )
        return VerificationMethod(
            id=method_id,
            type=method_type,
            controller=controller,
            public_key_b64=b64,
            key_format="publicKeyBase64",
        )

    if has_mb:
        if method_type not in ("Ed25519VerificationKey2020",):
            raise DidDocumentError(
                f"publicKeyMultibase requires Ed25519VerificationKey2020, "
                f"got {method_type!r}"
            )
        mb = m["publicKeyMultibase"]
        # Validate up-front so a malformed key raises at parse time.
        try:
            ed25519_pub_from_multibase(mb)
        except DidEncodingError as exc:
            raise DidDocumentError(f"invalid publicKeyMultibase: {exc}") from exc
        return VerificationMethod(
            id=method_id,
            type=method_type,
            controller=controller,
            public_key_multibase=mb,
            key_format="publicKeyMultibase",
        )

    # has_jwk
    if method_type != "JsonWebKey2020":
        raise DidDocumentError(
            f"publicKeyJwk requires JsonWebKey2020, got {method_type!r}"
        )
    jwk = m["publicKeyJwk"]
    try:
        ed25519_pub_from_jwk(jwk)
    except DidEncodingError as exc:
        raise DidDocumentError(f"invalid publicKeyJwk: {exc}") from exc
    return VerificationMethod(
        id=method_id,
        type=method_type,
        controller=controller,
        public_key_jwk=dict(jwk),
        key_format="publicKeyJwk",
    )


def parse_did_document(raw: object) -> DidDocument:
    if not isinstance(raw, dict):
        raise DidDocumentError("DID document must be a JSON object")
    did = raw.get("id")
    if not isinstance(did, str) or not did.startswith("did:"):
        raise DidDocumentError("DID document missing or invalid 'id'")
    methods_raw = raw.get("verificationMethod")
    if not isinstance(methods_raw, list) or not methods_raw:
        raise DidDocumentError(f"DID document {did} has no verificationMethod")
    methods: list[VerificationMethod] = []
    for m in methods_raw:
        methods.append(_parse_verification_method_entry(m))
    return DidDocument(id=did, verification_methods=tuple(methods))


class DidResolver(ABC):
    """Resolves a DID or kid to a public key.

    Implements the KeyResolver Protocol via `resolve()` and `resolve_revoked()`.
    Subclasses override `resolve_document()`.
    """

    @abstractmethod
    def resolve_document(self, did: str) -> DidDocument:
        ...

    def resolve(self, kid: str) -> Ed25519PublicKey:
        did, full_kid = parse_kid(kid)
        doc = self.resolve_document(did)
        method = doc.find_method(full_kid)
        if method.controller != did:
            raise DidKeyMismatch(
                f"verificationMethod controller {method.controller!r} does not match DID {did!r}"
            )
        return method.to_public_key()

    def resolve_revoked(self, kid: str) -> Optional[RevocationInfo]:
        return None


class MultiMethodResolver(DidResolver):
    """Dispatches resolution to a per-method resolver based on the DID prefix."""

    def __init__(self, **resolvers: DidResolver) -> None:
        self._by_method: dict[str, DidResolver] = dict(resolvers)

    def _pick(self, did: str) -> DidResolver:
        for method, resolver in self._by_method.items():
            if did.startswith(f"did:{method}:"):
                return resolver
        raise DidResolutionError(f"no resolver registered for: {did}")

    def resolve_document(self, did: str) -> DidDocument:
        return self._pick(did).resolve_document(did)
