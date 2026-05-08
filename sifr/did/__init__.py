"""DID resolution for SIFR.

Two methods are implemented:
- did:web (preferred) — fetches DID documents over HTTP/HTTPS.
- did:sifr (local fallback) — reads documents from a local directory.

Both resolvers implement the KeyResolver Protocol from keyring_iface, so they
can be passed directly to crypto.verify_message and capabilities.authorize_action.

This package does NOT claim full W3C DID interoperability. It supports
verificationMethod entries with type Ed25519VerificationKey2020 (or 2018) using
the publicKeyBase64 field. Other key types and JSON-LD context processing are
out of scope for v0.2. See docs/did_method.md.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..crypto import public_key_from_b64
from ..errors import SIFRError
from ..keyring_iface import RevocationInfo

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

SUPPORTED_VERIFICATION_TYPES = frozenset(
    {"Ed25519VerificationKey2020", "Ed25519VerificationKey2018"}
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
    id: str
    type: str
    controller: str
    public_key_b64: str

    def to_public_key(self) -> Ed25519PublicKey:
        return public_key_from_b64(self.public_key_b64)


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
        if not isinstance(m, dict):
            raise DidDocumentError("verificationMethod entry must be an object")
        method_id = m.get("id")
        method_type = m.get("type")
        controller = m.get("controller")
        public_key_b64 = m.get("publicKeyBase64")
        if not isinstance(method_id, str) or not isinstance(method_type, str):
            raise DidDocumentError(f"verificationMethod missing id or type: {m}")
        if not isinstance(controller, str) or not isinstance(public_key_b64, str):
            raise DidDocumentError(f"verificationMethod missing controller or publicKeyBase64: {m}")
        if method_type not in SUPPORTED_VERIFICATION_TYPES:
            raise DidDocumentError(f"unsupported verificationMethod type: {method_type}")
        methods.append(
            VerificationMethod(
                id=method_id,
                type=method_type,
                controller=controller,
                public_key_b64=public_key_b64,
            )
        )
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
