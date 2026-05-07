from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


@dataclass(frozen=True)
class RevocationInfo:
    kid: str
    reason: str
    revoked_at: str


@runtime_checkable
class KeyResolver(Protocol):
    def resolve(self, kid: str) -> Ed25519PublicKey: ...

    def resolve_revoked(self, kid: str) -> Optional[RevocationInfo]: ...
