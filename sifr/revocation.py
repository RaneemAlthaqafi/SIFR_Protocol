"""Capability revocation registry.

Each revocation is a `CapabilityRevocation` SIFR message, signed by the issuer
of the original capability. The registry persists revocations as JSONL and
re-verifies signatures on load — tampered entries are rejected at load time,
not silently accepted.

Lookups are O(1) by capability_id. Use the registry in `authorize_action` to
reject revoked grants before any action is dispatched.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .crypto import sign_message, verify_message
from .errors import RevocationError
from .keyring_iface import KeyResolver
from .messages import create_message
from .utils import utc_now_iso

IssuerKey = Union[Ed25519PublicKey, KeyResolver]

__all__ = ["RevocationRegistry"]


class RevocationRegistry:
    def __init__(
        self,
        *,
        issuer: str,
        issuer_kid: str,
        issuer_private_key: Optional[Ed25519PrivateKey] = None,
        verifier_key: Optional[IssuerKey] = None,
        store_path: Optional[Path | str] = None,
    ) -> None:
        self.issuer = issuer
        self.issuer_kid = issuer_kid
        self.issuer_private_key = issuer_private_key
        self.verifier_key = verifier_key
        self.store_path = Path(store_path) if store_path is not None else None
        self._entries: dict[str, dict[str, Any]] = {}
        if self.store_path is not None and self.store_path.exists():
            self._load()

    def revoke(
        self,
        capability_id: str,
        reason: str,
        *,
        receiver_id: str = "*",
        session_id: Optional[str] = None,
    ) -> dict[str, Any]:
        if self.issuer_private_key is None:
            raise RevocationError("registry has no issuer_private_key; cannot issue revocations")
        if capability_id in self._entries:
            return self._entries[capability_id]
        payload = {
            "capability_id": capability_id,
            "reason": reason,
            "revoked_at": utc_now_iso(),
        }
        msg = create_message(
            "CapabilityRevocation",
            self.issuer,
            receiver_id,
            payload,
            session_id=session_id,
            capability_id=capability_id,
        )
        signed = sign_message(msg, self.issuer_private_key, self.issuer_kid)
        self._entries[capability_id] = signed
        if self.store_path is not None:
            self._append(signed)
        return signed

    def add_entry(self, signed_revocation: dict[str, Any]) -> None:
        if self.verifier_key is None:
            raise RevocationError("no verifier_key configured; cannot validate external revocations")
        if signed_revocation.get("type") != "CapabilityRevocation":
            raise RevocationError("not a CapabilityRevocation message")
        verify_message(signed_revocation, self.verifier_key)
        cap_id = signed_revocation["payload"]["capability_id"]
        self._entries[cap_id] = signed_revocation
        if self.store_path is not None:
            self._append(signed_revocation)

    def is_revoked(self, capability_id: str) -> Optional[dict[str, Any]]:
        return self._entries.get(capability_id)

    def reload(self) -> None:
        """Re-read the on-disk JSONL log into the in-memory map.

        Useful when another process has appended revocations: this verifier
        instance was started before that write, so its cache is stale.
        Signature verification is performed for every entry, so a tampered
        log is rejected at reload time rather than silently accepted.
        """
        if self.store_path is None:
            return
        # Drop in-memory cache and re-load from disk.
        self._entries = {}
        if self.store_path.exists():
            self._load()

    def export(self) -> list[dict[str, Any]]:
        return list(self._entries.values())

    def _append(self, signed: dict[str, Any]) -> None:
        assert self.store_path is not None
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        with self.store_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(signed, sort_keys=True) + "\n")

    def _load(self) -> None:
        if self.verifier_key is None:
            raise RevocationError(
                "cannot load persistent registry without verifier_key (signatures must be re-checked)"
            )
        assert self.store_path is not None
        with self.store_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                signed = json.loads(line)
                if signed.get("type") != "CapabilityRevocation":
                    raise RevocationError(f"non-revocation entry in registry: {signed.get('type')}")
                verify_message(signed, self.verifier_key)
                cap_id = signed["payload"]["capability_id"]
                self._entries[cap_id] = signed
