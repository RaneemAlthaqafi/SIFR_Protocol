"""Encrypted-at-rest Ed25519 keystore with rotation and revocation metadata.

The keystore is a single JSON file. Private keys are encrypted with AES-256-GCM
using a key derived from the user passphrase via Argon2id. The kid is bound as
AAD so swapping ciphertexts between entries is rejected on decrypt.

Argon2id parameters travel with the file, so tests can use cheap params and
production keystores can use conservative ones without breaking compatibility.

This module does NOT claim HSM-grade or PKI-grade key management. See
docs/key_management.md for the threat model.
"""
from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import generate_keypair, private_key_to_b64, public_key_from_b64, public_key_to_b64
from .keyring_iface import RevocationInfo
from .utils import utc_now_iso

__all__ = [
    "KeyStoreError",
    "KeyEntry",
    "EncryptedFileKeyStore",
    "PRODUCTION_ARGON2_PARAMS",
    "TEST_ARGON2_PARAMS",
]

KEYSTORE_FILE_VERSION = 1
ARGON2_HASH_LEN = 32  # AES-256 key

PRODUCTION_ARGON2_PARAMS: dict[str, int] = {
    "time_cost": 3,
    "memory_cost": 65536,
    "parallelism": 1,
}

TEST_ARGON2_PARAMS: dict[str, int] = {
    "time_cost": 1,
    "memory_cost": 8,
    "parallelism": 1,
}


class KeyStoreError(Exception):
    pass


@dataclass(frozen=True)
class KeyEntry:
    kid: str
    public_key_b64: str
    created_at: str
    revoked_at: Optional[str] = None
    revoked_reason: Optional[str] = None


class EncryptedFileKeyStore:
    """Passphrase-protected on-disk Ed25519 keystore.

    Implements the `KeyResolver` Protocol via `resolve()` and `resolve_revoked()`.
    """

    def __init__(
        self,
        path: Path | str,
        passphrase: str | bytes,
        *,
        argon2_params: Optional[dict[str, int]] = None,
    ) -> None:
        self.path = Path(path)
        self._passphrase = passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase

        if self.path.exists():
            raw = json.loads(self.path.read_text("utf-8"))
            if raw.get("version") != KEYSTORE_FILE_VERSION:
                raise KeyStoreError(f"unsupported keystore version: {raw.get('version')}")
            self._argon2_params = raw["argon2"]
            self._salt = base64.b64decode(raw["salt"])
            self._entries: dict[str, dict[str, Any]] = {e["kid"]: e for e in raw["entries"]}
        else:
            self._argon2_params = dict(argon2_params or PRODUCTION_ARGON2_PARAMS)
            self._salt = os.urandom(16)
            self._entries = {}
            self._save()

        self._derived_key = hash_secret_raw(
            self._passphrase,
            self._salt,
            time_cost=self._argon2_params["time_cost"],
            memory_cost=self._argon2_params["memory_cost"],
            parallelism=self._argon2_params["parallelism"],
            hash_len=ARGON2_HASH_LEN,
            type=Type.ID,
        )

    def _save(self) -> None:
        out = {
            "version": KEYSTORE_FILE_VERSION,
            "argon2": self._argon2_params,
            "salt": base64.b64encode(self._salt).decode("ascii"),
            "entries": list(self._entries.values()),
        }
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(out, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def add_keypair(self, kid: str, private_key: Ed25519PrivateKey) -> KeyEntry:
        if kid in self._entries:
            raise KeyStoreError(f"kid already exists: {kid}")
        priv_raw = base64.b64decode(private_key_to_b64(private_key))
        nonce = os.urandom(12)
        cipher = AESGCM(self._derived_key)
        ct = cipher.encrypt(nonce, priv_raw, kid.encode("utf-8"))
        entry = {
            "kid": kid,
            "public_key": public_key_to_b64(private_key.public_key()),
            "created_at": utc_now_iso(),
            "revoked_at": None,
            "revoked_reason": None,
            "ciphertext": base64.b64encode(ct).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
        }
        self._entries[kid] = entry
        self._save()
        return KeyEntry(
            kid=kid,
            public_key_b64=entry["public_key"],
            created_at=entry["created_at"],
        )

    def generate_keypair(self, kid: str) -> Ed25519PublicKey:
        priv, pub = generate_keypair()
        self.add_keypair(kid, priv)
        return pub

    def load_private_key(self, kid: str) -> Ed25519PrivateKey:
        entry = self._require_entry(kid)
        cipher = AESGCM(self._derived_key)
        try:
            priv_raw = cipher.decrypt(
                base64.b64decode(entry["nonce"]),
                base64.b64decode(entry["ciphertext"]),
                kid.encode("utf-8"),
            )
        except Exception as exc:
            raise KeyStoreError(
                f"decryption failed for kid {kid} (wrong passphrase or tampered file)"
            ) from exc
        return Ed25519PrivateKey.from_private_bytes(priv_raw)

    def public_key(self, kid: str) -> Ed25519PublicKey:
        entry = self._require_entry(kid)
        return public_key_from_b64(entry["public_key"])

    def list_kids(self) -> list[str]:
        return list(self._entries.keys())

    def revoke(self, kid: str, reason: str) -> None:
        entry = self._require_entry(kid)
        if entry["revoked_at"]:
            return
        entry["revoked_at"] = utc_now_iso()
        entry["revoked_reason"] = reason
        self._save()

    def _require_entry(self, kid: str) -> dict[str, Any]:
        if kid not in self._entries:
            raise KeyStoreError(f"unknown kid: {kid}")
        return self._entries[kid]

    def resolve(self, kid: str) -> Ed25519PublicKey:
        return self.public_key(kid)

    def resolve_revoked(self, kid: str) -> Optional[RevocationInfo]:
        if kid not in self._entries:
            return None
        entry = self._entries[kid]
        if not entry["revoked_at"]:
            return None
        return RevocationInfo(
            kid=kid,
            reason=entry.get("revoked_reason") or "",
            revoked_at=entry["revoked_at"],
        )
