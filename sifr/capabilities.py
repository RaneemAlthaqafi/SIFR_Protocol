from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from typing import Any

from typing import Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .crypto import sign_message, verify_message
from .errors import CapabilityError, UnauthorizedAction
from .keyring_iface import KeyResolver
from .messages import create_message
from .utils import new_capability_id, parse_utc, utc_now_iso

IssuerKey = Union[Ed25519PublicKey, KeyResolver]


class CapabilityStore:
    def __init__(self) -> None:
        self._grants: dict[str, dict[str, Any]] = {}
        self._usage: dict[str, int] = {}

    def add(self, grant_message: dict[str, Any]) -> None:
        payload = grant_message.get("payload", {})
        cap_id = payload.get("capability_id")
        if not cap_id:
            raise CapabilityError("grant missing capability_id")
        self._grants[cap_id] = copy.deepcopy(grant_message)
        self._usage.setdefault(cap_id, 0)

    def get(self, capability_id: str) -> dict[str, Any]:
        try:
            return self._grants[capability_id]
        except KeyError as exc:
            raise CapabilityError("unknown capability") from exc

    def usage(self, capability_id: str) -> int:
        return self._usage.get(capability_id, 0)

    def consume(self, capability_id: str) -> None:
        self._usage[capability_id] = self.usage(capability_id) + 1


def create_capability_grant(
    issuer: str,
    subject: str,
    actions: list[str],
    resource_scope: list[str],
    *,
    issuer_private_key: Ed25519PrivateKey,
    receiver_id: str,
    session_id: str,
    expires_at: str,
    max_calls: int = 5,
    max_payload_bytes: int = 10000,
    allow_delegation: bool = False,
    capability_id: str | None = None,
) -> dict[str, Any]:
    cap_id = capability_id or new_capability_id()
    payload = {
        "capability_id": cap_id,
        "issuer": issuer,
        "subject": subject,
        "actions": actions,
        "resource_scope": resource_scope,
        "issued_at": utc_now_iso(),
        "expires_at": expires_at,
        "budget": {"max_calls": max_calls, "max_payload_bytes": max_payload_bytes},
        "constraints": {"allow_delegation": allow_delegation},
    }
    msg = create_message("CapabilityGrant", issuer, receiver_id, payload, session_id=session_id, capability_id=cap_id)
    return sign_message(msg, issuer_private_key, f"{issuer}#key-1")


def verify_capability_grant(grant_message: dict[str, Any], issuer_public_key: IssuerKey) -> bool:
    if grant_message.get("type") != "CapabilityGrant":
        raise CapabilityError("not a CapabilityGrant")
    verify_message(grant_message, issuer_public_key)
    payload = grant_message.get("payload", {})
    if payload.get("issuer") != grant_message.get("sender_id"):
        raise CapabilityError("issuer does not match signer sender_id")
    for field in ["capability_id", "subject", "actions", "resource_scope", "issued_at", "expires_at", "budget", "constraints"]:
        if field not in payload:
            raise CapabilityError(f"grant missing {field}")
    return True


def authorize_action(
    action_message: dict[str, Any],
    grant_message: dict[str, Any],
    issuer_public_key: IssuerKey,
    store: CapabilityStore,
    *,
    consume: bool = True,
    now: datetime | None = None,
) -> bool:
    verify_capability_grant(grant_message, issuer_public_key)
    payload = grant_message["payload"]
    cap_id = payload["capability_id"]
    if action_message.get("capability_id") != cap_id:
        raise UnauthorizedAction("CAPABILITY_MISMATCH")
    if payload["subject"] != action_message.get("sender_id"):
        raise UnauthorizedAction("WRONG_SUBJECT")
    action = action_message.get("payload", {}).get("action")
    if action not in payload["actions"]:
        raise UnauthorizedAction("UNAUTHORIZED_ACTION")
    expires = parse_utc(payload["expires_at"])
    if (now or datetime.now(timezone.utc)) >= expires:
        raise UnauthorizedAction("EXPIRED_CAPABILITY")
    encoded_payload = json.dumps(action_message.get("payload", {}), sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded_payload) > int(payload["budget"].get("max_payload_bytes", 0)):
        raise UnauthorizedAction("PAYLOAD_BUDGET_EXCEEDED")
    if store.usage(cap_id) >= int(payload["budget"].get("max_calls", 0)):
        raise UnauthorizedAction("CALL_BUDGET_EXCEEDED")
    if action_message.get("payload", {}).get("delegate_to") and not payload.get("constraints", {}).get("allow_delegation", False):
        raise UnauthorizedAction("DELEGATION_NOT_ALLOWED")
    if consume:
        store.consume(cap_id)
    return True
