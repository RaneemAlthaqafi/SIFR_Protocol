from __future__ import annotations

from typing import Any

from .crypto import sha256_cid
from .errors import MessageValidationError
from .utils import new_message_id, new_session_id, utc_now_iso, parse_utc

VERSION = "sifr/0.1"
MESSAGE_TYPES = {
    "Hello",
    "CapabilityOffer",
    "CapabilityGrant",
    "CapabilityRevocation",
    "Thought",
    "Action",
    "ToolUse",
    "Observation",
    "Result",
    "Critique",
    "Error",
    "TensorFrame",
}


def create_message(
    message_type: str,
    sender_id: str,
    receiver_id: str,
    payload: dict[str, Any],
    *,
    session_id: str | None = None,
    parents: list[str] | None = None,
    capability_id: str | None = None,
    message_id: str | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    if message_type not in MESSAGE_TYPES:
        raise MessageValidationError(f"invalid message type: {message_type}")
    msg = {
        "version": VERSION,
        "message_id": message_id or new_message_id(),
        "session_id": session_id or new_session_id(),
        "type": message_type,
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "timestamp": timestamp or utc_now_iso(),
        "parents": parents or [],
        "capability_id": capability_id,
        "payload": payload,
    }
    validate_message(msg)
    return msg


def validate_message(message: dict[str, Any]) -> None:
    required = ["version", "message_id", "session_id", "type", "sender_id", "receiver_id", "timestamp", "parents", "payload"]
    missing = [field for field in required if field not in message]
    if missing:
        raise MessageValidationError(f"missing required fields: {missing}")
    if message["version"] != VERSION:
        raise MessageValidationError("unsupported version")
    if message["type"] not in MESSAGE_TYPES:
        raise MessageValidationError("invalid message type")
    if not isinstance(message["parents"], list):
        raise MessageValidationError("parents MUST be a list")
    parse_utc(message["timestamp"])
    if message["type"] in {"Action", "ToolUse"} and message.get("payload", {}).get("requires_auth", False):
        if not message.get("capability_id"):
            raise MessageValidationError("capability_id required for authorized Action/ToolUse")


def stable_cid(message: dict[str, Any]) -> str:
    validate_message(message)
    return sha256_cid(message)
