from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        raise ValueError("timestamp MUST include timezone")
    return dt.astimezone(timezone.utc)


def new_message_id() -> str:
    return f"msg_{uuid4().hex}"


def new_session_id() -> str:
    return f"sess_{uuid4().hex}"


def new_capability_id() -> str:
    return f"cap_{uuid4().hex}"
