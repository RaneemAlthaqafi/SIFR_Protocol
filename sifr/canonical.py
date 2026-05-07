from __future__ import annotations

import copy
import json
from typing import Any


def _without_signature(obj: dict[str, Any]) -> dict[str, Any]:
    clone = copy.deepcopy(obj)
    clone.pop("signature", None)
    return clone


def canonical_json(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def message_to_canonical_bytes(message: dict[str, Any]) -> bytes:
    return canonical_json(_without_signature(message))
