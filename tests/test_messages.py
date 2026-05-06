import copy
import pytest

from sifr.crypto import message_to_canonical_bytes, sha256_cid
from sifr.errors import MessageValidationError
from sifr.messages import create_message


def test_deterministic_serialization():
    msg = create_message("Action", "did:sifr:a", "did:sifr:b", {"args": {"b": 3, "a": 2}, "action": "tool.calculator.add"}, session_id="s", message_id="m", timestamp="2026-01-01T00:00:00Z")
    assert message_to_canonical_bytes(msg) == message_to_canonical_bytes(copy.deepcopy(msg))


def test_required_fields():
    msg = create_message("Hello", "did:sifr:a", "did:sifr:b", {"agent_name": "A"})
    del msg["message_id"]
    with pytest.raises(MessageValidationError):
        from sifr.messages import validate_message
        validate_message(msg)


def test_invalid_message_type_rejected():
    with pytest.raises(MessageValidationError):
        create_message("Nope", "did:sifr:a", "did:sifr:b", {})


def test_stable_cid():
    msg = create_message("Thought", "did:sifr:a", "did:sifr:b", {"content": "x", "confidence": 1}, session_id="s", message_id="m", timestamp="2026-01-01T00:00:00Z")
    assert sha256_cid(msg) == sha256_cid(copy.deepcopy(msg))
