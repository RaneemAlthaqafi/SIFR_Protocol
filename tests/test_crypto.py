import copy
import pytest

from sifr.crypto import generate_keypair, sign_message, verify_message
from sifr.errors import SignatureError
from sifr.messages import create_message


def test_valid_signature_verifies():
    priv, pub = generate_keypair()
    msg = sign_message(create_message("Thought", "did:sifr:a", "did:sifr:b", {"content": "x", "confidence": 0.9}), priv)
    assert verify_message(msg, pub)


def test_tampered_payload_fails():
    priv, pub = generate_keypair()
    msg = sign_message(create_message("Thought", "did:sifr:a", "did:sifr:b", {"content": "x", "confidence": 0.9}), priv)
    msg["payload"]["content"] = "y"
    with pytest.raises(SignatureError):
        verify_message(msg, pub)


def test_tampered_sender_fails():
    priv, pub = generate_keypair()
    msg = sign_message(create_message("Thought", "did:sifr:a", "did:sifr:b", {"content": "x", "confidence": 0.9}), priv)
    msg["sender_id"] = "did:sifr:attacker"
    with pytest.raises(SignatureError):
        verify_message(msg, pub)


def test_wrong_public_key_fails():
    priv, _ = generate_keypair()
    _, wrong_pub = generate_keypair()
    msg = sign_message(create_message("Thought", "did:sifr:a", "did:sifr:b", {"content": "x", "confidence": 0.9}), priv)
    with pytest.raises(SignatureError):
        verify_message(msg, wrong_pub)


def test_missing_signature_fails():
    _, pub = generate_keypair()
    msg = create_message("Thought", "did:sifr:a", "did:sifr:b", {"content": "x", "confidence": 0.9})
    with pytest.raises(SignatureError):
        verify_message(msg, pub)
