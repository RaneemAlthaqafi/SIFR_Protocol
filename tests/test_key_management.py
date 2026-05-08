from __future__ import annotations

import json

import pytest

from sifr.crypto import public_key_to_b64, sign_message, verify_message
from sifr.key_management import (
    PRODUCTION_ARGON2_PARAMS,
    TEST_ARGON2_PARAMS,
    EncryptedFileKeyStore,
    KeyStoreError,
)


def _new_store(tmp_path, passphrase="correct-horse-battery"):
    return EncryptedFileKeyStore(tmp_path / "keys.json", passphrase, argon2_params=TEST_ARGON2_PARAMS)


def test_create_and_reload(tmp_path):
    ks1 = _new_store(tmp_path)
    pub = ks1.generate_keypair("did:sifr:alice#key-1")

    ks2 = _new_store(tmp_path)
    assert public_key_to_b64(ks2.public_key("did:sifr:alice#key-1")) == public_key_to_b64(pub)


def test_private_key_roundtrip_signs_and_verifies(tmp_path):
    ks = _new_store(tmp_path)
    pub = ks.generate_keypair("did:sifr:alice#key-1")
    priv = ks.load_private_key("did:sifr:alice#key-1")

    msg = {"sender_id": "did:sifr:alice", "type": "Hello", "payload": {}}
    signed = sign_message(msg, priv, "did:sifr:alice#key-1")
    assert verify_message(signed, pub)


def test_wrong_passphrase_rejected(tmp_path):
    ks = _new_store(tmp_path, "right")
    ks.generate_keypair("did:sifr:alice#key-1")

    ks2 = _new_store(tmp_path, "wrong")
    with pytest.raises(KeyStoreError, match="decryption failed"):
        ks2.load_private_key("did:sifr:alice#key-1")


def test_unknown_kid(tmp_path):
    ks = _new_store(tmp_path)
    with pytest.raises(KeyStoreError, match="unknown kid"):
        ks.public_key("did:sifr:bob#key-1")
    with pytest.raises(KeyStoreError, match="unknown kid"):
        ks.load_private_key("did:sifr:bob#key-1")


def test_duplicate_kid_rejected(tmp_path):
    ks = _new_store(tmp_path)
    ks.generate_keypair("did:sifr:alice#key-1")
    with pytest.raises(KeyStoreError, match="already exists"):
        ks.generate_keypair("did:sifr:alice#key-1")


def test_multiple_keys_per_agent(tmp_path):
    ks = _new_store(tmp_path)
    ks.generate_keypair("did:sifr:alice#key-1")
    ks.generate_keypair("did:sifr:alice#key-2")
    assert sorted(ks.list_kids()) == ["did:sifr:alice#key-1", "did:sifr:alice#key-2"]


def test_rotation_old_signature_still_verifies_via_resolver(tmp_path):
    ks = _new_store(tmp_path)
    ks.generate_keypair("did:sifr:alice#key-1")
    priv1 = ks.load_private_key("did:sifr:alice#key-1")

    msg = {"sender_id": "did:sifr:alice", "type": "Hello", "payload": {}}
    signed_v1 = sign_message(msg, priv1, "did:sifr:alice#key-1")

    ks.generate_keypair("did:sifr:alice#key-2")

    assert verify_message(signed_v1, ks)


def test_revocation_metadata(tmp_path):
    ks = _new_store(tmp_path)
    ks.generate_keypair("did:sifr:alice#key-1")
    assert ks.resolve_revoked("did:sifr:alice#key-1") is None

    ks.revoke("did:sifr:alice#key-1", "compromise suspected")

    info = ks.resolve_revoked("did:sifr:alice#key-1")
    assert info is not None
    assert info.kid == "did:sifr:alice#key-1"
    assert info.reason == "compromise suspected"
    assert info.revoked_at


def test_revocation_is_idempotent(tmp_path):
    ks = _new_store(tmp_path)
    ks.generate_keypair("did:sifr:alice#key-1")
    ks.revoke("did:sifr:alice#key-1", "first")
    first = ks.resolve_revoked("did:sifr:alice#key-1")
    ks.revoke("did:sifr:alice#key-1", "second")
    second = ks.resolve_revoked("did:sifr:alice#key-1")
    assert first == second


def test_resolve_unknown_kid_returns_none_for_revoked_query(tmp_path):
    ks = _new_store(tmp_path)
    assert ks.resolve_revoked("did:sifr:nobody#key-1") is None


def test_keystore_file_does_not_contain_raw_private_key(tmp_path):
    ks = _new_store(tmp_path)
    ks.generate_keypair("did:sifr:alice#key-1")
    priv = ks.load_private_key("did:sifr:alice#key-1")

    raw_priv_b64 = base64_priv = __import__(
        "sifr.crypto", fromlist=["private_key_to_b64"]
    ).private_key_to_b64(priv)
    file_text = (tmp_path / "keys.json").read_text("utf-8")
    assert raw_priv_b64 not in file_text


def test_tampered_ciphertext_rejected(tmp_path):
    ks = _new_store(tmp_path)
    ks.generate_keypair("did:sifr:alice#key-1")
    raw = json.loads((tmp_path / "keys.json").read_text("utf-8"))
    raw["entries"][0]["ciphertext"] = "AAAA" + raw["entries"][0]["ciphertext"][4:]
    (tmp_path / "keys.json").write_text(json.dumps(raw), encoding="utf-8")

    ks2 = _new_store(tmp_path)
    with pytest.raises(KeyStoreError, match="decryption failed"):
        ks2.load_private_key("did:sifr:alice#key-1")


def test_kid_aad_binding_prevents_ciphertext_swap(tmp_path):
    ks = _new_store(tmp_path)
    ks.generate_keypair("did:sifr:alice#key-1")
    ks.generate_keypair("did:sifr:bob#key-1")

    raw = json.loads((tmp_path / "keys.json").read_text("utf-8"))
    alice = next(e for e in raw["entries"] if e["kid"] == "did:sifr:alice#key-1")
    bob = next(e for e in raw["entries"] if e["kid"] == "did:sifr:bob#key-1")
    alice["ciphertext"], bob["ciphertext"] = bob["ciphertext"], alice["ciphertext"]
    alice["nonce"], bob["nonce"] = bob["nonce"], alice["nonce"]
    (tmp_path / "keys.json").write_text(json.dumps(raw), encoding="utf-8")

    ks2 = _new_store(tmp_path)
    with pytest.raises(KeyStoreError, match="decryption failed"):
        ks2.load_private_key("did:sifr:alice#key-1")


def test_production_argon2_params_are_conservative():
    assert PRODUCTION_ARGON2_PARAMS["time_cost"] >= 3
    assert PRODUCTION_ARGON2_PARAMS["memory_cost"] >= 65536
