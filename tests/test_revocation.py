from __future__ import annotations

import pytest

from sifr.crypto import generate_keypair
from sifr.errors import RevocationError, SignatureError
from sifr.revocation import RevocationRegistry


def _new_registry(tmp_path=None):
    priv, pub = generate_keypair()
    issuer = "did:sifr:alice"
    kid = f"{issuer}#key-1"
    store = (tmp_path / "revs.jsonl") if tmp_path else None
    reg = RevocationRegistry(
        issuer=issuer,
        issuer_kid=kid,
        issuer_private_key=priv,
        verifier_key=pub,
        store_path=store,
    )
    return reg, pub


def test_revoke_returns_signed_message():
    reg, _ = _new_registry()
    rev = reg.revoke("cap_001", "compromise")
    assert rev["type"] == "CapabilityRevocation"
    assert rev["payload"]["capability_id"] == "cap_001"
    assert rev["payload"]["reason"] == "compromise"
    assert "signature" in rev
    assert rev["signature"]["alg"] == "Ed25519"


def test_is_revoked_returns_entry():
    reg, _ = _new_registry()
    reg.revoke("cap_001", "x")
    info = reg.is_revoked("cap_001")
    assert info is not None
    assert info["payload"]["capability_id"] == "cap_001"


def test_is_revoked_returns_none_for_unknown():
    reg, _ = _new_registry()
    assert reg.is_revoked("cap_999") is None


def test_revoke_is_idempotent():
    reg, _ = _new_registry()
    first = reg.revoke("cap_001", "first")
    second = reg.revoke("cap_001", "second")
    assert first == second
    assert reg.is_revoked("cap_001")["payload"]["reason"] == "first"


def test_revoke_without_private_key_fails():
    _, pub = generate_keypair()
    reg = RevocationRegistry(
        issuer="did:sifr:alice",
        issuer_kid="did:sifr:alice#key-1",
        issuer_private_key=None,
        verifier_key=pub,
    )
    with pytest.raises(RevocationError, match="no issuer_private_key"):
        reg.revoke("cap_x", "reason")


def test_persistence_roundtrip(tmp_path):
    reg, pub = _new_registry(tmp_path)
    reg.revoke("cap_001", "first")
    reg.revoke("cap_002", "second")

    reg2 = RevocationRegistry(
        issuer="did:sifr:alice",
        issuer_kid="did:sifr:alice#key-1",
        verifier_key=pub,
        store_path=tmp_path / "revs.jsonl",
    )
    assert reg2.is_revoked("cap_001") is not None
    assert reg2.is_revoked("cap_002") is not None


def test_persistence_tampered_record_rejected(tmp_path):
    reg, pub = _new_registry(tmp_path)
    reg.revoke("cap_001", "first")
    path = tmp_path / "revs.jsonl"
    text = path.read_text("utf-8")
    tampered = text.replace("cap_001", "cap_999")
    path.write_text(tampered, encoding="utf-8")

    with pytest.raises(SignatureError):
        RevocationRegistry(
            issuer="did:sifr:alice",
            issuer_kid="did:sifr:alice#key-1",
            verifier_key=pub,
            store_path=path,
        )


def test_load_without_verifier_fails(tmp_path):
    reg, _ = _new_registry(tmp_path)
    reg.revoke("cap_001", "x")
    with pytest.raises(RevocationError, match="verifier_key"):
        RevocationRegistry(
            issuer="did:sifr:alice",
            issuer_kid="did:sifr:alice#key-1",
            verifier_key=None,
            store_path=tmp_path / "revs.jsonl",
        )


def test_add_external_entry_verifies():
    reg1, pub = _new_registry()
    rev = reg1.revoke("cap_001", "x")

    reg2 = RevocationRegistry(
        issuer="did:sifr:alice",
        issuer_kid="did:sifr:alice#key-1",
        verifier_key=pub,
    )
    reg2.add_entry(rev)
    assert reg2.is_revoked("cap_001") is not None


def test_add_entry_with_wrong_type_rejected():
    _, pub = generate_keypair()
    reg = RevocationRegistry(
        issuer="did:sifr:alice",
        issuer_kid="did:sifr:alice#key-1",
        verifier_key=pub,
    )
    bogus = {"type": "Hello", "payload": {"capability_id": "x"}}
    with pytest.raises(RevocationError, match="not a CapabilityRevocation"):
        reg.add_entry(bogus)


def test_add_entry_with_bad_signature_rejected():
    reg1, pub = _new_registry()
    rev = reg1.revoke("cap_001", "x")
    rev["payload"]["capability_id"] = "cap_evil"

    reg2 = RevocationRegistry(
        issuer="did:sifr:alice",
        issuer_kid="did:sifr:alice#key-1",
        verifier_key=pub,
    )
    with pytest.raises(SignatureError):
        reg2.add_entry(rev)


def test_export_returns_all_entries():
    reg, _ = _new_registry()
    reg.revoke("cap_001", "a")
    reg.revoke("cap_002", "b")
    exported = reg.export()
    assert len(exported) == 2
    cap_ids = {e["payload"]["capability_id"] for e in exported}
    assert cap_ids == {"cap_001", "cap_002"}
