from __future__ import annotations

import json
from pathlib import Path

import pytest

from sifr.crypto import generate_keypair, public_key_to_b64, sign_message, verify_message
from sifr.did import (
    DidDocumentError,
    DidError,
    DidKeyMismatch,
    DidResolutionError,
    MultiMethodResolver,
    parse_kid,
)
from sifr.did.did_sifr import DidSifrResolver
from sifr.did.did_web import DidWebResolver

from did_web_server import DidWebFixture


def _write_did_sifr_doc(root: Path, did: str, kid: str, public_key_b64: str) -> None:
    name = did[len("did:sifr:"):]
    doc = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": kid,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyBase64": public_key_b64,
            }
        ],
    }
    (root / f"{name}.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")


# ---------- did:sifr ----------

def test_did_sifr_resolves_and_verifies(tmp_path):
    priv, pub = generate_keypair()
    did = "did:sifr:alice"
    kid = f"{did}#key-1"
    _write_did_sifr_doc(tmp_path, did, kid, public_key_to_b64(pub))

    resolver = DidSifrResolver(tmp_path)
    assert public_key_to_b64(resolver.resolve(kid)) == public_key_to_b64(pub)

    msg = {"sender_id": did, "type": "Hello", "payload": {}}
    signed = sign_message(msg, priv, kid)
    assert verify_message(signed, resolver)


def test_did_sifr_unknown_doc(tmp_path):
    resolver = DidSifrResolver(tmp_path)
    with pytest.raises(DidResolutionError, match="not found"):
        resolver.resolve("did:sifr:nobody#key-1")


def test_did_sifr_rejects_other_methods(tmp_path):
    resolver = DidSifrResolver(tmp_path)
    with pytest.raises(DidResolutionError, match="not a did:sifr"):
        resolver.resolve_document("did:web:example.com")


def test_did_sifr_path_traversal_rejected(tmp_path):
    resolver = DidSifrResolver(tmp_path)
    with pytest.raises(DidResolutionError, match="invalid did:sifr name"):
        resolver.resolve("did:sifr:../etc/passwd#key-1")


def test_did_sifr_malformed_json(tmp_path):
    (tmp_path / "broken.json").write_text("{ not valid json", encoding="utf-8")
    resolver = DidSifrResolver(tmp_path)
    with pytest.raises(DidResolutionError, match="not valid JSON"):
        resolver.resolve("did:sifr:broken#key-1")


def test_did_sifr_missing_vmethod(tmp_path):
    (tmp_path / "alice.json").write_text(
        json.dumps({"id": "did:sifr:alice"}), encoding="utf-8"
    )
    resolver = DidSifrResolver(tmp_path)
    with pytest.raises(DidDocumentError, match="no verificationMethod"):
        resolver.resolve("did:sifr:alice#key-1")


def test_did_sifr_wrong_id_in_doc(tmp_path):
    (tmp_path / "alice.json").write_text(
        json.dumps({
            "id": "did:sifr:bob",
            "verificationMethod": [{
                "id": "did:sifr:bob#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:sifr:bob",
                "publicKeyBase64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            }],
        }),
        encoding="utf-8",
    )
    resolver = DidSifrResolver(tmp_path)
    with pytest.raises(DidResolutionError, match="declares id="):
        resolver.resolve("did:sifr:alice#key-1")


def test_did_sifr_kid_not_in_doc(tmp_path):
    """Trap-acceptance test: doc with valid syntax but the requested kid is absent."""
    priv, pub = generate_keypair()
    did = "did:sifr:alice"
    _write_did_sifr_doc(tmp_path, did, f"{did}#key-1", public_key_to_b64(pub))

    resolver = DidSifrResolver(tmp_path)
    with pytest.raises(DidKeyMismatch):
        resolver.resolve(f"{did}#key-2")


def test_did_sifr_unsupported_vmethod_type(tmp_path):
    (tmp_path / "alice.json").write_text(
        json.dumps({
            "id": "did:sifr:alice",
            "verificationMethod": [{
                "id": "did:sifr:alice#key-1",
                "type": "RsaVerificationKey2018",
                "controller": "did:sifr:alice",
                "publicKeyBase64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            }],
        }),
        encoding="utf-8",
    )
    resolver = DidSifrResolver(tmp_path)
    with pytest.raises(DidDocumentError, match="unsupported"):
        resolver.resolve("did:sifr:alice#key-1")


def test_did_sifr_controller_mismatch_rejected(tmp_path):
    (tmp_path / "alice.json").write_text(
        json.dumps({
            "id": "did:sifr:alice",
            "verificationMethod": [{
                "id": "did:sifr:alice#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:sifr:eve",
                "publicKeyBase64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            }],
        }),
        encoding="utf-8",
    )
    resolver = DidSifrResolver(tmp_path)
    with pytest.raises(DidKeyMismatch, match="controller"):
        resolver.resolve("did:sifr:alice#key-1")


# ---------- did:web ----------

def test_did_web_resolves_and_verifies():
    priv, pub = generate_keypair()
    with DidWebFixture() as fixture:
        did = fixture.did_for_path()
        kid = f"{did}#key-1"
        fixture.serve_document(
            "/.well-known/did.json",
            {
                "id": did,
                "verificationMethod": [{
                    "id": kid,
                    "type": "Ed25519VerificationKey2020",
                    "controller": did,
                    "publicKeyBase64": public_key_to_b64(pub),
                }],
            },
        )
        resolver = DidWebResolver(scheme="http")
        assert public_key_to_b64(resolver.resolve(kid)) == public_key_to_b64(pub)

        msg = {"sender_id": did, "type": "Hello", "payload": {}}
        signed = sign_message(msg, priv, kid)
        assert verify_message(signed, resolver)


def test_did_web_404():
    with DidWebFixture() as fixture:
        did = fixture.did_for_path()
        resolver = DidWebResolver(scheme="http")
        with pytest.raises(DidResolutionError, match="HTTP 404"):
            resolver.resolve(f"{did}#key-1")


def test_did_web_malformed_json():
    with DidWebFixture() as fixture:
        did = fixture.did_for_path()
        fixture.serve_document("/.well-known/did.json", DidWebFixture.MALFORMED)
        resolver = DidWebResolver(scheme="http")
        with pytest.raises(DidResolutionError, match="not valid JSON"):
            resolver.resolve(f"{did}#key-1")


def test_did_web_id_mismatch():
    with DidWebFixture() as fixture:
        did = fixture.did_for_path()
        fixture.serve_document(
            "/.well-known/did.json",
            {
                "id": "did:web:other.example",
                "verificationMethod": [{
                    "id": "did:web:other.example#key-1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": "did:web:other.example",
                    "publicKeyBase64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                }],
            },
        )
        resolver = DidWebResolver(scheme="http")
        with pytest.raises(DidResolutionError, match="declares id="):
            resolver.resolve(f"{did}#key-1")


def test_did_web_subpath():
    priv, pub = generate_keypair()
    with DidWebFixture() as fixture:
        did = fixture.did_for_path(("agents", "alice"))
        kid = f"{did}#key-1"
        fixture.serve_document(
            "/agents/alice/did.json",
            {
                "id": did,
                "verificationMethod": [{
                    "id": kid,
                    "type": "Ed25519VerificationKey2020",
                    "controller": did,
                    "publicKeyBase64": public_key_to_b64(pub),
                }],
            },
        )
        resolver = DidWebResolver(scheme="http")
        assert public_key_to_b64(resolver.resolve(kid)) == public_key_to_b64(pub)


def test_did_web_rejects_other_methods():
    resolver = DidWebResolver(scheme="http")
    with pytest.raises(DidResolutionError, match="not a did:web"):
        resolver.resolve_document("did:sifr:alice")


def test_did_web_caches_documents():
    """Cold then warm resolution: second call must not perform another HTTP request."""
    priv, pub = generate_keypair()
    with DidWebFixture() as fixture:
        did = fixture.did_for_path()
        kid = f"{did}#key-1"
        fixture.serve_document(
            "/.well-known/did.json",
            {
                "id": did,
                "verificationMethod": [{
                    "id": kid,
                    "type": "Ed25519VerificationKey2020",
                    "controller": did,
                    "publicKeyBase64": public_key_to_b64(pub),
                }],
            },
        )
        resolver = DidWebResolver(scheme="http")
        resolver.resolve(kid)
        # Stop the server; warm cache must still satisfy resolution.
        fixture.stop()
        assert public_key_to_b64(resolver.resolve(kid)) == public_key_to_b64(pub)
        fixture.start()  # restart so the context-manager exit does not error


# ---------- MultiMethodResolver ----------

def test_multi_method_resolver_dispatches(tmp_path):
    _, pub_a = generate_keypair()
    _, pub_b = generate_keypair()
    _write_did_sifr_doc(tmp_path, "did:sifr:alice", "did:sifr:alice#key-1", public_key_to_b64(pub_a))

    with DidWebFixture() as fixture:
        bob_did = fixture.did_for_path()
        bob_kid = f"{bob_did}#key-1"
        fixture.serve_document(
            "/.well-known/did.json",
            {
                "id": bob_did,
                "verificationMethod": [{
                    "id": bob_kid,
                    "type": "Ed25519VerificationKey2020",
                    "controller": bob_did,
                    "publicKeyBase64": public_key_to_b64(pub_b),
                }],
            },
        )
        multi = MultiMethodResolver(
            sifr=DidSifrResolver(tmp_path),
            web=DidWebResolver(scheme="http"),
        )
        assert public_key_to_b64(multi.resolve("did:sifr:alice#key-1")) == public_key_to_b64(pub_a)
        assert public_key_to_b64(multi.resolve(bob_kid)) == public_key_to_b64(pub_b)


def test_multi_method_unknown_method_rejected():
    multi = MultiMethodResolver()
    with pytest.raises(DidResolutionError, match="no resolver"):
        multi.resolve_document("did:bogus:foo")


# ---------- parse_kid ----------

def test_parse_kid_requires_fragment():
    with pytest.raises(DidError, match="fragment"):
        parse_kid("did:sifr:alice")


def test_parse_kid_must_be_did():
    with pytest.raises(DidError, match="DID"):
        parse_kid("not-a-did#key-1")


def test_parse_kid_splits_correctly():
    did, kid = parse_kid("did:sifr:alice#key-1")
    assert did == "did:sifr:alice"
    assert kid == "did:sifr:alice#key-1"
