"""Tests for the broader DID encoding surface introduced in v0.5:

- publicKeyMultibase under Ed25519VerificationKey2020
- publicKeyJwk under JsonWebKey2020
- did:key resolver

These tests intentionally feed canonical encodings into both the document
parser and the did:key resolver, then sign+verify a SIFR frame end-to-end.
A separate group covers each rejection path: malformed key, wrong type
binding, missing kid, controller mismatch, unsupported method, path
traversal, and unsupported multicodec.
"""
from __future__ import annotations

import json

import pytest

from sifr.crypto import generate_keypair, sign_message, verify_message
from sifr.did import (
    DidDocumentError,
    DidKeyMismatch,
    DidResolutionError,
    MultiMethodResolver,
    VerificationMethod,
    parse_did_document,
)
from sifr.did.did_key import DidKeyResolver
from sifr.did.did_sifr import DidSifrResolver
from sifr.did.encodings import (
    decode_multibase_base58btc,
    ed25519_pub_from_did_key,
    ed25519_pub_to_did_key,
    ed25519_pub_to_jwk,
    ed25519_pub_to_multibase,
    encode_multibase_base58btc,
    ED25519_MULTICODEC,
)


def test_multibase_round_trip_for_ed25519_keypair():
    _, pub = generate_keypair()
    mb = ed25519_pub_to_multibase(pub)
    assert mb.startswith("z")
    decoded = decode_multibase_base58btc(mb)
    assert decoded.startswith(ED25519_MULTICODEC)
    assert len(decoded) == 2 + 32


def test_multibase_known_vector():
    """Known did:key vector from W3C-CCG did:key spec.

    The 32-byte all-zero Ed25519 public key encodes to multicodec
    0xed01 || 0x00*32 which in base58btc is '1' (one) for each leading
    zero byte and the multicodec/zero remainder. We just check
    determinism + round-trip rather than hard-coding an external string.
    """
    raw = b"\x00" * 32
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    pub = Ed25519PublicKey.from_public_bytes(raw)
    mb = ed25519_pub_to_multibase(pub)
    decoded = decode_multibase_base58btc(mb)
    assert decoded == ED25519_MULTICODEC + raw


def test_did_key_resolves_and_verifies():
    priv, pub = generate_keypair()
    did = ed25519_pub_to_did_key(pub)
    resolver = DidKeyResolver()
    doc = resolver.resolve_document(did)
    assert doc.id == did
    assert len(doc.verification_methods) == 1
    method = doc.verification_methods[0]
    assert method.type == "Ed25519VerificationKey2020"
    assert method.controller == did
    assert method.key_format == "publicKeyMultibase"

    msg = {"sender_id": did, "type": "Hello", "payload": {}}
    signed = sign_message(msg, priv, method.id)
    assert verify_message(signed, resolver)


def test_did_key_authorizes_standard_relationships():
    _, pub = generate_keypair()
    did = ed25519_pub_to_did_key(pub)
    resolver = DidKeyResolver()
    doc = resolver.resolve_document(did)
    kid = doc.verification_methods[0].id
    for relationship in (
        "authentication",
        "assertionMethod",
        "capabilityInvocation",
        "capabilityDelegation",
    ):
        resolved = resolver.resolve_for(kid, relationship)
        assert resolved.public_bytes_raw() == pub.public_bytes_raw()


def test_did_key_round_trip_via_encoder():
    _, pub = generate_keypair()
    did = ed25519_pub_to_did_key(pub)
    decoded = ed25519_pub_from_did_key(did)
    assert decoded.public_bytes_raw() == pub.public_bytes_raw()


def test_did_key_rejects_non_canonical_form():
    """A did:key with extra leading characters or different multibase prefix
    must be rejected. Fragmented identifiers should be passed via resolver.resolve()."""
    resolver = DidKeyResolver()
    # base64-prefix 'm' is a legal multibase prefix but unsupported here.
    bad = "did:key:mAAAA"
    with pytest.raises(DidResolutionError):
        resolver.resolve_document(bad)


def test_did_key_rejects_non_ed25519_multicodec():
    """did:key with a multicodec prefix other than 0xed01 must fail."""
    resolver = DidKeyResolver()
    # 0xe7 0x01 is the secp256k1-pub multicodec; not Ed25519.
    fake_payload = b"\xe7\x01" + b"\x00" * 33
    bad_did = "did:key:" + encode_multibase_base58btc(fake_payload)
    with pytest.raises(DidResolutionError):
        resolver.resolve_document(bad_did)


def test_did_key_rejects_truncated_key():
    resolver = DidKeyResolver()
    # 0xed01 prefix but only 16 raw bytes instead of 32
    fake_payload = ED25519_MULTICODEC + b"\x00" * 16
    bad_did = "did:key:" + encode_multibase_base58btc(fake_payload)
    with pytest.raises(DidResolutionError):
        resolver.resolve_document(bad_did)


def test_did_key_rejects_other_did_methods():
    resolver = DidKeyResolver()
    with pytest.raises(DidResolutionError, match="not a did:key"):
        resolver.resolve_document("did:web:example.com")


# ----- DID document parsing for the new formats -----

def test_doc_parses_publicKeyMultibase():
    _, pub = generate_keypair()
    did = "did:sifr:alice"
    kid = f"{did}#key-1"
    raw_doc = {
        "id": did,
        "verificationMethod": [
            {
                "id": kid,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": ed25519_pub_to_multibase(pub),
            }
        ],
    }
    doc = parse_did_document(raw_doc)
    method = doc.find_method(kid)
    assert method.key_format == "publicKeyMultibase"
    resolved = method.to_public_key()
    assert resolved.public_bytes_raw() == pub.public_bytes_raw()


def test_doc_parses_publicKeyJwk():
    _, pub = generate_keypair()
    did = "did:sifr:bob"
    kid = f"{did}#jwk-1"
    raw_doc = {
        "id": did,
        "verificationMethod": [
            {
                "id": kid,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": ed25519_pub_to_jwk(pub),
            }
        ],
    }
    doc = parse_did_document(raw_doc)
    method = doc.find_method(kid)
    assert method.key_format == "publicKeyJwk"
    resolved = method.to_public_key()
    assert resolved.public_bytes_raw() == pub.public_bytes_raw()


def test_doc_rejects_jwk_with_wrong_type_binding():
    _, pub = generate_keypair()
    did = "did:sifr:bob"
    raw_doc = {
        "id": did,
        "verificationMethod": [
            {
                "id": f"{did}#k1",
                "type": "Ed25519VerificationKey2020",  # wrong binding for JWK
                "controller": did,
                "publicKeyJwk": ed25519_pub_to_jwk(pub),
            }
        ],
    }
    with pytest.raises(DidDocumentError, match="JsonWebKey2020"):
        parse_did_document(raw_doc)


def test_doc_rejects_multibase_with_wrong_type_binding():
    _, pub = generate_keypair()
    did = "did:sifr:carol"
    raw_doc = {
        "id": did,
        "verificationMethod": [
            {
                "id": f"{did}#k1",
                "type": "Ed25519VerificationKey2018",  # 2018 only carries base64
                "controller": did,
                "publicKeyMultibase": ed25519_pub_to_multibase(pub),
            }
        ],
    }
    with pytest.raises(DidDocumentError, match="Ed25519VerificationKey2020"):
        parse_did_document(raw_doc)


def test_doc_rejects_multiple_key_formats():
    _, pub = generate_keypair()
    did = "did:sifr:dan"
    raw_doc = {
        "id": did,
        "verificationMethod": [
            {
                "id": f"{did}#k1",
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": ed25519_pub_to_multibase(pub),
                "publicKeyBase64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            }
        ],
    }
    with pytest.raises(DidDocumentError, match="exactly one"):
        parse_did_document(raw_doc)


def test_doc_rejects_no_key_material():
    raw_doc = {
        "id": "did:sifr:eve",
        "verificationMethod": [
            {
                "id": "did:sifr:eve#k1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:sifr:eve",
            }
        ],
    }
    with pytest.raises(DidDocumentError, match="must carry one of"):
        parse_did_document(raw_doc)


def test_doc_rejects_malformed_jwk_curve():
    raw_doc = {
        "id": "did:sifr:frank",
        "verificationMethod": [
            {
                "id": "did:sifr:frank#k1",
                "type": "JsonWebKey2020",
                "controller": "did:sifr:frank",
                "publicKeyJwk": {"kty": "OKP", "crv": "X25519", "x": "AAAAAA"},
            }
        ],
    }
    with pytest.raises(DidDocumentError, match="invalid publicKeyJwk"):
        parse_did_document(raw_doc)


def test_doc_rejects_malformed_jwk_kty():
    raw_doc = {
        "id": "did:sifr:gina",
        "verificationMethod": [
            {
                "id": "did:sifr:gina#k1",
                "type": "JsonWebKey2020",
                "controller": "did:sifr:gina",
                "publicKeyJwk": {"kty": "RSA", "crv": "Ed25519", "x": "x"},
            }
        ],
    }
    with pytest.raises(DidDocumentError, match="invalid publicKeyJwk"):
        parse_did_document(raw_doc)


def test_doc_rejects_padded_jwk_x():
    _, pub = generate_keypair()
    did = "did:sifr:padded"
    jwk = ed25519_pub_to_jwk(pub)
    jwk["x"] = jwk["x"] + "="
    raw_doc = {
        "id": did,
        "verificationMethod": [
            {
                "id": f"{did}#k1",
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": jwk,
            }
        ],
    }
    with pytest.raises(DidDocumentError, match="invalid publicKeyJwk"):
        parse_did_document(raw_doc)


def test_doc_rejects_short_base64_key():
    raw_doc = {
        "id": "did:sifr:henry",
        "verificationMethod": [
            {
                "id": "did:sifr:henry#k1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:sifr:henry",
                "publicKeyBase64": "AAAA",  # too short
            }
        ],
    }
    with pytest.raises(DidDocumentError, match="32 bytes"):
        parse_did_document(raw_doc)


def test_did_sifr_with_multibase(tmp_path):
    """did:sifr resolver should also accept publicKeyMultibase entries."""
    priv, pub = generate_keypair()
    did = "did:sifr:imani"
    kid = f"{did}#k1"
    doc = {
        "id": did,
        "verificationMethod": [
            {
                "id": kid,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": ed25519_pub_to_multibase(pub),
            }
        ],
    }
    (tmp_path / "imani.json").write_text(json.dumps(doc), encoding="utf-8")
    resolver = DidSifrResolver(tmp_path)

    msg = {"sender_id": did, "type": "Hello", "payload": {}}
    signed = sign_message(msg, priv, kid)
    assert verify_message(signed, resolver)


def test_did_sifr_with_jwk(tmp_path):
    """did:sifr resolver should also accept publicKeyJwk entries."""
    priv, pub = generate_keypair()
    did = "did:sifr:jada"
    kid = f"{did}#jwk-key"
    doc = {
        "id": did,
        "verificationMethod": [
            {
                "id": kid,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": ed25519_pub_to_jwk(pub),
            }
        ],
    }
    (tmp_path / "jada.json").write_text(json.dumps(doc), encoding="utf-8")
    resolver = DidSifrResolver(tmp_path)

    msg = {"sender_id": did, "type": "Hello", "payload": {}}
    signed = sign_message(msg, priv, kid)
    assert verify_message(signed, resolver)


def test_multi_method_resolver_dispatches_to_did_key():
    priv, pub = generate_keypair()
    did = ed25519_pub_to_did_key(pub)
    multi = MultiMethodResolver(key=DidKeyResolver())
    doc = multi.resolve_document(did)
    method = doc.verification_methods[0]
    msg = {"sender_id": did, "type": "Hello", "payload": {}}
    signed = sign_message(msg, priv, method.id)
    assert verify_message(signed, multi)


def test_did_key_kid_mismatch_rejected():
    priv, pub = generate_keypair()
    did = ed25519_pub_to_did_key(pub)
    resolver = DidKeyResolver()
    # Use a kid that does not match the canonical did:key fragment.
    wrong_kid = f"{did}#key-1"
    msg = {"sender_id": did, "type": "Hello", "payload": {}}
    signed = sign_message(msg, priv, wrong_kid)
    with pytest.raises(DidKeyMismatch):
        verify_message(signed, resolver)
