from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sifr.credentials import credential_to_grant, issue_credential, verify_credential
from sifr.crypto import generate_keypair
from sifr.errors import CredentialError
from sifr.utils import utc_now_iso


def _now_iso():
    return utc_now_iso()


def _future_iso(seconds: int = 3600) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _past_iso(seconds: int = 60) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _issue(*, issuer="did:sifr:alice", subject="did:sifr:bob", expires=None, issued=None):
    priv, pub = generate_keypair()
    kid = f"{issuer}#key-1"
    grant_payload = {
        "capability_id": "cap_001",
        "issuer": issuer,
        "subject": subject,
        "actions": ["tool.calculator.add"],
        "resource_scope": ["calculator"],
        "issued_at": issued or _now_iso(),
        "expires_at": expires or _future_iso(),
        "budget": {"max_calls": 5, "max_payload_bytes": 1024},
        "constraints": {"allow_delegation": False},
    }
    cred = issue_credential(
        issuer=issuer,
        subject=subject,
        capability_grant_payload=grant_payload,
        issuer_private_key=priv,
        issuer_kid=kid,
        expires_at=expires or _future_iso(),
        issued_at=issued or _now_iso(),
    )
    return cred, pub, kid


def test_issue_then_verify():
    cred, pub, _ = _issue()
    assert verify_credential(cred, pub)


def test_credential_has_required_fields():
    cred, _, _ = _issue()
    assert "VerifiableCredential" in cred["type"]
    assert "CapabilityCredential" in cred["type"]
    assert cred["proof"]["type"] == "Ed25519Signature2020"
    assert cred["proof"]["proofPurpose"] == "assertionMethod"
    assert cred["credentialSubject"]["id"] == "did:sifr:bob"
    assert "capability" in cred["credentialSubject"]


def test_mutate_subject_id_after_sign_fails():
    cred, pub, _ = _issue()
    cred["credentialSubject"]["id"] = "did:sifr:eve"
    with pytest.raises(CredentialError, match="signature invalid"):
        verify_credential(cred, pub)


def test_mutate_expiration_after_sign_fails():
    cred, pub, _ = _issue()
    cred["expirationDate"] = _future_iso(seconds=86400 * 30)
    with pytest.raises(CredentialError, match="signature invalid"):
        verify_credential(cred, pub)


def test_mutate_capability_after_sign_fails():
    cred, pub, _ = _issue()
    cred["credentialSubject"]["capability"]["actions"].append("tool.dangerous")
    with pytest.raises(CredentialError, match="signature invalid"):
        verify_credential(cred, pub)


def test_swap_proof_value_fails():
    cred, pub, _ = _issue()
    cred["proof"]["proofValue"] = "AAAA" + cred["proof"]["proofValue"][4:]
    with pytest.raises(CredentialError, match="signature invalid"):
        verify_credential(cred, pub)


def test_unsupported_proof_type():
    cred, pub, _ = _issue()
    cred["proof"]["type"] = "MadeUp"
    with pytest.raises(CredentialError, match="unsupported proof type"):
        verify_credential(cred, pub)


def test_wrong_proof_purpose():
    cred, pub, _ = _issue()
    cred["proof"]["proofPurpose"] = "authentication"
    with pytest.raises(CredentialError, match="proofPurpose"):
        verify_credential(cred, pub)


def test_issuer_did_must_match_verification_method():
    """Trap-acceptance: the verificationMethod's DID must equal the issuer field."""
    priv_alice, pub_alice = generate_keypair()
    grant_payload = {
        "capability_id": "cap_001",
        "issuer": "did:sifr:bob",
        "subject": "did:sifr:carol",
        "actions": ["x"],
        "resource_scope": [],
        "issued_at": _now_iso(),
        "expires_at": _future_iso(),
        "budget": {"max_calls": 1, "max_payload_bytes": 100},
        "constraints": {"allow_delegation": False},
    }
    cred = issue_credential(
        issuer="did:sifr:alice",
        subject="did:sifr:carol",
        capability_grant_payload=grant_payload,
        issuer_private_key=priv_alice,
        issuer_kid="did:sifr:bob#key-1",
        expires_at=_future_iso(),
    )
    with pytest.raises(CredentialError, match="does not match issuer"):
        verify_credential(cred, pub_alice)


def test_expired_credential():
    cred, pub, _ = _issue(expires=_past_iso(seconds=10))
    with pytest.raises(CredentialError, match="expired"):
        verify_credential(cred, pub)


def test_not_yet_valid():
    cred, pub, _ = _issue(issued=_future_iso(seconds=60), expires=_future_iso(seconds=120))
    with pytest.raises(CredentialError, match="not yet valid"):
        verify_credential(cred, pub)


def test_credential_to_grant_extracts_payload():
    cred, _, _ = _issue()
    grant = credential_to_grant(cred)
    assert grant["capability_id"] == "cap_001"
    assert grant["actions"] == ["tool.calculator.add"]


def test_missing_proof():
    cred, pub, _ = _issue()
    del cred["proof"]
    with pytest.raises(CredentialError, match="missing proof"):
        verify_credential(cred, pub)


def test_missing_credential_subject():
    cred, pub, _ = _issue()
    cred["credentialSubject"] = {"id": "did:sifr:bob"}  # remove "capability"
    # First the signature verify will fail because we mutated body
    with pytest.raises(CredentialError, match="signature invalid"):
        verify_credential(cred, pub)


def test_credential_signed_by_wrong_key_rejected():
    cred, _, _ = _issue()
    _, other_pub = generate_keypair()
    with pytest.raises(CredentialError, match="signature invalid"):
        verify_credential(cred, other_pub)
