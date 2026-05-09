"""Tests for SIFRStatusList2021 credential-status mechanism.

These tests close the credential-revocation gap noted in the v0.4
limitations: a credential carrying a `credentialStatus` field must be
rejected when the referenced status list bit is set.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sifr.credential_status import (
    CredentialStatusError,
    StatusList,
    build_credential_status_field,
)
from sifr.credentials import (
    SIFR_CAPABILITY_CREDENTIAL_TYPE,
    SIFR_CONTEXT_URL,
    issue_credential,
    verify_credential,
)
from sifr.crypto import generate_keypair
from sifr.errors import CredentialError
from sifr.utils import utc_now_iso


def _future_iso(seconds: int = 3600) -> str:
    return (
        (datetime.now(timezone.utc) + timedelta(seconds=seconds))
        .isoformat()
        .replace("+00:00", "Z")
    )


def _make_credential(*, index, list_id, issuer="did:sifr:alice", subject="did:sifr:bob"):
    priv, pub = generate_keypair()
    kid = f"{issuer}#key-1"
    grant_payload = {
        "capability_id": "cap_001",
        "issuer": issuer,
        "subject": subject,
        "actions": ["tool.calculator.add"],
        "resource_scope": ["calculator"],
        "issued_at": utc_now_iso(),
        "expires_at": _future_iso(),
        "budget": {"max_calls": 5, "max_payload_bytes": 1024},
        "constraints": {"allow_delegation": False},
    }
    cred = issue_credential(
        issuer=issuer,
        subject=subject,
        capability_grant_payload=grant_payload,
        issuer_private_key=priv,
        issuer_kid=kid,
        expires_at=_future_iso(),
        credential_status=build_credential_status_field(
            status_list_id=list_id,
            statusListIndex=index,
        ),
    )
    return cred, pub, priv, kid


def test_status_list_round_trip_signed_and_verified():
    priv, pub = generate_keypair()
    issuer = "did:sifr:alice"
    kid = f"{issuer}#key-1"
    sl = StatusList(
        list_id="https://sifr.dev/lists/alice-revocation",
        issuer=issuer,
        size=1024,
        issuer_kid=kid,
        issuer_private_key=priv,
    )
    sl.revoke(7)
    sl.revoke(800)
    signed = sl.sign()
    assert "proof" in signed
    assert signed["type"] == "SIFRStatusList2021"
    # Round-trip via from_signed re-verifies and reconstitutes the bitmap.
    reloaded = StatusList.from_signed(signed, verifier_key=pub)
    assert reloaded.is_revoked(7)
    assert reloaded.is_revoked(800)
    assert not reloaded.is_revoked(0)
    assert not reloaded.is_revoked(801)


def test_status_list_signature_tampering_rejected():
    priv, pub = generate_keypair()
    issuer = "did:sifr:alice"
    kid = f"{issuer}#key-1"
    sl = StatusList(
        list_id="L",
        issuer=issuer,
        size=128,
        issuer_kid=kid,
        issuer_private_key=priv,
    )
    sl.revoke(3)
    signed = sl.sign()
    # Mutate the bitmap after signing — re-load must reject.
    signed["bits"] = "AAAAAAAAAAAAAAAAAAAAAA=="
    with pytest.raises(CredentialStatusError, match="signature invalid"):
        StatusList.from_signed(signed, verifier_key=pub)


def test_status_list_index_out_of_range_rejected():
    priv, _ = generate_keypair()
    sl = StatusList(
        list_id="L",
        issuer="did:sifr:alice",
        size=128,
        issuer_kid="did:sifr:alice#key-1",
        issuer_private_key=priv,
    )
    with pytest.raises(CredentialStatusError, match="out of range"):
        sl.revoke(128)
    with pytest.raises(CredentialStatusError, match="out of range"):
        sl.is_revoked(-1)


def test_status_list_size_must_be_multiple_of_8():
    priv, _ = generate_keypair()
    with pytest.raises(CredentialStatusError, match="multiple of 8"):
        StatusList(
            list_id="L",
            issuer="did:sifr:alice",
            size=100,
            issuer_kid="did:sifr:alice#key-1",
            issuer_private_key=priv,
        )


def test_credential_carries_sifr_type_and_context():
    cred, _, _, _ = _make_credential(index=1, list_id="L1")
    assert SIFR_CAPABILITY_CREDENTIAL_TYPE in cred["type"]
    assert SIFR_CONTEXT_URL in cred["@context"]
    assert "VerifiableCredential" in cred["type"]  # back-compat retained
    assert "credentialStatus" in cred


def test_credential_with_revoked_index_rejected():
    list_id = "https://sifr.dev/lists/alice-revocation"
    index = 42
    cred, pub, priv, kid = _make_credential(index=index, list_id=list_id)

    issuer = cred["issuer"]
    sl = StatusList(
        list_id=list_id,
        issuer=issuer,
        size=1024,
        issuer_kid=kid,
        issuer_private_key=priv,
    )
    # Revoke this credential's slot.
    sl.revoke(index)
    sl.sign()

    def status_checker(status_field):
        # The status-checker is given the embedded credentialStatus dict.
        # It must look up the index in the StatusList and raise on revocation.
        assert status_field["statusListCredential"] == list_id
        idx = status_field["statusListIndex"]
        if sl.is_revoked(idx):
            raise CredentialError(f"credential {idx} revoked via {list_id}")

    with pytest.raises(CredentialError, match="revoked"):
        verify_credential(cred, pub, status_checker=status_checker)


def test_credential_with_unrevoked_index_passes():
    list_id = "L"
    index = 7
    cred, pub, priv, kid = _make_credential(index=index, list_id=list_id)
    sl = StatusList(
        list_id=list_id,
        issuer=cred["issuer"],
        size=64,
        issuer_kid=kid,
        issuer_private_key=priv,
    )
    sl.sign()

    def checker(status_field):
        if sl.is_revoked(status_field["statusListIndex"]):
            raise CredentialError("revoked")

    assert verify_credential(cred, pub, status_checker=checker)


def test_credential_status_bound_into_signature():
    """Mutating the credentialStatus field after issuance must invalidate the proof."""
    cred, pub, _, _ = _make_credential(index=10, list_id="L")
    cred["credentialStatus"]["statusListIndex"] = 999  # tamper after sign
    with pytest.raises(CredentialError, match="signature invalid"):
        verify_credential(cred, pub)


def test_credential_without_status_field_does_not_call_checker():
    """Credentials without credentialStatus pass even if a checker is provided."""
    priv, pub = generate_keypair()
    issuer = "did:sifr:alice"
    kid = f"{issuer}#key-1"
    grant_payload = {
        "capability_id": "c",
        "issuer": issuer,
        "subject": "did:sifr:bob",
        "actions": ["x"],
        "resource_scope": [],
        "issued_at": utc_now_iso(),
        "expires_at": _future_iso(),
        "budget": {"max_calls": 1, "max_payload_bytes": 100},
        "constraints": {"allow_delegation": False},
    }
    cred = issue_credential(
        issuer=issuer,
        subject="did:sifr:bob",
        capability_grant_payload=grant_payload,
        issuer_private_key=priv,
        issuer_kid=kid,
        expires_at=_future_iso(),
    )

    called = []

    def checker(status_field):
        called.append(status_field)
        raise CredentialError("should not be called")

    assert verify_credential(cred, pub, status_checker=checker)
    assert called == []
