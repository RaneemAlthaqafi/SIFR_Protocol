"""11 controlled adversary cases. Each test asserts:
  1. The exact rejection error class.
  2. The WasmToolRunner's last_invocation_evidence is unchanged after the
     rejection (proving the attack never reached the tool).

Tests use LocalTransport semantics; the rejection paths are at the
authorization layer, not the wire layer. Wire-level concerns (corruption,
peer disconnect) are exercised by tests/test_quic_transport.py.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sifr.audit_dag import AuditDAG
from sifr.capabilities import CapabilityStore, authorize_action, create_capability_grant
from sifr.crypto import generate_keypair, sign_message, verify_message
from sifr.errors import (
    AuditDAGError,
    CapabilityError,
    MessageValidationError,
    ReplayError,
    SignatureError,
    UnauthorizedAction,
)
from sifr.messages import create_message, validate_message
from sifr.replay import ReplayCache
from sifr.revocation import RevocationRegistry
from sifr.wasm_runner import WasmToolRunner


def _future_iso(seconds: int = 600) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _past_iso(seconds: int = 60) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _make_scenario(*, expires_at: str | None = None, max_payload_bytes: int = 1024):
    issuer_priv, issuer_pub = generate_keypair()
    issuer = "did:sifr:alice"
    issuer_kid = f"{issuer}#key-1"

    subject_priv, subject_pub = generate_keypair()
    subject = "did:sifr:bob"
    subject_kid = f"{subject}#key-1"

    grant = create_capability_grant(
        issuer=issuer,
        subject=subject,
        actions=["tool.calculator.add"],
        resource_scope=["calculator"],
        issuer_private_key=issuer_priv,
        receiver_id=subject,
        session_id="sess_test",
        expires_at=expires_at or _future_iso(),
        max_calls=5,
        max_payload_bytes=max_payload_bytes,
    )
    cap_id = grant["payload"]["capability_id"]

    action = create_message(
        "Action",
        subject,
        issuer,
        {"action": "tool.calculator.add", "args": {"a": 2, "b": 3}, "requires_auth": True},
        session_id="sess_test",
        capability_id=cap_id,
    )
    signed_action = sign_message(action, subject_priv, subject_kid)

    class _Resolver:
        def resolve(self, kid):
            if kid == issuer_kid:
                return issuer_pub
            if kid == subject_kid:
                return subject_pub
            raise SignatureError(f"unknown kid: {kid}")

        def resolve_revoked(self, kid):
            return None

    return {
        "issuer_priv": issuer_priv,
        "issuer_pub": issuer_pub,
        "issuer_kid": issuer_kid,
        "subject_priv": subject_priv,
        "subject_pub": subject_pub,
        "subject_kid": subject_kid,
        "grant": grant,
        "action": signed_action,
        "store": CapabilityStore(),
        "registry": RevocationRegistry(
            issuer=issuer,
            issuer_kid=issuer_kid,
            issuer_private_key=issuer_priv,
            verifier_key=issuer_pub,
        ),
        "cache": ReplayCache(),
        "runner": WasmToolRunner(),
        "resolver": _Resolver(),
        "cap_id": cap_id,
    }


def _authorized_execute(s, *, action=None, grant=None):
    """Guarded WASM dispatch: verify action signature, authorize, then run.

    Raises before reaching the runner if any check fails. This is the
    integration choke point for adversary tests.
    """
    action = action if action is not None else s["action"]
    if grant is None:
        raise CapabilityError("no grant provided; refusing WASM execution")
    s["store"].add(grant) if grant["payload"]["capability_id"] not in s["store"]._grants else None
    verify_message(action, s["resolver"])
    authorize_action(
        action,
        grant,
        s["issuer_pub"],
        s["store"],
        revocation_registry=s["registry"],
        replay_cache=s["cache"],
    )
    return s["runner"].execute(action["payload"]["action"], action["payload"]["args"])


# ---- 1. Tampered body ----
def test_attack_01_tamper_body():
    s = _make_scenario()
    s["action"]["payload"]["args"]["a"] = 999  # change after sign
    with pytest.raises(SignatureError):
        _authorized_execute(s, grant=s["grant"])
    assert s["runner"].last_invocation_evidence is None


# ---- 2. Replay old message ----
def test_attack_02_replay():
    s = _make_scenario()
    out = _authorized_execute(s, grant=s["grant"])
    assert out == {"result": 5}
    evidence_after_legitimate = dict(s["runner"].last_invocation_evidence)

    with pytest.raises(ReplayError):
        _authorized_execute(s, grant=s["grant"])

    # The replayed call did not reach the runner; evidence still reflects
    # only the first (legitimate) call.
    assert s["runner"].last_invocation_evidence == evidence_after_legitimate


# ---- 3. Use expired grant ----
def test_attack_03_expired_grant():
    s = _make_scenario(expires_at=_past_iso())
    with pytest.raises(UnauthorizedAction, match="EXPIRED_CAPABILITY"):
        _authorized_execute(s, grant=s["grant"])
    assert s["runner"].last_invocation_evidence is None


# ---- 4. Use revoked grant ----
def test_attack_04_revoked_grant():
    s = _make_scenario()
    s["registry"].revoke(s["cap_id"], "compromise")
    with pytest.raises(UnauthorizedAction, match="REVOKED_CAPABILITY"):
        _authorized_execute(s, grant=s["grant"])
    assert s["runner"].last_invocation_evidence is None


# ---- 5. Swap sender_id ----
def test_attack_05_swap_sender_id():
    s = _make_scenario()
    s["action"]["sender_id"] = "did:sifr:eve"
    with pytest.raises(SignatureError):
        _authorized_execute(s, grant=s["grant"])
    assert s["runner"].last_invocation_evidence is None


# ---- 6. Swap kid ----
def test_attack_06_swap_kid():
    s = _make_scenario()
    # Point signature at the issuer's kid; the bytes were signed by the
    # subject's private key, so verifying with issuer_pub must fail.
    s["action"]["signature"]["kid"] = s["issuer_kid"]
    with pytest.raises(SignatureError):
        _authorized_execute(s, grant=s["grant"])
    assert s["runner"].last_invocation_evidence is None


# ---- 7. Unauthorized action name ----
def test_attack_07_unauthorized_action_name():
    s = _make_scenario()
    # Re-sign an action with a different action name not in the grant
    new_action = create_message(
        "Action",
        s["action"]["sender_id"],
        s["action"]["receiver_id"],
        {"action": "tool.calculator.subtract", "args": {"a": 5, "b": 3}, "requires_auth": True},
        session_id=s["action"]["session_id"],
        capability_id=s["cap_id"],
    )
    signed = sign_message(new_action, s["subject_priv"], s["subject_kid"])
    with pytest.raises(UnauthorizedAction, match="UNAUTHORIZED_ACTION"):
        _authorized_execute(s, action=signed, grant=s["grant"])
    assert s["runner"].last_invocation_evidence is None


# ---- 8. Malformed frame ----
def test_attack_08_malformed_frame():
    s = _make_scenario()
    bogus = {"type": "Action", "payload": {"action": "tool.calculator.add"}}
    with pytest.raises(MessageValidationError):
        validate_message(bogus)
    assert s["runner"].last_invocation_evidence is None


# ---- 9. Drop parent DAG node ----
def test_attack_09_drop_parent_dag_node():
    s = _make_scenario()
    dag = AuditDAG()
    grant_cid = dag.add_message(s["grant"])
    s["action"]["parents"] = [grant_cid]
    re_signed = sign_message(s["action"], s["subject_priv"], s["subject_kid"])
    dag.add_message(re_signed)

    del dag.nodes[grant_cid]
    del dag.messages[grant_cid]

    with pytest.raises(AuditDAGError):
        dag.verify_dag_integrity()
    assert s["runner"].last_invocation_evidence is None


# ---- 10. Oversized payload ----
def test_attack_10_oversized_payload():
    s = _make_scenario(max_payload_bytes=50)
    big_action = create_message(
        "Action",
        s["action"]["sender_id"],
        s["action"]["receiver_id"],
        {
            "action": "tool.calculator.add",
            "args": {"a": 1, "b": 2},
            "requires_auth": True,
            "padding": "x" * 5000,
        },
        session_id=s["action"]["session_id"],
        capability_id=s["cap_id"],
    )
    signed = sign_message(big_action, s["subject_priv"], s["subject_kid"])
    with pytest.raises(UnauthorizedAction, match="PAYLOAD_BUDGET_EXCEEDED"):
        _authorized_execute(s, action=signed, grant=s["grant"])
    assert s["runner"].last_invocation_evidence is None


# ---- 11. WASM execution without grant ----
def test_attack_11_wasm_without_grant():
    s = _make_scenario()
    with pytest.raises(CapabilityError):
        _authorized_execute(s, grant=None)
    assert s["runner"].last_invocation_evidence is None
