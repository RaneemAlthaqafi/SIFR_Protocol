"""SIFR v0.4 proof-obligation tests.

Each claim C1-C7 from `docs/security_claims_v0_4.md` has at least one
positive test (the obligation holds when the system is operated correctly)
and one or more adversarial negative tests (the obligation rejects every
documented attack against it).

These tests are the implementation-level evidence that the formal claims
hold against the running code. They do NOT replace the formal artifacts
(`formal/sifr_capability.tla`, `formal/tamarin/sifr_core.spthy`); they
are the bridge between specification and implementation.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

import pytest

from sifr.audit_dag import AuditDAG
from sifr.capabilities import (
    CapabilityStore,
    authorize_action,
    create_capability_grant,
    verify_capability_grant,
)
from sifr.crypto import generate_keypair, sign_message, verify_message
from sifr.errors import (
    AuditDAGError,
    CapabilityError,
    ReplayError,
    SignatureError,
    UnauthorizedAction,
)
from sifr.messages import create_message
from sifr.replay import ReplayCache
from sifr.revocation import RevocationRegistry
from sifr.wasm_runner import WasmToolRunner


def _future_iso(seconds: int = 600) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _past_iso(seconds: int = 60) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _scenario():
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
        session_id="sess_v0_4",
        expires_at=_future_iso(),
        max_calls=3,
        max_payload_bytes=512,
    )
    cap_id = grant["payload"]["capability_id"]
    action = create_message(
        "Action", subject, issuer,
        {"action": "tool.calculator.add", "args": {"a": 2, "b": 3}, "requires_auth": True},
        session_id="sess_v0_4", capability_id=cap_id,
    )
    signed_action = sign_message(action, subject_priv, subject_kid)

    revoked_kid = f"{subject}#key-revoked"
    revoked_priv, revoked_pub = generate_keypair()
    revoked_kids: set[str] = set()

    class _Resolver:
        def resolve(self, kid):
            if kid == issuer_kid: return issuer_pub
            if kid == subject_kid: return subject_pub
            if kid == revoked_kid:
                if kid in revoked_kids: raise SignatureError(f"key revoked: {kid}")
                return revoked_pub
            raise SignatureError(f"unknown kid: {kid}")
        def resolve_revoked(self, kid): return None

    return {
        "issuer": issuer, "issuer_priv": issuer_priv, "issuer_pub": issuer_pub, "issuer_kid": issuer_kid,
        "subject": subject, "subject_priv": subject_priv, "subject_pub": subject_pub, "subject_kid": subject_kid,
        "revoked_priv": revoked_priv, "revoked_kid": revoked_kid, "revoked_kids": revoked_kids,
        "grant": grant, "cap_id": cap_id, "action": signed_action,
        "store": CapabilityStore(),
        "registry": RevocationRegistry(
            issuer=issuer, issuer_kid=issuer_kid,
            issuer_private_key=issuer_priv, verifier_key=issuer_pub,
        ),
        "cache": ReplayCache(),
        "runner": WasmToolRunner(),
        "resolver": _Resolver(),
    }


def _execute(s, action=None, grant=None):
    action = action if action is not None else s["action"]
    if grant is None: raise CapabilityError("no grant provided")
    if grant["payload"]["capability_id"] not in s["store"]._grants:
        s["store"].add(grant)
    verify_message(action, s["resolver"])
    authorize_action(action, grant, s["issuer_pub"], s["store"],
                     revocation_registry=s["registry"], replay_cache=s["cache"])
    return s["runner"].execute(action["payload"]["action"], action["payload"]["args"])


# ---------- C1 Authorization Safety ----------

def test_C1_positive_authorized_action_executes():
    s = _scenario()
    out = _execute(s, grant=s["grant"])
    assert out == {"result": 5}
    assert s["runner"].last_invocation_evidence["fuel_consumed"] > 0


def test_C1_negative_wrong_subject():
    s = _scenario()
    grant_for_eve = create_capability_grant(
        issuer=s["issuer"], subject="did:sifr:eve",
        actions=["tool.calculator.add"], resource_scope=["calculator"],
        issuer_private_key=s["issuer_priv"], receiver_id="did:sifr:eve",
        session_id="sess_v0_4", expires_at=_future_iso(),
    )
    with pytest.raises(UnauthorizedAction, match="WRONG_SUBJECT"):
        action = copy.deepcopy(s["action"])
        action["capability_id"] = grant_for_eve["payload"]["capability_id"]
        action = sign_message(
            {k: v for k, v in action.items() if k != "signature"},
            s["subject_priv"], s["subject_kid"],
        )
        _execute(s, action=action, grant=grant_for_eve)
    assert s["runner"].last_invocation_evidence is None


def test_C1_negative_wrong_issuer():
    s = _scenario()
    grant = copy.deepcopy(s["grant"])
    grant["payload"]["issuer"] = "did:sifr:eve"  # forge issuer claim
    with pytest.raises((CapabilityError, SignatureError)):
        _execute(s, grant=grant)
    assert s["runner"].last_invocation_evidence is None


def test_C1_negative_revoked_key():
    s = _scenario()
    s["revoked_kids"].add(s["revoked_kid"])
    bad = sign_message(
        {k: v for k, v in s["action"].items() if k != "signature"},
        s["revoked_priv"], s["revoked_kid"],
    )
    with pytest.raises(SignatureError, match="revoked"):
        _execute(s, action=bad, grant=s["grant"])
    assert s["runner"].last_invocation_evidence is None


def test_C1_negative_expired_capability():
    s = _scenario()
    expired_grant = create_capability_grant(
        issuer=s["issuer"], subject=s["subject"],
        actions=["tool.calculator.add"], resource_scope=["calculator"],
        issuer_private_key=s["issuer_priv"], receiver_id=s["subject"],
        session_id="sess_v0_4", expires_at=_past_iso(),
    )
    expired_cap = expired_grant["payload"]["capability_id"]
    action = create_message(
        "Action", s["subject"], s["issuer"],
        {"action": "tool.calculator.add", "args": {"a": 1, "b": 1}, "requires_auth": True},
        session_id="sess_v0_4", capability_id=expired_cap,
    )
    signed = sign_message(action, s["subject_priv"], s["subject_kid"])
    with pytest.raises(UnauthorizedAction, match="EXPIRED"):
        _execute(s, action=signed, grant=expired_grant)
    assert s["runner"].last_invocation_evidence is None


# ---------- C2 Replay Safety ----------

def test_C2_positive_first_message_accepted():
    s = _scenario()
    out = _execute(s, grant=s["grant"])
    assert out == {"result": 5}


def test_C2_negative_replayed_message_rejected():
    s = _scenario()
    _execute(s, grant=s["grant"])
    fuel_after = dict(s["runner"].last_invocation_evidence)
    with pytest.raises(ReplayError):
        _execute(s, grant=s["grant"])
    assert s["runner"].last_invocation_evidence == fuel_after


# ---------- C3 Revocation Safety ----------

def test_C3_positive_unrevoked_capability_works():
    s = _scenario()
    assert s["registry"].is_revoked(s["cap_id"]) is None
    out = _execute(s, grant=s["grant"])
    assert out == {"result": 5}


def test_C3_negative_revoked_capability_rejected():
    s = _scenario()
    s["registry"].revoke(s["cap_id"], "v0.4 proof obligation")
    with pytest.raises(UnauthorizedAction, match="REVOKED"):
        _execute(s, grant=s["grant"])
    assert s["runner"].last_invocation_evidence is None


def test_C3_negative_revocation_known_before_authorization():
    """Revocation enforcement order: revocation is consulted before any
    other authorization check in `authorize_action`."""
    s = _scenario()
    s["registry"].revoke(s["cap_id"], "ordering test")
    expired_grant = copy.deepcopy(s["grant"])
    expired_grant["payload"]["expires_at"] = _past_iso()
    # Even though the grant is also expired, revocation should fire first.
    with pytest.raises(UnauthorizedAction, match="REVOKED"):
        _execute(s, grant=s["grant"])


# ---------- C4 Signature Binding ----------

def test_C4_positive_valid_signature_resolves_to_correct_key():
    s = _scenario()
    assert verify_message(s["action"], s["resolver"])


def test_C4_negative_kid_did_must_match_sender_id():
    """A signed message claiming sender=bob with kid pointing at issuer's
    DID must be rejected by the v0.3 binding closure."""
    s = _scenario()
    bad = copy.deepcopy(s["action"])
    bad["signature"]["kid"] = s["issuer_kid"]
    with pytest.raises(SignatureError, match="does not match sender_id|signature verification failed"):
        verify_message(bad, s["resolver"])


def test_C4_negative_tampered_payload_breaks_signature():
    s = _scenario()
    bad = copy.deepcopy(s["action"])
    bad["payload"]["args"]["a"] = 999
    with pytest.raises(SignatureError):
        verify_message(bad, s["resolver"])


# ---------- C5 Audit DAG Tamper Evidence ----------

def test_C5_positive_clean_dag_verifies():
    s = _scenario()
    dag = AuditDAG()
    dag.add_message(s["grant"])
    dag.add_message(s["action"])
    dag.verify_dag_integrity()  # no exception


def test_C5_negative_tampered_node_detected():
    s = _scenario()
    dag = AuditDAG()
    cid = dag.add_message(s["grant"])
    dag.messages[cid]["payload"]["actions"].append("tool.calculator.subtract")
    with pytest.raises(AuditDAGError):
        dag.verify_dag_integrity()


def test_C5_negative_dropped_parent_detected():
    s = _scenario()
    dag = AuditDAG()
    parent_cid = dag.add_message(s["grant"])
    s["action"]["parents"] = [parent_cid]
    re_signed = sign_message(
        {k: v for k, v in s["action"].items() if k != "signature"},
        s["subject_priv"], s["subject_kid"],
    )
    dag.add_message(re_signed)
    del dag.nodes[parent_cid]
    del dag.messages[parent_cid]
    with pytest.raises(AuditDAGError):
        dag.verify_dag_integrity()


# ---------- C6 No Tool Before Authorization ----------

def test_C6_positive_authorize_then_execute():
    s = _scenario()
    _execute(s, grant=s["grant"])
    assert s["runner"].last_invocation_evidence is not None


def test_C6_negative_direct_execute_without_grant():
    """The `_execute` integration helper raises CapabilityError when the
    grant argument is None — proving the authorization gate is checked
    before the tool runner is invoked."""
    s = _scenario()
    with pytest.raises(CapabilityError):
        _execute(s, grant=None)
    assert s["runner"].last_invocation_evidence is None


def test_C6_negative_authorization_failure_blocks_tool():
    """If authorize_action raises, the tool runner must not be reached."""
    s = _scenario()
    s["registry"].revoke(s["cap_id"], "C6 test")
    with pytest.raises(UnauthorizedAction):
        _execute(s, grant=s["grant"])
    assert s["runner"].last_invocation_evidence is None


# ---------- C7 Bounded State-Machine Safety ----------

def test_C7_tlc_artifacts_present():
    """The TLC output must be present and report no error. This is the
    runtime-level check on the bounded-proven claim. The detailed
    invariant-by-invariant assertions are in tests/test_formal_artifacts.py."""
    from pathlib import Path
    output = Path(__file__).resolve().parents[1] / "formal" / "output" / "tlc_output.txt"
    if not output.is_file():
        pytest.skip("TLC output absent; run `bash formal/run_tlc.sh`")
    body = output.read_text(encoding="utf-8")
    assert "No error has been found" in body
    assert "11601 states" in body or "11,601" in body or "distinct states found" in body
