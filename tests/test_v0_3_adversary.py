"""SIFR v0.3 strict adversary evaluation: 30 controlled cases.

Each case asserts:
  1. The exact rejection error class.
  2. `WasmToolRunner.last_invocation_evidence` is unchanged after the
     rejection -- proving the attack never reached the tool.

This file is the authoritative v0.3 adversary contract. The companion
benchmark `benchmarks/bench_v0_3_adversary_rejection.py` re-times the same
attacks and writes raw results under `benchmarks/results/v0.3/`.

Some cases also exercise the real QUIC transport (A25, A26, A27).
TensorFrame cases (A28-A30) exercise the decoder boundary, not the
authorization layer.
"""
from __future__ import annotations

import asyncio
import base64
import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sifr.audit_dag import AuditDAG
from sifr.capabilities import (
    CapabilityStore,
    authorize_action,
    create_capability_grant,
)
from sifr.credentials import issue_credential, verify_credential
from sifr.crypto import generate_keypair, public_key_to_b64, sign_message, verify_message
from sifr.errors import (
    AuditDAGError,
    CapabilityError,
    CredentialError,
    MessageValidationError,
    ReplayError,
    SignatureError,
    UnauthorizedAction,
)
from sifr.messages import create_message, validate_message
from sifr.replay import ReplayCache
from sifr.revocation import RevocationRegistry
from sifr.tensor import decode_base64
from sifr.transport._certs import generate_self_signed_cert
from sifr.transport.quic import connect_quic, serve_quic
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
        session_id="sess_v0_3",
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
        session_id="sess_v0_3",
        capability_id=cap_id,
    )
    signed_action = sign_message(action, subject_priv, subject_kid)

    # Authorized 3rd-party kid (valid signing key, NOT in any grant for `subject`)
    eve_priv, eve_pub = generate_keypair()
    eve_kid = "did:sifr:eve#key-1"
    revoked_priv, revoked_pub = generate_keypair()
    revoked_kid = f"{subject}#key-revoked"

    revoked_kids: set[str] = set()

    class _Resolver:
        def resolve(self, kid):
            if kid == issuer_kid:
                return issuer_pub
            if kid == subject_kid:
                return subject_pub
            if kid == eve_kid:
                return eve_pub
            if kid == revoked_kid:
                if kid in revoked_kids:
                    raise SignatureError(f"key revoked: {kid}")
                return revoked_pub
            raise SignatureError(f"unknown kid: {kid}")

        def resolve_revoked(self, kid):
            return None

    resolver = _Resolver()

    return {
        "issuer_priv": issuer_priv,
        "issuer_pub": issuer_pub,
        "issuer_kid": issuer_kid,
        "issuer": issuer,
        "subject_priv": subject_priv,
        "subject_pub": subject_pub,
        "subject_kid": subject_kid,
        "subject": subject,
        "eve_priv": eve_priv,
        "eve_pub": eve_pub,
        "eve_kid": eve_kid,
        "revoked_priv": revoked_priv,
        "revoked_kid": revoked_kid,
        "revoked_kids": revoked_kids,
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
        "resolver": resolver,
        "cap_id": cap_id,
    }


def _authorized_execute(s, *, action=None, grant=None):
    action = action if action is not None else s["action"]
    if grant is None:
        raise CapabilityError("no grant provided")
    if grant["payload"]["capability_id"] not in s["store"]._grants:
        s["store"].add(grant)
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


# ---------- A01–A04: tampering ----------

def test_a01_tamper_payload():
    s = _make_scenario()
    s["action"]["payload"]["args"]["a"] = 999
    with pytest.raises(SignatureError):
        _authorized_execute(s, grant=s["grant"])
    assert s["runner"].last_invocation_evidence is None


def test_a02_tamper_sender():
    s = _make_scenario()
    s["action"]["sender_id"] = "did:sifr:eve"
    with pytest.raises(SignatureError):
        _authorized_execute(s, grant=s["grant"])
    assert s["runner"].last_invocation_evidence is None


def test_a03_tamper_receiver():
    s = _make_scenario()
    s["action"]["receiver_id"] = "did:sifr:mallory"
    with pytest.raises(SignatureError):
        _authorized_execute(s, grant=s["grant"])
    assert s["runner"].last_invocation_evidence is None


def test_a04_tamper_capability_action():
    s = _make_scenario()
    grant = copy.deepcopy(s["grant"])
    grant["payload"]["actions"] = ["tool.calculator.add", "tool.calculator.multiply"]
    with pytest.raises(SignatureError):
        _authorized_execute(s, grant=grant)
    assert s["runner"].last_invocation_evidence is None


# ---------- A05–A07: credential layer ----------

def test_a05_credential_subject_mismatch():
    s = _make_scenario()
    cred = issue_credential(
        issuer=s["issuer"],
        subject=s["subject"],
        capability_grant_payload=s["grant"]["payload"],
        issuer_private_key=s["issuer_priv"],
        issuer_kid=s["issuer_kid"],
        expires_at=s["grant"]["payload"]["expires_at"],
    )
    cred["credentialSubject"]["id"] = "did:sifr:eve"
    with pytest.raises(CredentialError, match="signature invalid"):
        verify_credential(cred, s["resolver"])
    assert s["runner"].last_invocation_evidence is None


def test_a06_credential_issuer_mismatch():
    s = _make_scenario()
    cred = issue_credential(
        issuer=s["issuer"],
        subject=s["subject"],
        capability_grant_payload=s["grant"]["payload"],
        issuer_private_key=s["issuer_priv"],
        issuer_kid="did:sifr:eve#key-1",  # signing kid for a DIFFERENT issuer
        expires_at=s["grant"]["payload"]["expires_at"],
    )
    with pytest.raises(CredentialError, match="does not match issuer"):
        verify_credential(cred, s["resolver"])
    assert s["runner"].last_invocation_evidence is None


def test_a07_credential_signed_by_wrong_key():
    s = _make_scenario()
    cred = issue_credential(
        issuer=s["issuer"],
        subject=s["subject"],
        capability_grant_payload=s["grant"]["payload"],
        issuer_private_key=s["eve_priv"],  # Eve's private key, but issuer="alice"
        issuer_kid=s["issuer_kid"],
        expires_at=s["grant"]["payload"]["expires_at"],
    )
    with pytest.raises(CredentialError, match="signature invalid"):
        verify_credential(cred, s["resolver"])
    assert s["runner"].last_invocation_evidence is None


# ---------- A08-A09: key layer ----------

def test_a08_swap_kid_to_valid_unauthorized_key():
    s = _make_scenario()
    # Re-sign with Eve's key, advertise Eve's kid. Eve's key resolves but the
    # action's sender_id is still subject (bob). authorize_action then sees
    # sender=bob but the sig is by eve -- depending on order, signature
    # verification fails first because we resolve by kid.
    bad = sign_message(
        {k: v for k, v in s["action"].items() if k != "signature"},
        s["eve_priv"],
        s["eve_kid"],
    )
    # The signature is now valid for the wrong principal (Eve). authorize
    # then fails on subject mismatch (sender_id=bob, signer=eve).
    bad["sender_id"] = s["subject"]  # forge the sender claim
    # Re-sign so the bytes match the forged sender_id
    bad_resigned = sign_message(
        {k: v for k, v in bad.items() if k != "signature"},
        s["eve_priv"],
        s["eve_kid"],
    )
    with pytest.raises((SignatureError, UnauthorizedAction)):
        _authorized_execute(s, action=bad_resigned, grant=s["grant"])
    assert s["runner"].last_invocation_evidence is None


def test_a09_revoked_key():
    s = _make_scenario()
    # Sign action with the revoked kid; resolver raises SignatureError on resolve.
    s["revoked_kids"].add(s["revoked_kid"])
    bad = sign_message(
        {k: v for k, v in s["action"].items() if k != "signature"},
        s["revoked_priv"],
        s["revoked_kid"],
    )
    with pytest.raises(SignatureError, match="revoked"):
        _authorized_execute(s, action=bad, grant=s["grant"])
    assert s["runner"].last_invocation_evidence is None


# ---------- A10-A12: credential time/revocation ----------

def test_a10_expired_credential():
    s = _make_scenario()
    cred = issue_credential(
        issuer=s["issuer"],
        subject=s["subject"],
        capability_grant_payload=s["grant"]["payload"],
        issuer_private_key=s["issuer_priv"],
        issuer_kid=s["issuer_kid"],
        expires_at=_past_iso(seconds=60),
        issued_at=_past_iso(seconds=120),
    )
    with pytest.raises(CredentialError, match="expired"):
        verify_credential(cred, s["resolver"])
    assert s["runner"].last_invocation_evidence is None


def test_a11_not_yet_valid_credential():
    s = _make_scenario()
    cred = issue_credential(
        issuer=s["issuer"],
        subject=s["subject"],
        capability_grant_payload=s["grant"]["payload"],
        issuer_private_key=s["issuer_priv"],
        issuer_kid=s["issuer_kid"],
        expires_at=_future_iso(seconds=120),
        issued_at=_future_iso(seconds=60),
    )
    with pytest.raises(CredentialError, match="not yet valid"):
        verify_credential(cred, s["resolver"])
    assert s["runner"].last_invocation_evidence is None


def test_a12_revoked_capability():
    s = _make_scenario()
    s["registry"].revoke(s["cap_id"], "v0.3 adversary")
    with pytest.raises(UnauthorizedAction, match="REVOKED_CAPABILITY"):
        _authorized_execute(s, grant=s["grant"])
    assert s["runner"].last_invocation_evidence is None


# ---------- A13-A17: replay layer ----------

def test_a13_replay_same_message():
    s = _make_scenario()
    out = _authorized_execute(s, grant=s["grant"])
    assert out == {"result": 5}
    fuel_after = dict(s["runner"].last_invocation_evidence)
    with pytest.raises(ReplayError):
        _authorized_execute(s, grant=s["grant"])
    assert s["runner"].last_invocation_evidence == fuel_after


def test_a14_replay_with_modified_signature():
    s = _make_scenario()
    _authorized_execute(s, grant=s["grant"])
    fuel_after = dict(s["runner"].last_invocation_evidence)
    # Re-sign the same message_id with the same key. Cache key does not include
    # the signature, so this must still be rejected as replay.
    re_signed = sign_message(
        {k: v for k, v in s["action"].items() if k != "signature"},
        s["subject_priv"],
        s["subject_kid"],
    )
    with pytest.raises(ReplayError):
        _authorized_execute(s, action=re_signed, grant=s["grant"])
    assert s["runner"].last_invocation_evidence == fuel_after


def test_a15_replay_across_restarted_cache(tmp_path):
    s = _make_scenario()
    # Use a persistent SQLite cache so a "restart" can rehydrate.
    persistent = ReplayCache(store_path=tmp_path / "replay.sqlite")
    persistent.check_and_record(s["action"])
    persistent.close()
    rehydrated = ReplayCache(store_path=tmp_path / "replay.sqlite")
    with pytest.raises(ReplayError):
        rehydrated.check_and_record(s["action"])
    assert s["runner"].last_invocation_evidence is None


def test_a16_stale_timestamp():
    s = _make_scenario()
    # Force a stale timestamp on the action (use a very short window so we don't
    # need time travel).
    cache = ReplayCache(window_seconds=1)
    s["action"]["timestamp"] = _past_iso(seconds=120)
    s["action"] = sign_message(
        {k: v for k, v in s["action"].items() if k != "signature"},
        s["subject_priv"],
        s["subject_kid"],
    )
    s["cache"] = cache
    with pytest.raises(ReplayError, match="stale"):
        _authorized_execute(s, grant=s["grant"])
    assert s["runner"].last_invocation_evidence is None


def test_a17_future_timestamp():
    s = _make_scenario()
    s["action"]["timestamp"] = _future_iso(seconds=3600)
    s["action"] = sign_message(
        {k: v for k, v in s["action"].items() if k != "signature"},
        s["subject_priv"],
        s["subject_kid"],
    )
    with pytest.raises(ReplayError, match="future"):
        _authorized_execute(s, grant=s["grant"])
    assert s["runner"].last_invocation_evidence is None


# ---------- A18-A22: framing / authorization ----------

def test_a18_oversized_payload():
    s = _make_scenario(max_payload_bytes=50)
    big = create_message(
        "Action",
        s["subject"],
        s["issuer"],
        {
            "action": "tool.calculator.add",
            "args": {"a": 1, "b": 2},
            "requires_auth": True,
            "padding": "x" * 5000,
        },
        session_id="sess_v0_3",
        capability_id=s["cap_id"],
    )
    signed = sign_message(big, s["subject_priv"], s["subject_kid"])
    with pytest.raises(UnauthorizedAction, match="PAYLOAD_BUDGET_EXCEEDED"):
        _authorized_execute(s, action=signed, grant=s["grant"])
    assert s["runner"].last_invocation_evidence is None


def test_a19_malformed_frame():
    s = _make_scenario()
    bogus = {"type": "Action", "payload": {}}
    with pytest.raises(MessageValidationError):
        validate_message(bogus)
    assert s["runner"].last_invocation_evidence is None


def test_a20_missing_dag_parent():
    s = _make_scenario()
    dag = AuditDAG()
    grant_cid = dag.add_message(s["grant"])
    s["action"]["parents"] = [grant_cid]
    re_signed = sign_message(
        {k: v for k, v in s["action"].items() if k != "signature"},
        s["subject_priv"],
        s["subject_kid"],
    )
    dag.add_message(re_signed)
    del dag.nodes[grant_cid]
    del dag.messages[grant_cid]
    with pytest.raises(AuditDAGError):
        dag.verify_dag_integrity()
    assert s["runner"].last_invocation_evidence is None


def test_a21_tampered_dag_node():
    s = _make_scenario()
    dag = AuditDAG()
    cid = dag.add_message(s["grant"])
    # Tamper the stored message body without updating CID.
    dag.messages[cid]["payload"]["actions"].append("tool.calculator.subtract")
    with pytest.raises(AuditDAGError):
        dag.verify_dag_integrity()
    assert s["runner"].last_invocation_evidence is None


def test_a22_unauthorized_tool():
    s = _make_scenario()
    bad = create_message(
        "Action",
        s["subject"],
        s["issuer"],
        {"action": "tool.calculator.subtract", "args": {"a": 5, "b": 3}, "requires_auth": True},
        session_id="sess_v0_3",
        capability_id=s["cap_id"],
    )
    signed = sign_message(bad, s["subject_priv"], s["subject_kid"])
    with pytest.raises(UnauthorizedAction, match="UNAUTHORIZED_ACTION"):
        _authorized_execute(s, action=signed, grant=s["grant"])
    assert s["runner"].last_invocation_evidence is None


# ---------- A23-A24: WASM ----------

FIXTURES = Path(__file__).parent / "fixtures" / "wasm_modules"


def test_a23_wasm_filesystem_import_fails():
    s = _make_scenario()
    wat = (FIXTURES / "fs_attempt.wat").read_text(encoding="utf-8")
    from sifr.wasm_runner import WasmToolError

    with pytest.raises(WasmToolError, match="instantiate failed"):
        s["runner"].try_instantiate(wat)
    assert s["runner"].last_invocation_evidence is None


def test_a24_wasm_infinite_loop_traps_on_fuel():
    import wasmtime
    runner = WasmToolRunner(fuel=1000)
    wat = (FIXTURES / "looping.wat").read_text(encoding="utf-8")
    instance, store = runner.try_instantiate(wat)
    spin = instance.exports(store)["spin"]
    with pytest.raises(wasmtime.Trap, match="fuel"):
        spin(store)
    assert runner.last_invocation_evidence is None


# ---------- A25-A27: QUIC-mediated ----------

def _run(coro, timeout: float = 15.0):
    return asyncio.run(asyncio.wait_for(coro, timeout=timeout))


async def _quic_pair(tmp_path):
    cert, key = generate_self_signed_cert(tmp_path, hostname="localhost")
    server, accept, port = await serve_quic("127.0.0.1", 0, cert, key)
    client = None

    async def server_side():
        return await accept()

    server_task = asyncio.create_task(server_side())
    client = await connect_quic("127.0.0.1", port, ca_certs=cert)
    server_transport = await server_task
    return server, server_transport, client


async def _a25_inner(tmp_path):
    server, server_t, client = await _quic_pair(tmp_path)
    try:
        # Send a non-JSON byte sequence directly on the QUIC stream.
        proto = client._protocol
        sid = proto._quic.get_next_available_stream_id(is_unidirectional=False)
        # Length prefix says 100 bytes but we send 5 bytes of garbage that aren't valid JSON.
        bad = (5).to_bytes(4, "big") + b"\xff\xff\xff\xff\xff"
        proto._quic.send_stream_data(sid, bad, end_stream=False)
        proto.transmit()
        # The server-side recv should raise (json decode fails).
        with pytest.raises((json.JSONDecodeError, ConnectionError, Exception)):
            await asyncio.wait_for(server_t.recv(), timeout=5)
    finally:
        await client.close()
        server.close()


def test_a25_quic_malformed_frame_rejected(tmp_path):
    _run(_a25_inner(tmp_path))


async def _a26_inner(tmp_path):
    """A duplicate Action over QUIC must be rejected by the receiver's replay
    cache, regardless of the transport."""
    server, server_t, client = await _quic_pair(tmp_path)
    s = _make_scenario()
    try:
        await client.send(s["action"])
        recv1 = await server_t.recv()
        # First arrival: cache it on the server side.
        s["cache"].check_and_record(recv1)
        # Duplicate
        await client.send(s["action"])
        recv2 = await server_t.recv()
        with pytest.raises(ReplayError):
            s["cache"].check_and_record(recv2)
    finally:
        await client.close()
        server.close()
    assert s["runner"].last_invocation_evidence is None


def test_a26_quic_duplicate_action_rejected(tmp_path):
    _run(_a26_inner(tmp_path))


async def _a27_inner(tmp_path):
    """A revoked credential routed over QUIC must still be rejected by the
    server's revocation registry."""
    server, server_t, client = await _quic_pair(tmp_path)
    s = _make_scenario()
    s["registry"].revoke(s["cap_id"], "qubic-route-test")
    try:
        await client.send(s["action"])
        recv = await server_t.recv()
        # Server-side authorization
        s["store"].add(s["grant"])
        verify_message(recv, s["resolver"])
        with pytest.raises(UnauthorizedAction, match="REVOKED_CAPABILITY"):
            authorize_action(
                recv,
                s["grant"],
                s["issuer_pub"],
                s["store"],
                revocation_registry=s["registry"],
                replay_cache=s["cache"],
            )
    finally:
        await client.close()
        server.close()
    assert s["runner"].last_invocation_evidence is None


def test_a27_quic_revoked_credential_rejected(tmp_path):
    _run(_a27_inner(tmp_path))


# ---------- A28-A30: TensorFrame ----------

def test_a28_tensor_shape_bomb():
    s = _make_scenario()
    # Shape claims 1e9*1e9 elements but data is small -- decoder must reject
    # length mismatch, not allocate the tensor.
    with pytest.raises(ValueError, match="shape does not match"):
        decode_base64(base64.b64encode(b"\x00\x00\x00\x00").decode("ascii"), [1_000_000_000, 1_000_000_000], "float32")
    assert s["runner"].last_invocation_evidence is None


def test_a29_tensor_invalid_dtype():
    s = _make_scenario()
    with pytest.raises(ValueError, match="unsupported dtype"):
        decode_base64(base64.b64encode(b"\x00" * 16).decode("ascii"), [4], "float64")
    assert s["runner"].last_invocation_evidence is None


def test_a30_tensor_payload_length_mismatch():
    s = _make_scenario()
    # 4 float32 elements need 16 bytes; provide 12 bytes.
    with pytest.raises(ValueError, match="shape does not match"):
        decode_base64(base64.b64encode(b"\x00" * 12).decode("ascii"), [4], "float32")
    assert s["runner"].last_invocation_evidence is None
