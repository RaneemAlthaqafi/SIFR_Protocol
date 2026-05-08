"""SIFR v0.2 Secure Flow Demo.

End-to-end vertical slice over real QUIC transport. Implements section 2 of
docs/full_security_implementation_prompt.md.

Two agents:
- Alice (client / capability subject): sends Hello and Action, receives the
  capability credential and Observation.
- Bob (server / capability issuer + tool host): receives Hello, sends Hello
  back, issues the credential, runs the action through replay + revocation
  + authorization checks, executes the WASM calculator, returns a signed
  Observation.

Each successful step prints "<step>: OK". Any failure raises and prints the
exception; the demo exits non-zero.
"""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from sifr.audit_dag import AuditDAG
from sifr.capabilities import CapabilityStore, authorize_action, create_capability_grant
from sifr.credentials import issue_credential, verify_credential
from sifr.crypto import public_key_to_b64, sign_message, verify_message
from sifr.did.did_sifr import DidSifrResolver
from sifr.errors import UnauthorizedAction
from sifr.key_management import TEST_ARGON2_PARAMS, EncryptedFileKeyStore
from sifr.messages import create_message
from sifr.replay import ReplayCache
from sifr.revocation import RevocationRegistry
from sifr.transport._certs import generate_self_signed_cert
from sifr.transport.quic import connect_quic, serve_quic
from sifr.wasm_runner import WasmToolRunner

ALICE = "did:sifr:alice"
BOB = "did:sifr:bob"
ALICE_KID = f"{ALICE}#key-1"
BOB_KID = f"{BOB}#key-1"
SESSION = "sess_demo"


def _write_did_doc(root: Path, did: str, kid: str, pub_b64: str) -> None:
    name = did[len("did:sifr:"):]
    doc = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": kid,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyBase64": pub_b64,
            }
        ],
    }
    (root / f"{name}.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")


def _future_iso(seconds: int = 600) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


async def main() -> int:
    print("=== SIFR v0.2 Secure Flow Demo ===")

    status: dict[str, str] = {
        "did": "PENDING",
        "quic": "PENDING",
        "hello_sig": "PENDING",
        "credential": "PENDING",
        "replay": "PENDING",
        "revocation": "PENDING",
        "authorized": "PENDING",
        "wasm": "PENDING",
        "observation": "PENDING",
        "audit_dag": "PENDING",
    }
    result_value: int | None = None

    with tempfile.TemporaryDirectory() as td_str:
        td = Path(td_str)

        alice_keys = EncryptedFileKeyStore(td / "alice_keys.json", "alice-pass", argon2_params=TEST_ARGON2_PARAMS)
        bob_keys = EncryptedFileKeyStore(td / "bob_keys.json", "bob-pass", argon2_params=TEST_ARGON2_PARAMS)
        alice_pub = alice_keys.generate_keypair(ALICE_KID)
        bob_pub = bob_keys.generate_keypair(BOB_KID)
        alice_priv = alice_keys.load_private_key(ALICE_KID)
        bob_priv = bob_keys.load_private_key(BOB_KID)

        did_dir = td / "dids"
        did_dir.mkdir()
        _write_did_doc(did_dir, ALICE, ALICE_KID, public_key_to_b64(alice_pub))
        _write_did_doc(did_dir, BOB, BOB_KID, public_key_to_b64(bob_pub))

        alice_resolver = DidSifrResolver(did_dir)
        bob_resolver = DidSifrResolver(did_dir)
        assert public_key_to_b64(alice_resolver.resolve(BOB_KID)) == public_key_to_b64(bob_pub)
        assert public_key_to_b64(bob_resolver.resolve(ALICE_KID)) == public_key_to_b64(alice_pub)
        status["did"] = "OK"

        cert, key = generate_self_signed_cert(td / "certs", hostname="localhost")
        server, accept, port = await serve_quic("127.0.0.1", 0, cert, key)

        store = CapabilityStore()
        replay_cache = ReplayCache()
        registry = RevocationRegistry(
            issuer=BOB,
            issuer_kid=BOB_KID,
            issuer_private_key=bob_priv,
            verifier_key=bob_pub,
        )
        runner = WasmToolRunner()
        dag = AuditDAG()

        async def server_role():
            t = await accept()
            assert t.negotiated_alpn == "sifr/0.2"
            status["quic"] = "OK"

            client_hello = await t.recv()
            verify_message(client_hello, alice_resolver)
            status["hello_sig"] = "OK"
            dag.add_message(client_hello)

            own_hello = create_message("Hello", BOB, ALICE, {"version": "sifr/0.2"}, session_id=SESSION)
            signed_own_hello = sign_message(own_hello, bob_priv, BOB_KID)
            await t.send(signed_own_hello)
            dag.add_message(signed_own_hello)

            grant = create_capability_grant(
                issuer=BOB,
                subject=ALICE,
                actions=["tool.calculator.add"],
                resource_scope=["calculator"],
                issuer_private_key=bob_priv,
                receiver_id=ALICE,
                session_id=SESSION,
                expires_at=_future_iso(),
                max_calls=3,
                max_payload_bytes=1024,
            )
            store.add(grant)
            cred = issue_credential(
                issuer=BOB,
                subject=ALICE,
                capability_grant_payload=grant["payload"],
                issuer_private_key=bob_priv,
                issuer_kid=BOB_KID,
                expires_at=grant["payload"]["expires_at"],
            )
            offer = create_message(
                "CapabilityOffer",
                BOB,
                ALICE,
                {"credential": cred, "grant": grant},
                session_id=SESSION,
                capability_id=grant["payload"]["capability_id"],
            )
            signed_offer = sign_message(offer, bob_priv, BOB_KID)
            await t.send(signed_offer)
            dag.add_message(signed_offer)
            dag.add_message(grant)

            action = await t.recv()
            verify_message(action, alice_resolver)
            dag.add_message(action)

            replay_cache.check_and_record(action)
            status["replay"] = "OK"

            cap_id = action["capability_id"]
            if registry.is_revoked(cap_id) is not None:
                raise UnauthorizedAction("REVOKED_CAPABILITY")
            status["revocation"] = "OK"

            authorize_action(action, grant, bob_pub, store)
            status["authorized"] = "OK"

            result = runner.execute("tool.calculator.add", action["payload"]["args"])
            assert runner.last_invocation_evidence is not None
            assert runner.last_invocation_evidence["fuel_consumed"] > 0
            status["wasm"] = "OK"

            obs = create_message(
                "Observation",
                BOB,
                ALICE,
                {"result": result["result"], "for_action": action["message_id"]},
                session_id=SESSION,
                capability_id=cap_id,
                parents=[dag.add_message(action) if False else action["message_id"]],  # noop, kept for clarity
            )
            obs["parents"] = [list(dag.nodes.keys())[-1]]
            signed_obs = sign_message(obs, bob_priv, BOB_KID)
            await t.send(signed_obs)
            dag.add_message(signed_obs)
            return result["result"]

        async def client_role():
            nonlocal result_value
            t = await connect_quic("127.0.0.1", port, ca_certs=cert)

            hello = create_message("Hello", ALICE, BOB, {"version": "sifr/0.2"}, session_id=SESSION)
            signed_hello = sign_message(hello, alice_priv, ALICE_KID)
            await t.send(signed_hello)

            bob_hello = await t.recv()
            verify_message(bob_hello, bob_resolver)

            offer = await t.recv()
            verify_message(offer, bob_resolver)
            cred = offer["payload"]["credential"]
            grant = offer["payload"]["grant"]
            verify_credential(cred, bob_resolver)
            status["credential"] = "OK"

            action = create_message(
                "Action",
                ALICE,
                BOB,
                {"action": "tool.calculator.add", "args": {"a": 2, "b": 3}, "requires_auth": True},
                session_id=SESSION,
                capability_id=grant["payload"]["capability_id"],
            )
            signed_action = sign_message(action, alice_priv, ALICE_KID)
            await t.send(signed_action)

            obs = await t.recv()
            verify_message(obs, bob_resolver)
            status["observation"] = "OK"
            result_value = obs["payload"]["result"]

            await t.close()

        try:
            server_result, _ = await asyncio.gather(server_role(), client_role())
        finally:
            server.close()

        try:
            dag.verify_dag_integrity()
            status["audit_dag"] = "OK"
        except Exception as exc:
            status["audit_dag"] = f"FAILED: {exc}"

        formal_present = "PRESENT" if (REPO_ROOT / "formal" / "sifr_capability.tla").is_file() else "PENDING"

    print(f"DID resolution: {status['did']}")
    print(f"QUIC session: {status['quic']}")
    print(f"Hello signature: {status['hello_sig']}")
    print(f"Capability credential: {status['credential']}")
    print(f"Replay check: {status['replay']}")
    print(f"Revocation check: {status['revocation']}")
    print(f"Action authorized: {status['authorized']}")
    print(f"WASM calculator executed: {status['wasm']}")
    print(f"Observation verified: {status['observation']}")
    print(f"Audit DAG integrity: {status['audit_dag']}")
    print(f"Formal model artifacts: {formal_present}")
    print(f"Result: {result_value}")

    runtime_steps_ok = all(
        status[k] == "OK"
        for k in (
            "did", "quic", "hello_sig", "credential",
            "replay", "revocation", "authorized",
            "wasm", "observation", "audit_dag",
        )
    )
    if runtime_steps_ok and result_value == 5:
        if formal_present == "PENDING":
            print("Demo completed successfully (formal model artifacts pending Phase 5).")
        else:
            print("Demo completed successfully.")
        return 0
    print("Demo FAILED: not all runtime steps reached OK.")
    return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
