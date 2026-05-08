"""Phase 4 minimal QUIC demo: two agents exchange a few signed messages.

This is the "QUIC works" smoke test. The full security flow is in
demo_secure_quic_wasm_did_flow.py.

Run:
    python examples/demo_quic_two_agents.py
"""
from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sifr.crypto import generate_keypair, sign_message, verify_message
from sifr.messages import create_message
from sifr.transport._certs import generate_self_signed_cert
from sifr.transport.quic import connect_quic, serve_quic


async def main() -> int:
    alice_priv, alice_pub = generate_keypair()
    bob_priv, bob_pub = generate_keypair()

    with tempfile.TemporaryDirectory() as td:
        cert, key = generate_self_signed_cert(td, hostname="localhost")
        server, accept, port = await serve_quic("127.0.0.1", 0, cert, key)
        print(f"server bound on 127.0.0.1:{port}")

        async def server_side():
            t = await accept()
            print(f"server: handshake done, ALPN={t.negotiated_alpn}")
            for _ in range(3):
                signed = await t.recv()
                verify_message(signed, alice_pub)
                print(f"server: received valid signed message #{signed['payload']['n']}")
                reply = create_message(
                    "Observation",
                    "did:sifr:bob",
                    "did:sifr:alice",
                    {"echo_of": signed["payload"]["n"]},
                )
                await t.send(sign_message(reply, bob_priv, "did:sifr:bob#key-1"))

        async def client_side():
            t = await connect_quic("127.0.0.1", port, ca_certs=cert)
            print(f"client: handshake done, ALPN={t.negotiated_alpn}")
            for n in range(3):
                msg = create_message(
                    "Thought",
                    "did:sifr:alice",
                    "did:sifr:bob",
                    {"n": n, "content": f"thought #{n}", "confidence": 0.9},
                )
                await t.send(sign_message(msg, alice_priv, "did:sifr:alice#key-1"))
                reply = await t.recv()
                verify_message(reply, bob_pub)
                print(f"client: round-trip {n} -> echo_of={reply['payload']['echo_of']}")
            await t.close()

        await asyncio.gather(server_side(), client_side())
        server.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
