"""SIFR QUIC node entrypoint.

Modes (chosen via $SIFR_NODE_ROLE):
- server: bind 0.0.0.0:4433, accept one client, echo each signed message,
  on EOF print final marker and exit.
- client: connect to $SIFR_PEER_HOST:4433, send N signed messages with
  sign+verify+DAG round-trip timing, write CSV to /out/quic_rtt.csv.

Runs forever as `server` until the client side closes the connection.
"""
from __future__ import annotations

import asyncio
import csv
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, "/app")

from sifr.audit_dag import AuditDAG
from sifr.crypto import generate_keypair, sign_message, verify_message
from sifr.messages import create_message
from sifr.transport._certs import generate_self_signed_cert
from sifr.transport.quic import connect_quic, serve_quic


async def server_main() -> None:
    cert_dir = Path("/tmp/sifr_certs")
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert, key = generate_self_signed_cert(cert_dir, hostname="server")
    priv, pub = generate_keypair()

    server, accept, port = await serve_quic("0.0.0.0", 4433, cert, key)
    print(f"server listening 0.0.0.0:{port}", flush=True)
    transport = await accept()
    dag = AuditDAG()
    print("client connected", flush=True)
    try:
        while True:
            msg = await transport.recv()
            # The client embeds its own public key (this is a test transport
            # for measurement; production uses the resolver path).
            client_pub = verify_anyway(msg)
            verify_message(msg, client_pub)
            dag.add_message(msg)
            await transport.send({"ack": msg.get("message_id")})
    except ConnectionError:
        print("server: client disconnected", flush=True)


def verify_anyway(msg):
    """Test-mode: verify without resolver. The client sends with its OWN private
    key and embeds its public key in the message for trust-on-first-receive
    over loopback. We trust the embedded key for measurement only.
    """
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    pub_b64 = msg.get("_test_pub_key")
    if not pub_b64:
        raise RuntimeError("missing _test_pub_key (test-mode requirement)")
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
    return pub


async def client_main() -> None:
    peer = os.environ.get("SIFR_PEER_HOST", "server")
    port = int(os.environ.get("SIFR_PEER_PORT", "4433"))
    n = int(os.environ.get("SIFR_BENCH_N", "100"))
    out = Path(os.environ.get("SIFR_OUT_PATH", "/out/quic_rtt.csv"))
    label = os.environ.get("SIFR_BENCH_LABEL", "container_baseline")

    out.parent.mkdir(parents=True, exist_ok=True)
    priv, pub = generate_keypair()
    import base64
    pub_b64 = base64.b64encode(
        pub.public_bytes(
            __import__("cryptography").hazmat.primitives.serialization.Encoding.Raw,
            __import__("cryptography").hazmat.primitives.serialization.PublicFormat.Raw,
        )
    ).decode("ascii")

    msg_template = create_message(
        "Thought",
        "did:sifr:client_no_check",
        "did:sifr:server",
        {"content": "ping", "confidence": 0.9},
    )
    msg_template["_test_pub_key"] = pub_b64

    print(f"client connecting to {peer}:{port} (label={label}, n={n})", flush=True)
    # Wait for server to bind. Try a short loop.
    for _ in range(20):
        try:
            transport = await connect_quic(peer, port, verify=False)
            break
        except Exception as exc:
            await asyncio.sleep(0.5)
    else:
        raise RuntimeError(f"could not connect to {peer}:{port}")
    print("client connected", flush=True)
    dag = AuditDAG()

    rtts: list[float] = []
    for i in range(n):
        msg = dict(msg_template)
        msg["payload"] = {"content": f"ping {i}", "confidence": 0.9}
        signed = sign_message(msg, priv, "did:sifr:client_no_check#key-1")
        t0 = time.perf_counter()
        await transport.send(signed)
        ack = await transport.recv()
        dag.add_message(signed)
        rtts.append(time.perf_counter() - t0)

    avg_ms = sum(rtts) / len(rtts) * 1000
    p95_ms = sorted(rtts)[int(0.95 * len(rtts))] * 1000

    write_header = not out.is_file() or out.stat().st_size == 0
    with out.open("a", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        if write_header:
            w.writerow(["label", "n", "avg_rtt_ms", "p95_rtt_ms"])
        w.writerow([label, n, round(avg_ms, 4), round(p95_ms, 4)])
    print(f"label={label} n={n} avg_rtt_ms={avg_ms:.4f} p95_rtt_ms={p95_ms:.4f}", flush=True)

    await transport.close()


def setup_netem() -> None:
    import quic_runner

    rc = quic_runner.main()
    if rc != 0:
        raise RuntimeError(f"NetEm setup failed with exit code {rc}")


def main() -> int:
    setup_netem()
    role = os.environ.get("SIFR_NODE_ROLE", "server")
    if role == "server":
        asyncio.run(server_main())
    elif role == "client":
        asyncio.run(client_main())
    else:
        print(f"unknown SIFR_NODE_ROLE: {role}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
