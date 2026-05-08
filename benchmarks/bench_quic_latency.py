"""Benchmark sign+verify+DAG round-trip latency over LocalTransport, QUIC,
and the HTTP-JSON serialization baseline.

LocalTransport is in-process queues; QUIC is real wire-level traffic on
loopback; HTTP-JSON is the serialization-only baseline (no actual sockets).
"""
from __future__ import annotations

import asyncio
import csv
import json
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from sifr.audit_dag import AuditDAG
from sifr.crypto import generate_keypair, sign_message, verify_message
from sifr.messages import create_message
from sifr.transport import HttpJsonBaselineTransport, LocalTransport
from sifr.transport._certs import generate_self_signed_cert
from sifr.transport.quic import connect_quic, serve_quic


def _make_signed():
    priv, pub = generate_keypair()
    msg = create_message(
        "Thought",
        "did:sifr:a",
        "did:sifr:b",
        {"content": "hello", "confidence": 0.9},
    )
    return sign_message(msg, priv, "did:sifr:a#key-1"), pub


async def bench_local(n: int) -> dict:
    a, b = LocalTransport.pair()
    signed, pub = _make_signed()
    dag = AuditDAG()
    t0 = time.perf_counter()
    for _ in range(n):
        await a.send(signed)
        recv = await b.recv()
        verify_message(recv, pub)
        dag.add_message(recv)
    elapsed = time.perf_counter() - t0
    return {"transport": "local", "n": n, "avg_rtt_ms": round(elapsed / n * 1000, 4)}


async def bench_quic(n: int) -> dict:
    signed, pub = _make_signed()
    dag = AuditDAG()
    with tempfile.TemporaryDirectory() as td:
        cert, key = generate_self_signed_cert(td, hostname="localhost")
        server, accept, port = await serve_quic("127.0.0.1", 0, cert, key)
        try:

            async def server_side(t_count: int):
                t = await accept()
                for _ in range(t_count):
                    msg = await t.recv()
                    verify_message(msg, pub)
                    dag.add_message(msg)
                    await t.send({"ack": True})

            async def client_side(t_count: int):
                t = await connect_quic("127.0.0.1", port, ca_certs=cert)
                t0 = time.perf_counter()
                for _ in range(t_count):
                    await t.send(signed)
                    await t.recv()
                elapsed_inner = time.perf_counter() - t0
                await t.close()
                return elapsed_inner

            _, elapsed = await asyncio.gather(server_side(n), client_side(n))
        finally:
            server.close()
    return {
        "transport": "quic",
        "n": n,
        "avg_rtt_ms": round(elapsed / n * 1000, 4),
    }


def bench_http_json(n: int) -> dict:
    signed, pub = _make_signed()
    dag = AuditDAG()
    t0 = time.perf_counter()
    for _ in range(n):
        wire = HttpJsonBaselineTransport.serialize(signed)
        decoded = HttpJsonBaselineTransport.deserialize(wire)
        verify_message(decoded, pub)
        dag.add_message(decoded)
    elapsed = time.perf_counter() - t0
    return {
        "transport": "http-json-baseline",
        "n": n,
        "avg_rtt_ms": round(elapsed / n * 1000, 4),
    }


async def main_async() -> list[dict]:
    rows = []
    rows.append(await bench_local(2000))
    rows.append(bench_http_json(2000))
    rows.append(await bench_quic(500))
    return rows


def main() -> None:
    rows = asyncio.run(main_async())
    out = REPO_ROOT / "benchmarks" / "results" / "quic_latency.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {out}")
    for r in rows:
        print(f"  {r['transport']:20}  n={r['n']:>5}  avg_rtt={r['avg_rtt_ms']:.4f} ms")


if __name__ == "__main__":
    main()
