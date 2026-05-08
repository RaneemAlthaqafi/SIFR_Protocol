from __future__ import annotations

import asyncio
import sys

import pytest
from aioquic.quic.connection import QuicConnection

from sifr.transport._certs import generate_self_signed_cert
from sifr.transport.quic import connect_quic, serve_quic


def _run(coro, timeout: float = 15.0):
    return asyncio.run(asyncio.wait_for(coro, timeout=timeout))


async def _bidir(tmp_path):
    cert, key = generate_self_signed_cert(tmp_path)
    server, accept, port = await serve_quic("127.0.0.1", 0, cert, key)

    async def server_side():
        t = await accept()
        msg = await t.recv()
        await t.send({"reply": msg["q"] * 2})

    server_task = asyncio.create_task(server_side())
    client = await connect_quic("127.0.0.1", port, ca_certs=cert)
    try:
        await client.send({"q": 21})
        reply = await client.recv()
        assert reply == {"reply": 42}
        return client
    finally:
        await server_task
        server.close()


def test_quic_handshake_and_bidirectional_roundtrip(tmp_path):
    client = _run(_bidir(tmp_path))


async def _check_real_quic(tmp_path):
    cert, key = generate_self_signed_cert(tmp_path)
    server, accept, port = await serve_quic("127.0.0.1", 0, cert, key)

    async def server_side():
        t = await accept()
        await t.recv()

    server_task = asyncio.create_task(server_side())
    client = await connect_quic("127.0.0.1", port, ca_certs=cert)
    try:
        await client.send({"hello": "world"})
        # Trap-acceptance: this MUST be a real QuicConnection from aioquic.
        assert isinstance(client.quic_connection, QuicConnection), (
            "QuicTransport.quic_connection is not aioquic's QuicConnection"
        )
        assert client.negotiated_alpn == "sifr/0.2", (
            f"ALPN must be sifr/0.2, got {client.negotiated_alpn!r}"
        )
        # Real handshake produces a destination connection ID.
        odcid = client.quic_connection.original_destination_connection_id
        assert odcid is not None and len(odcid) > 0, (
            "QuicConnection has no original_destination_connection_id; handshake did not happen"
        )
    finally:
        await server_task
        server.close()


def test_quic_uses_real_aioquic(tmp_path):
    _run(_check_real_quic(tmp_path))


async def _multiple_messages(tmp_path):
    cert, key = generate_self_signed_cert(tmp_path)
    server, accept, port = await serve_quic("127.0.0.1", 0, cert, key)

    async def server_side():
        t = await accept()
        for _ in range(5):
            msg = await t.recv()
            await t.send({"echo": msg["i"]})

    server_task = asyncio.create_task(server_side())
    client = await connect_quic("127.0.0.1", port, ca_certs=cert)
    try:
        for i in range(5):
            await client.send({"i": i})
            r = await client.recv()
            assert r == {"echo": i}
    finally:
        await server_task
        server.close()


def test_quic_multiple_messages(tmp_path):
    _run(_multiple_messages(tmp_path))


async def _unverified_cert_rejected(tmp_path):
    cert, key = generate_self_signed_cert(tmp_path)
    other_cert, other_key = generate_self_signed_cert(tmp_path / "other")
    server, accept, port = await serve_quic("127.0.0.1", 0, cert, key)
    try:
        # Use the OTHER cert as CA — verification must fail at handshake.
        with pytest.raises(Exception):
            await asyncio.wait_for(
                connect_quic("127.0.0.1", port, ca_certs=other_cert), timeout=5
            )
    finally:
        server.close()


def test_quic_bad_ca_rejected(tmp_path):
    _run(_unverified_cert_rejected(tmp_path), timeout=20.0)


async def _peer_disconnect(tmp_path):
    cert, key = generate_self_signed_cert(tmp_path)
    server, accept, port = await serve_quic("127.0.0.1", 0, cert, key)

    async def server_side():
        t = await accept()
        await t.recv()
        # close immediately after first message
        await t.close()

    server_task = asyncio.create_task(server_side())
    client = await connect_quic("127.0.0.1", port, ca_certs=cert)
    try:
        await client.send({"hello": "world"})
        await asyncio.sleep(0.5)  # let server close
        with pytest.raises(ConnectionError):
            await asyncio.wait_for(client.recv(), timeout=5)
    finally:
        await server_task
        server.close()


def test_quic_peer_disconnect_recv_raises(tmp_path):
    _run(_peer_disconnect(tmp_path))
