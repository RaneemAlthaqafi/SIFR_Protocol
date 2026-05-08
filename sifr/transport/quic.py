"""QUIC transport using aioquic.

A bidirectional message-frame transport over a single QUIC stream. Each
message is serialized as a length-prefixed canonical-JSON frame: 4 bytes
big-endian uint32 length, then `length` bytes of UTF-8 JSON.

The transport exposes the underlying `aioquic.quic.connection.QuicConnection`
via `QuicTransport.quic_connection` for trap-acceptance tests that verify
real QUIC machinery is in use.

NOT FOR PRODUCTION as wired up here: `serve_quic` and `connect_quic` use
self-signed certs and (when `verify=False`) skip TLS verification. They are
suitable for tests, demos, and local research.
"""
from __future__ import annotations

import asyncio
import json
import ssl
from pathlib import Path
from typing import Any, Optional

import aioquic.asyncio
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted, StreamDataReceived

from ._base import Transport

__all__ = ["QuicTransport", "serve_quic", "connect_quic", "ALPN"]

ALPN = "sifr/0.2"


def _frame(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


class _FrameProtocol(aioquic.asyncio.QuicConnectionProtocol):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.inbox: asyncio.Queue[Optional[bytes]] = asyncio.Queue()
        self._buffer = b""
        self._inbound_stream_id: Optional[int] = None
        self.handshake_done: asyncio.Event = asyncio.Event()

    def quic_event_received(self, event: Any) -> None:
        if isinstance(event, HandshakeCompleted):
            self.handshake_done.set()
        elif isinstance(event, StreamDataReceived):
            if self._inbound_stream_id is None:
                self._inbound_stream_id = event.stream_id
            self._buffer += event.data
            while len(self._buffer) >= 4:
                length = int.from_bytes(self._buffer[:4], "big")
                if len(self._buffer) < 4 + length:
                    break
                frame = self._buffer[4 : 4 + length]
                self._buffer = self._buffer[4 + length :]
                self.inbox.put_nowait(frame)
        elif isinstance(event, ConnectionTerminated):
            self.inbox.put_nowait(None)


class QuicTransport(Transport):
    def __init__(self, protocol: _FrameProtocol, *, owner_ctx: Optional[Any] = None) -> None:
        self._protocol = protocol
        self._owner_ctx = owner_ctx
        self._send_stream_id: Optional[int] = None

    @property
    def quic_connection(self) -> Any:
        return self._protocol._quic

    @property
    def negotiated_alpn(self) -> Optional[str]:
        tls = getattr(self._protocol._quic, "tls", None)
        if tls is None:
            return None
        return getattr(tls, "alpn_negotiated", None)

    async def send(self, message: dict[str, Any]) -> None:
        body = json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if self._send_stream_id is None:
            self._send_stream_id = self._protocol._quic.get_next_available_stream_id(is_unidirectional=False)
        self._protocol._quic.send_stream_data(self._send_stream_id, _frame(body), end_stream=False)
        self._protocol.transmit()

    async def recv(self) -> dict[str, Any]:
        frame = await self._protocol.inbox.get()
        if frame is None:
            raise ConnectionError("peer disconnected")
        return json.loads(frame.decode("utf-8"))

    async def close(self) -> None:
        try:
            self._protocol.close()
        except Exception:
            pass
        if self._owner_ctx is not None:
            try:
                await self._owner_ctx.__aexit__(None, None, None)
            except Exception:
                pass
            self._owner_ctx = None


async def serve_quic(
    host: str,
    port: int,
    certfile: Path | str,
    keyfile: Path | str,
):
    """Start a QUIC server. Returns (server_handle, accept_coroutine, actual_port).

    `accept_coroutine()` returns a QuicTransport for the next client whose
    handshake has completed.
    """
    new_clients: asyncio.Queue[_FrameProtocol] = asyncio.Queue()

    class _ServerProtocol(_FrameProtocol):
        def connection_made(self, transport: Any) -> None:  # type: ignore[override]
            super().connection_made(transport)
            new_clients.put_nowait(self)

    config = QuicConfiguration(is_client=False, alpn_protocols=[ALPN])
    config.load_cert_chain(str(certfile), str(keyfile))

    server = await aioquic.asyncio.serve(
        host,
        port,
        configuration=config,
        create_protocol=_ServerProtocol,
    )
    transport_obj = getattr(server, "_transport", None)
    actual_port = transport_obj.get_extra_info("sockname")[1] if transport_obj is not None else port

    async def accept() -> QuicTransport:
        proto = await new_clients.get()
        await proto.handshake_done.wait()
        return QuicTransport(proto)

    return server, accept, actual_port


async def connect_quic(
    host: str,
    port: int,
    *,
    ca_certs: Optional[Path | str] = None,
    verify: bool = True,
) -> QuicTransport:
    config = QuicConfiguration(is_client=True, alpn_protocols=[ALPN])
    if ca_certs is not None:
        config.load_verify_locations(str(ca_certs))
    if not verify:
        config.verify_mode = ssl.CERT_NONE

    ctx = aioquic.asyncio.connect(
        host,
        port,
        configuration=config,
        create_protocol=_FrameProtocol,
    )
    proto = await ctx.__aenter__()
    try:
        await asyncio.wait_for(proto.handshake_done.wait(), timeout=10)
    except Exception:
        await ctx.__aexit__(None, None, None)
        raise
    return QuicTransport(proto, owner_ctx=ctx)
