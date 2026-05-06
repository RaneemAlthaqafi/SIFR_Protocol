from __future__ import annotations

import asyncio
import copy
import json
from abc import ABC, abstractmethod
from typing import Any


class Transport(ABC):
    @abstractmethod
    async def send(self, message: dict[str, Any]) -> None:
        ...

    @abstractmethod
    async def recv(self) -> dict[str, Any]:
        ...


class LocalTransport(Transport):
    def __init__(self, incoming: asyncio.Queue, outgoing: asyncio.Queue) -> None:
        self.incoming = incoming
        self.outgoing = outgoing

    @classmethod
    def pair(cls) -> tuple["LocalTransport", "LocalTransport"]:
        a_to_b: asyncio.Queue = asyncio.Queue()
        b_to_a: asyncio.Queue = asyncio.Queue()
        return cls(b_to_a, a_to_b), cls(a_to_b, b_to_a)

    async def send(self, message: dict[str, Any]) -> None:
        await self.outgoing.put(copy.deepcopy(message))

    async def recv(self) -> dict[str, Any]:
        return await self.incoming.get()


class HttpJsonBaselineTransport:
    """Serialization-only baseline; this is not a real HTTP implementation."""

    @staticmethod
    def serialize(message: dict[str, Any]) -> bytes:
        return json.dumps(message, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def deserialize(data: bytes) -> dict[str, Any]:
        return json.loads(data.decode("utf-8"))
