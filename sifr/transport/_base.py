from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Transport(ABC):
    @abstractmethod
    async def send(self, message: dict[str, Any]) -> None:
        ...

    @abstractmethod
    async def recv(self) -> dict[str, Any]:
        ...
