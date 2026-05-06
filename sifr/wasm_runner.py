from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class SandboxedToolRunner(ABC):
    @abstractmethod
    def execute(self, action: str, args: dict[str, Any]) -> dict[str, Any]:
        ...


class CalculatorTool(SandboxedToolRunner):
    """Safe Python stub for v0.1. WASM/WASI is documented as future work."""

    def execute(self, action: str, args: dict[str, Any]) -> dict[str, Any]:
        if action != "tool.calculator.add":
            raise ValueError("unsupported calculator action")
        a = args.get("a")
        b = args.get("b")
        if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
            raise ValueError("calculator arguments MUST be numeric")
        return {"result": a + b}
