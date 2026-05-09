"""Sandboxed tool execution.

Two implementations:

- `PythonCalculatorReference`: pure-Python parity reference. Used in tests to
  cross-check the WASM result. NOT sandboxed; do not use in adversarial
  settings.
- `WasmToolRunner`: real WASM/WASI sandbox via `wasmtime`. No WASI imports
  are linked, so modules cannot reach the host filesystem, network, or
  environment. Per-call fuel limit bounds compute time.

Trap-acceptance: `WasmToolRunner.last_invocation_evidence` is set on every
successful execute call, with the actual fuel consumed. Tests assert that
fuel_consumed > 0, which proves WASM (not Python) actually ran.

A backwards-compatible alias `CalculatorTool = PythonCalculatorReference`
is kept so v0.1 demos still import correctly.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Optional

import wasmtime

__all__ = [
    "SandboxedToolRunner",
    "PythonCalculatorReference",
    "CalculatorTool",
    "WasmToolError",
    "WasmFuelExhausted",
    "WasmToolRunner",
]


class WasmToolError(Exception):
    pass


class WasmFuelExhausted(WasmToolError):
    pass


class SandboxedToolRunner(ABC):
    @abstractmethod
    def execute(self, action: str, args: dict[str, Any]) -> dict[str, Any]:
        ...


class PythonCalculatorReference(SandboxedToolRunner):
    """Python implementation. Used as a parity reference for WasmToolRunner.

    NOT sandboxed. Do NOT use in adversarial settings — use WasmToolRunner.
    """

    def execute(self, action: str, args: dict[str, Any]) -> dict[str, Any]:
        if action != "tool.calculator.add":
            raise ValueError(f"unsupported calculator action: {action}")
        a = args.get("a")
        b = args.get("b")
        if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
            raise ValueError("calculator arguments MUST be numeric")
        return {"result": a + b}


CalculatorTool = PythonCalculatorReference  # back-compat alias for v0.1 demo


_DEFAULT_WASM_DIR = Path(__file__).resolve().parent.parent / "wasm" / "calculator"


class WasmToolRunner(SandboxedToolRunner):
    DEFAULT_FUEL = 1_000_000
    # 16 wasm pages = 1 MiB. Calculator never grows; adversarial modules
    # asking for hundreds of MiB are denied at memory.grow time.
    DEFAULT_MEMORY_PAGE_LIMIT = 16

    SUPPORTED_TOOLS: dict[str, str] = {
        "tool.calculator.add": "calculator.wat",
    }

    def __init__(
        self,
        *,
        modules_dir: Optional[Path | str] = None,
        fuel: int = DEFAULT_FUEL,
        memory_page_limit: int = DEFAULT_MEMORY_PAGE_LIMIT,
    ) -> None:
        self._fuel_per_call = fuel
        self._memory_page_limit = memory_page_limit
        self._modules_dir = Path(modules_dir) if modules_dir is not None else _DEFAULT_WASM_DIR
        config = wasmtime.Config()
        config.consume_fuel = True
        # Note: we considered enabling wasmtime epoch interruption as a second
        # preemption channel. Wasmtime's epoch policy traps as soon as the
        # current epoch crosses the deadline, and a runner that does not bump
        # epochs externally would trap on the first invocation. Fuel is
        # sufficient for SIFR's policy: every supported tool is small,
        # CPU-bounded, and does not need wall-clock preemption.
        self._engine = wasmtime.Engine(config)
        self._modules: dict[str, wasmtime.Module] = {}
        self.last_invocation_evidence: Optional[dict[str, Any]] = None

    def _new_store(self) -> "wasmtime.Store":
        store = wasmtime.Store(self._engine)
        store.set_fuel(self._fuel_per_call)
        # Apply memory cap via Store.set_limits. Cap is in bytes; one wasm
        # page is 64 KiB. memory.grow will return -1 once the limit is
        # crossed, and instantiation fails if a module's declared minimum
        # exceeds the cap.
        try:
            store.set_limits(memory_size=self._memory_page_limit * 64 * 1024)
        except Exception:
            # If the wasmtime-py build lacks set_limits, fuel remains the
            # load-bearing isolation lever.
            pass
        return store

    def _load_module(self, filename: str) -> wasmtime.Module:
        if filename not in self._modules:
            path = self._modules_dir / filename
            if not path.is_file():
                raise WasmToolError(f"WASM module not found: {path}")
            source: Any = (
                path.read_text(encoding="utf-8") if path.suffix == ".wat" else path.read_bytes()
            )
            try:
                self._modules[filename] = wasmtime.Module(self._engine, source)
            except wasmtime.WasmtimeError as exc:
                raise WasmToolError(f"failed to compile {path}: {exc}") from exc
        return self._modules[filename]

    def execute(self, action: str, args: dict[str, Any]) -> dict[str, Any]:
        if action not in self.SUPPORTED_TOOLS:
            raise WasmToolError(f"unsupported action: {action}")
        if action == "tool.calculator.add":
            return self._calculator_add(args)
        raise WasmToolError(f"unhandled action: {action}")

    def _calculator_add(self, args: dict[str, Any]) -> dict[str, Any]:
        a = args.get("a")
        b = args.get("b")
        if not isinstance(a, int) or isinstance(a, bool):
            raise WasmToolError("calculator add requires int 'a'")
        if not isinstance(b, int) or isinstance(b, bool):
            raise WasmToolError("calculator add requires int 'b'")

        action_name = "tool.calculator.add"
        module = self._load_module(self.SUPPORTED_TOOLS[action_name])
        store = self._new_store()
        try:
            instance = wasmtime.Instance(store, module, [])
        except wasmtime.WasmtimeError as exc:
            raise WasmToolError(f"failed to instantiate {action_name}: {exc}") from exc
        try:
            add_fn = instance.exports(store)["add"]
        except KeyError as exc:
            raise WasmToolError(f"missing export for {action_name}: add") from exc
        try:
            result = add_fn(store, int(a), int(b))
        except wasmtime.Trap as exc:
            if "fuel" in str(exc).lower():
                raise WasmFuelExhausted(str(exc)) from exc
            raise WasmToolError(str(exc)) from exc
        fuel_remaining = store.get_fuel()
        self.last_invocation_evidence = {
            "tool": action_name,
            "args": dict(args),
            "result": int(result),
            "fuel_consumed": self._fuel_per_call - fuel_remaining,
        }
        return {"result": int(result)}

    def try_instantiate(
        self,
        wat_or_wasm: str | bytes,
        *,
        fuel: Optional[int] = None,
    ) -> tuple[wasmtime.Instance, wasmtime.Store]:
        """Compile + instantiate a custom module under runner constraints.

        Used by tests to exercise hostile modules (FS attempts, infinite loops)
        under the same engine/fuel/import policy as production calls.
        """
        try:
            module = wasmtime.Module(self._engine, wat_or_wasm)
        except wasmtime.WasmtimeError as exc:
            raise WasmToolError(f"compile failed: {exc}") from exc
        store = self._new_store()
        if fuel is not None:
            store.set_fuel(fuel)
        try:
            instance = wasmtime.Instance(store, module, [])
        except wasmtime.WasmtimeError as exc:
            raise WasmToolError(f"instantiate failed: {exc}") from exc
        return instance, store
