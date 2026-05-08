"""Phase 3 demo: calculator runs inside a real WASM sandbox.

Compiles the calculator.wat module via wasmtime, executes add(2, 3) inside
the sandbox, and prints the fuel consumed as evidence the work happened
inside WASM (not in Python).

Run:
    python examples/demo_wasm_calculator.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sifr.wasm_runner import PythonCalculatorReference, WasmToolRunner


def main() -> int:
    wasm = WasmToolRunner()
    py = PythonCalculatorReference()

    args = {"a": 2, "b": 3}

    py_out = py.execute("tool.calculator.add", args)
    print(f"Python reference: add(2, 3) = {py_out['result']}")

    wasm_out = wasm.execute("tool.calculator.add", args)
    print(f"WASM sandbox:    add(2, 3) = {wasm_out['result']}")

    ev = wasm.last_invocation_evidence
    assert ev is not None
    print(f"  fuel_consumed: {ev['fuel_consumed']} (proves WASM execution)")

    assert py_out == wasm_out, "WASM and Python must agree"
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
