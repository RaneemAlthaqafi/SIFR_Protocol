from __future__ import annotations

from pathlib import Path

import pytest

from sifr.wasm_runner import (
    PythonCalculatorReference,
    WasmFuelExhausted,
    WasmToolError,
    WasmToolRunner,
)

FIXTURES = Path(__file__).parent / "fixtures" / "wasm_modules"


def test_calculator_add_returns_correct_result():
    runner = WasmToolRunner()
    out = runner.execute("tool.calculator.add", {"a": 2, "b": 3})
    assert out == {"result": 5}


def test_python_and_wasm_parity():
    """Trap-acceptance precondition: both runners must produce the same answer
    for many inputs. Combined with the fuel-consumed evidence below, this
    proves WASM is doing the work (not silently routed to Python).
    """
    py = PythonCalculatorReference()
    wasm = WasmToolRunner()
    cases = [
        (0, 0), (1, 1), (-5, 7), (100, -50), (123456789, 987654321),
        (-2**31, 2**31 - 1), (0, 2**62), (-1, -1),
    ]
    for a, b in cases:
        py_out = py.execute("tool.calculator.add", {"a": a, "b": b})["result"]
        wasm_out = wasm.execute("tool.calculator.add", {"a": a, "b": b})["result"]
        assert py_out == wasm_out, f"mismatch for ({a}, {b}): py={py_out} wasm={wasm_out}"


def test_evidence_counter_advances_per_call():
    """Trap-acceptance: every successful WASM call must consume real fuel.
    A Python fall-through would never advance this counter.
    """
    runner = WasmToolRunner()
    assert runner.last_invocation_evidence is None
    runner.execute("tool.calculator.add", {"a": 2, "b": 3})
    e1 = runner.last_invocation_evidence
    assert e1 is not None
    assert e1["fuel_consumed"] > 0
    assert e1["fuel_consumed"] < runner._fuel_per_call

    runner.execute("tool.calculator.add", {"a": 10, "b": 20})
    e2 = runner.last_invocation_evidence
    assert e2 is not None
    assert e2["result"] == 30


def test_unsupported_action_rejected():
    runner = WasmToolRunner()
    with pytest.raises(WasmToolError, match="unsupported action"):
        runner.execute("tool.calculator.subtract", {"a": 5, "b": 3})


def test_non_integer_args_rejected():
    runner = WasmToolRunner()
    with pytest.raises(WasmToolError, match="int 'a'"):
        runner.execute("tool.calculator.add", {"a": 1.5, "b": 2})
    with pytest.raises(WasmToolError, match="int 'b'"):
        runner.execute("tool.calculator.add", {"a": 1, "b": "x"})


def test_fs_attempt_module_fails_to_instantiate():
    """Trap-acceptance: a module importing wasi_snapshot_preview1 must fail
    to instantiate, because the runner links no WASI imports.
    """
    runner = WasmToolRunner()
    wat = (FIXTURES / "fs_attempt.wat").read_text(encoding="utf-8")
    with pytest.raises(WasmToolError, match="instantiate failed"):
        runner.try_instantiate(wat)


def test_looping_module_exhausts_fuel():
    """Trap-acceptance: an infinite loop must trap on fuel, not run forever."""
    runner = WasmToolRunner(fuel=1000)
    wat = (FIXTURES / "looping.wat").read_text(encoding="utf-8")
    instance, store = runner.try_instantiate(wat)
    spin = instance.exports(store)["spin"]
    import wasmtime
    with pytest.raises(wasmtime.Trap, match="fuel"):
        spin(store)


def test_calculator_does_not_have_wasi_imports():
    """The default calculator module must not import anything; modules with
    only no-import operations cannot exfiltrate."""
    runner = WasmToolRunner()
    module = runner._load_module("calculator.wat")
    imports = module.imports
    assert list(imports) == [], "calculator must have zero imports"


def test_module_not_found():
    runner = WasmToolRunner(modules_dir="/nonexistent/path")
    with pytest.raises(WasmToolError, match="not found"):
        runner.execute("tool.calculator.add", {"a": 1, "b": 1})


def test_default_fuel_is_finite():
    assert isinstance(WasmToolRunner.DEFAULT_FUEL, int)
    assert WasmToolRunner.DEFAULT_FUEL > 0
    assert WasmToolRunner.DEFAULT_FUEL <= 100_000_000


def test_python_reference_unsupported_action():
    py = PythonCalculatorReference()
    with pytest.raises(ValueError, match="unsupported"):
        py.execute("tool.calculator.divide", {"a": 1, "b": 1})


def test_python_reference_non_numeric_args():
    py = PythonCalculatorReference()
    with pytest.raises(ValueError, match="numeric"):
        py.execute("tool.calculator.add", {"a": "x", "b": 1})


def test_wasm_runner_isolates_engine_state_across_calls():
    """Each call uses a fresh Store; state cannot leak between calls."""
    runner = WasmToolRunner()
    runner.execute("tool.calculator.add", {"a": 1, "b": 2})
    fuel_after_call_1 = runner.last_invocation_evidence["fuel_consumed"]
    runner.execute("tool.calculator.add", {"a": 1, "b": 2})
    fuel_after_call_2 = runner.last_invocation_evidence["fuel_consumed"]
    # Same operation, same fuel cost — Stores are independent, not accumulating.
    assert fuel_after_call_1 == fuel_after_call_2
