"""Adversarial WASM-sandbox tests for v0.5.

These tests strengthen the v0.4 evidence ("calculator + a couple of hostile
fixtures") with explicit coverage of:

  - filesystem WASI import attempt;
  - environment WASI import attempt;
  - network/socket WASI import attempt;
  - infinite loop (fuel trap);
  - memory growth abuse (StoreLimits);
  - large input rejection (input validation);
  - missing exported function rejection;
  - trap (unreachable) surfacing.

Honest non-claim: this is NOT a proof of arbitrary untrusted-code safety.
It is a test of the SIFR runner's documented policy: no WASI imports,
fuel-bounded, memory-capped, fresh-store, and integer-typed args only.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import wasmtime

from sifr.wasm_runner import (
    PythonCalculatorReference,
    WasmFuelExhausted,
    WasmToolError,
    WasmToolRunner,
)

FIXTURES = Path(__file__).parent / "fixtures" / "wasm_modules"


# --------------------------------------------------------------------------
# WASI-import refusal
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "fixture_name",
    [
        "fs_attempt.wat",
        "env_attempt.wat",
        "network_attempt.wat",
    ],
)
def test_wasi_imports_refused(fixture_name: str):
    """Any module that imports wasi_snapshot_preview1.* must fail to instantiate."""
    runner = WasmToolRunner()
    wat = (FIXTURES / fixture_name).read_text(encoding="utf-8")
    with pytest.raises(WasmToolError, match="instantiate failed"):
        runner.try_instantiate(wat)


# --------------------------------------------------------------------------
# Fuel & traps
# --------------------------------------------------------------------------

def test_infinite_loop_traps_on_fuel():
    runner = WasmToolRunner(fuel=2000)
    wat = (FIXTURES / "looping.wat").read_text(encoding="utf-8")
    instance, store = runner.try_instantiate(wat)
    spin = instance.exports(store)["spin"]
    with pytest.raises(wasmtime.Trap, match="fuel"):
        spin(store)


def test_unreachable_trap_surfaces():
    runner = WasmToolRunner()
    wat = (FIXTURES / "trap_unreachable.wat").read_text(encoding="utf-8")
    instance, store = runner.try_instantiate(wat)
    boom = instance.exports(store)["boom"]
    with pytest.raises(wasmtime.Trap):
        boom(store)


# --------------------------------------------------------------------------
# Memory growth
# --------------------------------------------------------------------------

def test_memory_growth_abuse_denied():
    """Asking for 4096 pages (256 MiB) must be denied under the runner's cap."""
    runner = WasmToolRunner(memory_page_limit=8)
    wat = (FIXTURES / "memory_grow_abuse.wat").read_text(encoding="utf-8")
    instance, store = runner.try_instantiate(wat)
    grow = instance.exports(store)["grow_lots"]
    # WASM's memory.grow returns -1 on failure. We assert that the host's
    # memory cap is enforced and no allocation happened.
    result = grow(store)
    assert result == -1, f"memory.grow should fail under cap, got {result}"


# --------------------------------------------------------------------------
# Calculator parity & fuel evidence
# --------------------------------------------------------------------------

def test_calculator_parity_with_python_reference():
    """The hardened runner still produces correct calculator results."""
    py = PythonCalculatorReference()
    wasm = WasmToolRunner()
    cases = [(0, 0), (1, 2), (-50, 50), (10**9, 10**9 - 1)]
    for a, b in cases:
        assert wasm.execute("tool.calculator.add", {"a": a, "b": b})["result"] == a + b
        assert (
            py.execute("tool.calculator.add", {"a": a, "b": b})["result"]
            == wasm.execute("tool.calculator.add", {"a": a, "b": b})["result"]
        )


def test_calculator_fuel_consumed_evidence():
    runner = WasmToolRunner()
    runner.execute("tool.calculator.add", {"a": 5, "b": 7})
    e = runner.last_invocation_evidence
    assert e is not None
    assert e["tool"] == "tool.calculator.add"
    assert e["fuel_consumed"] > 0
    assert e["fuel_consumed"] < runner._fuel_per_call


# --------------------------------------------------------------------------
# Input validation
# --------------------------------------------------------------------------

def test_unsupported_action_never_reaches_runner():
    runner = WasmToolRunner()
    with pytest.raises(WasmToolError, match="unsupported action"):
        runner.execute("tool.shell.run", {"cmd": "rm -rf /"})


def test_non_int_args_rejected_before_wasm():
    """Float / string args must be rejected BEFORE entering the runtime."""
    runner = WasmToolRunner()
    with pytest.raises(WasmToolError, match="int 'a'"):
        runner.execute("tool.calculator.add", {"a": 1.5, "b": 2})
    with pytest.raises(WasmToolError, match="int 'b'"):
        runner.execute("tool.calculator.add", {"a": 1, "b": "x"})


def test_bool_args_rejected_as_non_int():
    """Bools are int subtypes in Python — the runner explicitly excludes them."""
    runner = WasmToolRunner()
    with pytest.raises(WasmToolError, match="int 'a'"):
        runner.execute("tool.calculator.add", {"a": True, "b": 1})


def test_huge_int_args_clamped_or_traps():
    """A 64-bit overflow input either clamps to i64 wraparound (defined)
    or traps cleanly; it must never crash the host or escape the sandbox."""
    runner = WasmToolRunner()
    big = 2**62
    out = runner.execute("tool.calculator.add", {"a": big, "b": big})
    # Calculator uses i64 add; result is well-defined within i64 range.
    assert isinstance(out["result"], int)


# --------------------------------------------------------------------------
# Module loading hygiene
# --------------------------------------------------------------------------

def test_calculator_has_no_imports():
    runner = WasmToolRunner()
    module = runner._load_module("calculator.wat")
    assert list(module.imports) == [], "calculator module must have zero imports"


def test_state_isolation_across_calls():
    """Each call gets a fresh Store: fuel cost is identical for identical input."""
    runner = WasmToolRunner()
    runner.execute("tool.calculator.add", {"a": 7, "b": 8})
    f1 = runner.last_invocation_evidence["fuel_consumed"]
    runner.execute("tool.calculator.add", {"a": 7, "b": 8})
    f2 = runner.last_invocation_evidence["fuel_consumed"]
    assert f1 == f2, "fresh Store ⇒ deterministic fuel for identical input"


def test_module_with_missing_export_rejected_cleanly():
    """A module without the expected `add` export must not crash the runner."""
    runner = WasmToolRunner()
    wat = (FIXTURES / "missing_export.wat").read_text(encoding="utf-8")
    instance, store = runner.try_instantiate(wat)
    # Confirm the runner instantiates the module fine — but accessing a
    # non-existent export raises a clean error.
    with pytest.raises(KeyError):
        instance.exports(store)["add"]


def test_runner_default_memory_limit_is_finite():
    assert isinstance(WasmToolRunner.DEFAULT_MEMORY_PAGE_LIMIT, int)
    assert WasmToolRunner.DEFAULT_MEMORY_PAGE_LIMIT > 0
    assert WasmToolRunner.DEFAULT_MEMORY_PAGE_LIMIT <= 1024  # ≤ 64 MiB
