# WASM Tool Isolation

SIFR v0.2 executes tool actions inside a [wasmtime](https://github.com/bytecodealliance/wasmtime) sandbox via `sifr/wasm_runner.py`'s `WasmToolRunner`.

## Sandbox boundary

The runner instantiates modules with **no WASI imports linked**:

- No filesystem access — no preopened directories, no `path_open`, no `fd_*`.
- No network access — no socket APIs available.
- No environment variables — no `environ_get` provided.
- No clock/time access — no `clock_time_get` provided.
- No host imports of any kind — modules with non-empty `imports` cannot instantiate.

A module that imports anything from `wasi_snapshot_preview1` (or any other host namespace) fails at `wasmtime.Instance(store, module, [])` with the error `expected N imports, found 0`. This is verified by `tests/test_wasm_runner.py::test_fs_attempt_module_fails_to_instantiate`.

## Fuel limit

Every call to `WasmToolRunner.execute()` runs in a fresh `wasmtime.Store` with a fixed fuel budget (default `1_000_000`). When fuel is exhausted, wasmtime raises a `Trap` containing the substring `"fuel"`; the runner converts it to `WasmFuelExhausted`.

This bounds compute per call. An infinite loop in a module traps after ~1M instructions instead of consuming the host indefinitely. Verified by `test_looping_module_exhausts_fuel`.

Fuel cost is per WebAssembly instruction; the calculator's `add` consumes 4 fuel.

## State isolation

Each call gets a fresh `wasmtime.Store`. State cannot leak between calls — there is no shared memory, no shared instance, and no shared linker.

## Trap-acceptance

The runner must not silently fall through to a Python implementation when wasmtime fails or is unavailable. Tests enforce this:

| Test | What it proves |
|---|---|
| `test_python_and_wasm_parity` | WASM and Python produce bit-identical results across 8 input pairs including negatives, large values, and overflow boundaries. |
| `test_evidence_counter_advances_per_call` | Every successful `execute()` advances `last_invocation_evidence["fuel_consumed"]`. A Python fall-through would never advance this counter. |
| `test_calculator_does_not_have_wasi_imports` | The committed calculator module has zero imports. |
| `test_fs_attempt_module_fails_to_instantiate` | A hostile module importing `wasi_snapshot_preview1.path_open` cannot be instantiated. |
| `test_looping_module_exhausts_fuel` | An infinite-loop module traps on fuel rather than running indefinitely. |
| `test_unsupported_action_rejected` | Unknown action names are rejected before any module work. |

## Module source: WAT, not WASM binary

Modules are committed as `.wat` (WebAssembly text), not `.wasm` (binary). Reasons:

1. **Reviewer transparency.** A 13-line WAT file can be inspected by hand. A binary cannot.
2. **No build step.** wasmtime compiles the WAT at load time; reviewers do not need a Rust toolchain.
3. **Reproducibility.** The same WAT compiled by any wasmtime version produces an equivalent module.

The cost is a one-time compile per process, amortized at startup.

## Limitations

- The runner ships only the calculator module. Adding new tools requires:
  1. Writing a new `.wat` file with the desired exports.
  2. Adding a method to `WasmToolRunner` that loads it and calls the export.
  3. Registering the action name in `WasmToolRunner.SUPPORTED_TOOLS`.
  4. Adding parity tests against a Python reference if behavioral correctness matters.
- The fuel limit is fixed at construction time. Per-call fuel overrides would be a small extension.
- The runner does not impose a real wall-clock timeout; fuel is a proxy for compute, not for time. A module performing only fast instructions could run within fuel for many milliseconds. For wall-clock isolation use wasmtime's epoch-interruption API (not enabled in v0.2).

## What we explicitly do NOT claim

- Arbitrary untrusted code safety. The sandbox is verified for the calculator module and the two adversarial fixtures. Other modules require their own threat-model review.
- Side-channel resistance (timing, cache, Spectre-class attacks). wasmtime's mitigations are partial and platform-dependent.
- Memory protection beyond what wasmtime provides. The host is in the same process; a wasmtime CVE could be exploited.
- A multi-tenant sandbox. WasmToolRunner is intended for one trust domain at a time.
